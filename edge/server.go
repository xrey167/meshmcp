package edge

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/xrey167/meshmcp/policy"
	"github.com/xrey167/meshmcp/protocol/authorization"
)

// Server is a constructed edge: validated config, capability signer, fail-closed
// audit ledger, and the abuse limiters. Stores for clients, tokens, authz, and
// sessions are attached by later construction phases; a nil store makes the
// corresponding endpoint report "not configured" rather than panic, which keeps
// the scaffold independently testable.
type Server struct {
	cfg    Config
	signer *policy.Signer
	verify *policy.CapabilityVerifier
	audit  *auditLedger

	clients  *ClientStore
	authz    *AuthzStore
	codes    *codeStore
	tokens   *tokenStore
	engine   *policy.Engine
	sessions *sessionTable
	dial     DialBackend
	iats     []resolvedIAT

	preauthLimit  *fixedWindowLimiter
	registerLimit *fixedWindowLimiter
	clientLimit   *tokenBucket

	now func() time.Time
}

// Options are non-config construction inputs, primarily to inject a clock and
// pre-built collaborators in tests.
type Options struct {
	// Now overrides the wall clock (tests). Defaults to time.Now.
	Now func() time.Time
	// Signer overrides the capability authority (tests). When nil, New loads or
	// generates it from cfg.SigningKey.
	Signer *policy.Signer
	// AuditWriter overrides where the audit ledger writes (tests). When nil,
	// New opens cfg.AuditLog (append, fail-closed, chain-seeded).
	AuditWriter interface {
		Write([]byte) (int, error)
	}
	// DialBackend overrides how the one configured backend is reached. Production
	// injects a WireGuard mesh dial (client.Dial); when nil, a plain TCP dial to
	// cfg.Backend.Addr is used (same-host backends and tests).
	DialBackend DialBackend
}

// New validates cfg and constructs a Server. It creates the state directory,
// loads or (opt-in) generates the signing key, opens the fail-closed audit
// ledger seeded from any existing chain, and pins a capability verifier to the
// signer's own public key.
func New(cfg Config, opts Options) (*Server, error) {
	cfg, err := cfg.Validate()
	if err != nil {
		return nil, err
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}

	if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
		return nil, fmt.Errorf("edge: create state_dir: %w", err)
	}

	signer := opts.Signer
	if signer == nil {
		signer, err = loadOrGenerateSigner(cfg.SigningKey, cfg.SigningKeyAutogen)
		if err != nil {
			return nil, err
		}
	}
	verify, err := policy.NewCapabilityVerifier([]string{signer.PubKeyHex()}, now)
	if err != nil {
		return nil, fmt.Errorf("edge: build capability verifier: %w", err)
	}

	audit, err := openAuditLedger(cfg.AuditLog, opts.AuditWriter, now)
	if err != nil {
		return nil, err
	}

	clients, err := NewClientStore(filepath.Join(cfg.StateDir, "clients"), now)
	if err != nil {
		return nil, err
	}
	iats, err := resolveIATs(cfg.Registration)
	if err != nil {
		return nil, err
	}
	authz, err := NewAuthzStore(filepath.Join(cfg.StateDir, "authz"), now)
	if err != nil {
		return nil, err
	}
	codes, err := newCodeStore(filepath.Join(cfg.StateDir, "codes"))
	if err != nil {
		return nil, err
	}
	tokens, err := newTokenStore(filepath.Join(cfg.StateDir, "tokens"))
	if err != nil {
		return nil, err
	}

	pol := cfg.Backend.Policy
	engine := policy.NewEngine(&pol, now, nil)
	dial := opts.DialBackend
	if dial == nil {
		dial = defaultDial(cfg.Backend.Addr)
	}

	s := &Server{
		cfg:           cfg,
		signer:        signer,
		verify:        verify,
		audit:         audit,
		clients:       clients,
		authz:         authz,
		codes:         codes,
		tokens:        tokens,
		engine:        engine,
		sessions:      newSessionTable(cfg.Limits.MaxSessionsPerClient, cfg.Limits.MaxSSEBufferMsgs, now),
		dial:          dial,
		iats:          iats,
		preauthLimit:  newFixedWindowLimiter(cfg.Limits.PreauthPerIPPerMin, time.Minute, now),
		registerLimit: newFixedWindowLimiter(cfg.Limits.RegisterPerIPPerMin, time.Minute, now),
		clientLimit:   newTokenBucket(cfg.Limits.PerClientRPS, cfg.Limits.PerClientBurst, now),
		now:           now,
	}
	return s, nil
}

// loadOrGenerateSigner loads the Ed25519 capability authority from path, or —
// only when autogen is set — generates and saves one. A missing key without
// autogen is fatal (the S13 "missing signing key is fatal" precedent).
func loadOrGenerateSigner(path string, autogen bool) (*policy.Signer, error) {
	signer, err := policy.LoadSigner(path)
	if err == nil {
		return signer, nil
	}
	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("edge: load signing_key %s: %w", path, err)
	}
	if !autogen {
		return nil, fmt.Errorf("edge: signing_key %s does not exist (set signing_key_autogen: true to create it, or generate it out of band)", path)
	}
	signer, err = policy.GenerateSigner()
	if err != nil {
		return nil, fmt.Errorf("edge: generate signing_key: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("edge: create signing_key dir: %w", err)
	}
	if err := signer.SaveSigner(path); err != nil {
		return nil, fmt.Errorf("edge: save signing_key: %w", err)
	}
	return signer, nil
}

// Handler assembles the edge mux. Every route is explicit; there is no catch-all
// proxy. The MCP path is the only tool-carrying surface and is deny-by-default
// (in this scaffold phase it always challenges, since no tokens exist yet).
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(wellKnownPRM, s.handleProtectedResourceMetadata)
	mux.HandleFunc(wellKnownPRM+pathMCP, s.handleProtectedResourceMetadata) // path-insertion form
	mux.HandleFunc(wellKnownAS, s.handleAuthorizationServerMetadata)
	mux.HandleFunc(wellKnownOIDC, s.handleAuthorizationServerMetadata)
	mux.HandleFunc(pathHealthz, s.handleHealthz)
	mux.HandleFunc(pathMCP, s.handleMCP)
	mux.HandleFunc(pathRegister, s.handleRegister)
	mux.HandleFunc(pathRegister+"/", s.handleManage)
	mux.HandleFunc(pathAuthorizeStat, s.handleAuthorizeStatus)
	mux.HandleFunc(pathAuthorize, s.handleAuthorize)
	mux.HandleFunc(pathToken, s.handleToken)
	return mux
}

// handleHealthz is a liveness probe that discloses no state.
func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write([]byte("ok\n"))
}

// writeBearerChallenge writes a 401 with a spec-shaped WWW-Authenticate header
// pointing at the protected-resource-metadata document, and an OAuth error body.
// errCode, when non-empty, is echoed as the challenge error parameter.
func (s *Server) writeBearerChallenge(w http.ResponseWriter, errCode string) {
	rm := s.cfg.PublicURL + wellKnownPRM + pathMCP
	challenge := fmt.Sprintf(`%s resource_metadata=%q`, authorization.SchemeBearer, rm)
	if errCode != "" {
		challenge += fmt.Sprintf(`, error=%q`, errCode)
	}
	w.Header().Set("WWW-Authenticate", challenge)
	body := authorization.TokenErrorResponse{Error: errCodeOr(errCode, "invalid_token")}
	writeJSON(w, http.StatusUnauthorized, body)
}

func errCodeOr(code, fallback string) string {
	if code == "" {
		return fallback
	}
	return code
}

// buildTLSConfig produces the *tls.Config for the listener. In files mode it
// loads the operator-provided keypair (fatal on error); in ACME mode it hands
// off to certmagic (see acme.go). Exactly one mode is guaranteed by Validate.
func (s *Server) buildTLSConfig() (*tls.Config, *acmeRuntime, error) {
	if s.cfg.TLS.files() {
		cert, err := tls.LoadX509KeyPair(s.cfg.TLS.CertFile, s.cfg.TLS.KeyFile)
		if err != nil {
			return nil, nil, fmt.Errorf("edge: load tls cert/key: %w", err)
		}
		return &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{cert},
		}, nil, nil
	}
	return s.buildACMETLSConfig()
}

// httpServer wraps the mux with hardened timeouts. There is deliberately no
// global WriteTimeout or ReadTimeout: the MCP endpoint streams SSE, which those
// would sever. ReadHeaderTimeout and IdleTimeout bound slow/half-open clients;
// per-request deadlines are applied inside non-streaming handlers.
func (s *Server) httpServer(tlsConf *tls.Config) *http.Server {
	return &http.Server{
		Addr:              s.cfg.Listen,
		Handler:           s.Handler(),
		TLSConfig:         tlsConf,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
}

// Run builds the TLS config (fatal on cert error), starts any ACME challenge
// listener, and serves until ctx is cancelled, then shuts down gracefully. It
// blocks. TLS certificates are already loaded/obtained before Serve begins, so
// a certificate problem is a startup error, never a first-handshake surprise.
func (s *Server) Run(ctx context.Context) error {
	tlsConf, acme, err := s.buildTLSConfig()
	if err != nil {
		return err
	}
	acme.start()
	defer acme.stop(context.Background())

	srv := s.httpServer(tlsConf)
	ln, err := net.Listen("tcp", s.cfg.Listen)
	if err != nil {
		return fmt.Errorf("edge: listen on %s: %w", s.cfg.Listen, err)
	}

	errCh := make(chan error, 1)
	go func() {
		// The keypair/GetCertificate already lives in tlsConf; empty strings
		// tell ServeTLS to use it.
		errCh <- srv.ServeTLS(ln, "", "")
	}()

	select {
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(shutCtx)
	case err := <-errCh:
		if err == http.ErrServerClosed {
			return nil
		}
		return err
	}
}
