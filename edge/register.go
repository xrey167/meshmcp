package edge

import (
	"crypto/subtle"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/xrey167/meshmcp/protocol/authorization"
)

// maxRegisterBody bounds a registration request body — DCR documents are small.
const maxRegisterBody = 16 << 10

// scopeClientRegister is the scope an initial access token must carry to
// register a client in token mode.
const scopeClientRegister = "client:register"

// resolvedIAT is an initial access token with its secret resolved from the
// environment (or literal), plus its per-token client cap.
type resolvedIAT struct {
	token      string
	maxClients int
}

// resolveIATs reads the configured initial access tokens, pulling secrets from
// the environment where TokenEnv is set. A token-mode config with an
// unresolvable env var is a startup error.
func resolveIATs(cfg RegistrationConfig) ([]resolvedIAT, error) {
	var out []resolvedIAT
	for _, iat := range cfg.InitialAccessTokens {
		tok := iat.Token
		if iat.TokenEnv != "" {
			tok = os.Getenv(iat.TokenEnv)
			if tok == "" {
				return nil, &configError{"edge: registration initial access token env " + iat.TokenEnv + " is empty"}
			}
		}
		if tok == "" {
			continue
		}
		out = append(out, resolvedIAT{token: tok, maxClients: iat.MaxClients})
	}
	return out, nil
}

type configError struct{ msg string }

func (e *configError) Error() string { return e.msg }

// handleRegister implements RFC 7591 Dynamic Client Registration for both gating
// modes. Open-approval registrations land pending (and can do nothing until an
// operator approves); token-mode registrations require a valid initial access
// token and land approved.
func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	if !s.registerLimit.allow(s.rateLimitKey(r)) {
		writeOAuthError(w, http.StatusTooManyRequests, "temporarily_unavailable", "registration rate limit exceeded")
		return
	}
	ip := clientIP(r) // honest transport peer, for the registration audit record

	var req authorization.ClientRegistrationRequest
	dec := json.NewDecoder(io.LimitReader(r.Body, maxRegisterBody))
	if err := dec.Decode(&req); err != nil {
		writeOAuthError(w, http.StatusBadRequest, authorization.ErrorInvalidRequest, "malformed registration body")
		return
	}

	redirects, err := validateRedirectURIs(req.RedirectURIs)
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_redirect_uri", err.Error())
		return
	}

	// Serialize the quota check and the create so the cap holds under concurrent
	// registrations (federation/dcr.go serializes its quota the same way). The
	// lock key is distinct from any client_id, so it never nests with Create's
	// own per-client_id lock.
	mode := s.cfg.Registration.Mode
	unlock := s.clients.keyed.lock("register:quota")
	if mode == RegistrationToken {
		if !s.authorizeIAT(r) {
			unlock()
			writeOAuthError(w, http.StatusUnauthorized, authorization.ErrorInvalidClient, "a valid initial access token is required")
			return
		}
	} else {
		// open-approval: bound the pending backlog to protect disk / audit.
		if n, err := s.clients.CountPending(); err == nil && n >= s.cfg.Registration.MaxPending {
			unlock()
			writeOAuthError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "too many pending registrations; try again after an operator reviews the queue")
			return
		}
	}

	rec, regToken, err := s.clients.Create(req.ClientName, redirects, mode)
	unlock()
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "could not persist registration")
		return
	}
	if aerr := s.auditClientEvent(rec, "register", ip); aerr != nil {
		// Fail closed: a registration we cannot record is rolled back.
		_, _ = s.clients.Revoke(rec.ClientID, "audit-failure")
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "could not record registration")
		return
	}

	resp := authorization.ClientRegistrationResponse{
		ClientRegistrationRequest: authorization.ClientRegistrationRequest{
			RedirectURIs:            rec.RedirectURIs,
			ClientName:              rec.ClientName,
			TokenEndpointAuthMethod: rec.TokenEndpointAuthMethod,
			GrantTypes:              []string{authorization.GrantAuthorizationCode, authorization.GrantRefreshToken},
			ResponseTypes:           []string{authorization.ResponseTypeCode},
		},
		ClientID:                rec.ClientID,
		ClientIDIssuedAt:        rec.CreatedAt.Unix(),
		RegistrationAccessToken: regToken,
		RegistrationClientURI:   s.cfg.PublicURL + pathRegister + "/" + rec.ClientID,
	}
	writeJSON(w, http.StatusCreated, resp)
}

// authorizeIAT checks the request's bearer against the configured initial
// access tokens (constant-time) and enforces the per-token client cap.
func (s *Server) authorizeIAT(r *http.Request) bool {
	presented := bearerToken(r)
	if presented == "" {
		return false
	}
	for _, iat := range s.iats {
		if subtle.ConstantTimeCompare([]byte(iat.token), []byte(presented)) == 1 {
			if iat.maxClients > 0 {
				if n, err := s.clients.List(); err == nil && len(n) >= iat.maxClients {
					return false
				}
			}
			return true
		}
	}
	return false
}

// handleManage implements the RFC 7592 client-configuration endpoint
// (GET/PUT/DELETE /oauth2/register/{client_id}), authenticated by the
// registration access token. DELETE is how a client de-registers itself.
func (s *Server) handleManage(w http.ResponseWriter, r *http.Request) {
	clientID := strings.TrimPrefix(r.URL.Path, pathRegister+"/")
	if clientID == "" || strings.Contains(clientID, "/") {
		http.NotFound(w, r)
		return
	}
	// The store methods lock per-client internally; holding a second lock here
	// would deadlock the non-reentrant mutex when we call Revoke below.
	rec, err := s.clients.Get(clientID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if !s.clients.VerifyRegToken(rec, bearerToken(r)) {
		writeOAuthError(w, http.StatusUnauthorized, authorization.ErrorInvalidClient, "invalid registration access token")
		return
	}

	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, authorization.ClientRegistrationResponse{
			ClientRegistrationRequest: authorization.ClientRegistrationRequest{
				RedirectURIs:            rec.RedirectURIs,
				ClientName:              rec.ClientName,
				TokenEndpointAuthMethod: rec.TokenEndpointAuthMethod,
			},
			ClientID: rec.ClientID,
		})
	case http.MethodDelete:
		if _, err := s.clients.Revoke(clientID, "self-deregister"); err != nil {
			writeOAuthError(w, http.StatusInternalServerError, "server_error", "could not deregister")
			return
		}
		_ = s.auditClientEvent(rec, "deregister", clientIP(r))
		w.WriteHeader(http.StatusNoContent)
	default:
		methodNotAllowed(w, http.MethodGet, http.MethodDelete)
	}
}

// validateRedirectURIs enforces exact-match-ready redirect URIs: at least one,
// absolute, https (or a localhost http callback for native dev), no fragment.
func validateRedirectURIs(uris []string) ([]string, error) {
	if len(uris) == 0 {
		return nil, errString("at least one redirect_uri is required")
	}
	out := make([]string, 0, len(uris))
	for _, raw := range uris {
		u, err := url.Parse(raw)
		if err != nil || !u.IsAbs() {
			return nil, errString("redirect_uri must be an absolute URI: " + raw)
		}
		if u.Fragment != "" {
			return nil, errString("redirect_uri must not contain a fragment: " + raw)
		}
		if u.Scheme != "https" && !isLocalhost(u.Hostname()) {
			return nil, errString("redirect_uri must be https (or a localhost http callback): " + raw)
		}
		out = append(out, raw)
	}
	return out, nil
}

func isLocalhost(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

// bearerToken extracts a Bearer credential from the Authorization header.
func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	const p = "Bearer "
	if len(h) > len(p) && strings.EqualFold(h[:len(p)], p) {
		return strings.TrimSpace(h[len(p):])
	}
	return ""
}

type strErr string

func (e strErr) Error() string { return string(e) }

func errString(s string) error { return strErr(s) }

// writeOAuthError writes an RFC 6749 §5.2-shaped error with the given status.
func writeOAuthError(w http.ResponseWriter, status int, code, desc string) {
	writeJSON(w, status, authorization.TokenErrorResponse{Error: code, ErrorDescription: desc})
}
