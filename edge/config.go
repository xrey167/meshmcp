// Package edge is meshmcp's public OAuth ingress — the one deliberately
// separate, off-by-default TLS listener that lets a hosted MCP client (e.g. a
// claude.ai custom connector) reach exactly one tool-scoped mesh backend.
//
// It exists because meshmcp's core is mesh-only: every other listener rides the
// WireGuard interface and derives identity from the transport key. A hosted
// client holds no mesh identity, so the edge terminates OAuth 2.1 (RFC 9728 /
// 8414 discovery, RFC 7591 DCR, authorization-code + PKCE with operator-in-the-
// loop consent) at the edge, exchanges the resulting bearer into an internal
// Ed25519 capability (policy.CapabilityClaims) bound to a synthetic identity
// "oauth:<client_id>", and forwards MCP traffic through the UNCHANGED policy
// engine and a fail-closed audit log. See docs/spec/OAUTH-STANDARDS.md (the
// recorded exposure-model decision, "extended Option A", deviations D-A..D-D)
// and docs/THREAT-MODEL.md adversaries 12–13.
//
// This file defines the configuration surface and its validation. The
// configuration is parsed by the meshmcp binary (strict KnownFields decode) and
// handed here already-decoded; Validate is the single authority on what a
// well-formed, safe-by-default edge configuration is.
package edge

import (
	"fmt"
	"net/url"
	"path"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/xrey167/meshmcp/policy"
)

// Duration is a time.Duration that decodes from a YAML string such as "15m" or
// "720h" (gopkg.in/yaml.v3 otherwise expects raw nanoseconds). Programmatic
// construction in tests uses Duration(15 * time.Minute).
type Duration time.Duration

// Std returns the wrapped time.Duration.
func (d Duration) Std() time.Duration { return time.Duration(d) }

// UnmarshalYAML parses a duration string (time.ParseDuration syntax).
func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err != nil {
		return err
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	*d = Duration(parsed)
	return nil
}

// MarshalYAML renders the duration back to its string form.
func (d Duration) MarshalYAML() (any, error) { return time.Duration(d).String(), nil }

// Registration gating modes for the DCR endpoint.
const (
	// RegistrationOpenApproval is the default: RFC 7591 registration is open,
	// but a newly registered client lands PENDING and can complete no
	// authorization and obtain no token until an operator approves it. This is
	// the mode hosted clients such as claude.ai require (they register without
	// an initial access token). Deviation D-B in the exposure-model decision.
	RegistrationOpenApproval = "open-approval"
	// RegistrationToken is the spec-literal C1 gate: registration requires a
	// pre-issued initial access token with the client:register scope, and a
	// successful registration is approved directly (the operator vouched by
	// minting the token). Unusable by claude.ai, offered for closed deployments.
	RegistrationToken = "token"
)

// ACME challenge types the edge can use to obtain a certificate.
const (
	// ChallengeTLSALPN01 is the default: no extra listener, the challenge is
	// answered on the TLS listener itself.
	ChallengeTLSALPN01 = "tls-alpn-01"
	// ChallengeHTTP01 binds an additional plaintext HTTP listener (default :80)
	// serving only the ACME challenge.
	ChallengeHTTP01 = "http-01"
)

// Default lifetimes and bounds. Access-token TTL is capped at maxAccessTokenTTL
// to honor the ≤1h federation-grant ceiling that the minted capability shares.
const (
	maxAccessTokenTTL = time.Hour

	defaultAccessTokenTTL  = 15 * time.Minute
	defaultRefreshTokenTTL = 30 * 24 * time.Hour
	defaultAuthzPendingTTL = 15 * time.Minute
	defaultPendingTTL      = 7 * 24 * time.Hour
	defaultMaxPending      = 50

	defaultRegisterPerIPPerMin  = 5
	defaultPreauthPerIPPerMin   = 60
	defaultPerClientRPS         = 5
	defaultPerClientBurst       = 20
	defaultMaxSessionsPerClient = 8
	defaultMaxSSEBufferMsgs     = 256
	defaultMaxMCPBodyBytes      = 1 << 20 // 1 MiB
	defaultACMEHTTPPort         = 80
)

// Config is the fully-decoded edge configuration. Field tags match edge.yaml;
// the meshmcp binary decodes with yaml KnownFields(true) so an unknown key is a
// startup error, mirroring the gateway's loadConfig discipline.
type Config struct {
	// Listen is the TLS bind address, e.g. "203.0.113.7:8443". REQUIRED — there
	// is no default; an empty value is a startup error (never a default-on bind).
	Listen string `yaml:"listen"`
	// PublicURL is the externally-reachable https base URL, e.g.
	// "https://mcp.example.com". It is the OAuth issuer and the protected
	// resource base. REQUIRED, https only.
	PublicURL string `yaml:"public_url"`
	// StateDir holds all persistent edge state (clients, tokens, authz, acme).
	// Created 0700. REQUIRED.
	StateDir string `yaml:"state_dir"`
	// AuditLog is the edge's own hash-chained decision ledger. REQUIRED. It is
	// ALWAYS fail-closed (not configurable): a decision that cannot be recorded
	// is not allowed to proceed.
	AuditLog string `yaml:"audit_log"`
	// SigningKey is the Ed25519 capability-authority key file. REQUIRED.
	SigningKey string `yaml:"signing_key"`
	// SigningKeyAutogen, when true, generates and saves SigningKey if absent.
	// Explicit opt-in (mirrors the gateway's audit key autogen).
	SigningKeyAutogen bool `yaml:"signing_key_autogen"`

	TLS          TLSConfig          `yaml:"tls"`
	Registration RegistrationConfig `yaml:"registration"`
	OAuth        OAuthConfig        `yaml:"oauth"`
	Mesh         MeshConfig         `yaml:"mesh"`
	Backend      BackendConfig      `yaml:"backend"`
	Limits       LimitsConfig       `yaml:"limits"`
}

// TLSConfig selects exactly one TLS mode: operator-provided cert files, or an
// ACME block. Both absent, or both present, is a configuration error.
type TLSConfig struct {
	CertFile string      `yaml:"cert_file"`
	KeyFile  string      `yaml:"key_file"`
	ACME     *ACMEConfig `yaml:"acme"`
}

func (t TLSConfig) files() bool { return t.CertFile != "" || t.KeyFile != "" }
func (t TLSConfig) acme() bool  { return t.ACME != nil }

// ACMEConfig configures certmagic-backed automatic certificates.
type ACMEConfig struct {
	// Domains are the hostnames to obtain certificates for. The PublicURL host
	// MUST be one of them.
	Domains []string `yaml:"domains"`
	// Email is the ACME account contact.
	Email string `yaml:"email"`
	// CA is the ACME directory URL. Empty means Let's Encrypt production.
	CA string `yaml:"ca"`
	// CacheDir is where certmagic stores certificates/account keys.
	// Empty means <state_dir>/acme.
	CacheDir string `yaml:"cache_dir"`
	// Challenge is tls-alpn-01 (default) or http-01.
	Challenge string `yaml:"challenge"`
	// HTTPPort is the http-01 challenge listener port (default 80).
	HTTPPort int `yaml:"http_port"`
}

// RegistrationConfig gates the DCR endpoint.
type RegistrationConfig struct {
	Mode string `yaml:"mode"` // open-approval (default) | token
	// InitialAccessTokens are honored only in token mode.
	InitialAccessTokens []InitialAccessToken `yaml:"initial_access_tokens"`
	// MaxPending caps outstanding pending registrations (open-approval mode),
	// bounding the disk-exhaustion → fail-closed-audit cascade.
	MaxPending int `yaml:"max_pending"`
	// PendingTTL is how long an unapproved registration is retained before GC.
	PendingTTL Duration `yaml:"pending_ttl"`
}

// InitialAccessToken is a token-mode registration bootstrap credential. Either
// Token or TokenEnv must be set; TokenEnv (read from the environment) is
// preferred so the secret is not written to the config file.
type InitialAccessToken struct {
	Token      string `yaml:"token"`
	TokenEnv   string `yaml:"token_env"`
	MaxClients int    `yaml:"max_clients"`
}

// OAuthConfig sets token lifetimes and the session toggle.
type OAuthConfig struct {
	AccessTokenTTL  Duration `yaml:"access_token_ttl"`
	RefreshTokenTTL Duration `yaml:"refresh_token_ttl"`
	AuthzPendingTTL Duration `yaml:"authz_pending_ttl"`
	// Sessions enables full Streamable-HTTP sessions (Mcp-Session-Id + GET SSE).
	// When false the MCP endpoint is stateless POST-only (spec-legal).
	Sessions *bool `yaml:"sessions"`
	// DPoPReplayStore, when set, is a postgres:// DSN backing the edge's DPoP
	// replay store (jti + nonce tracking) with PostgreSQL, so replay protection
	// holds across edge restarts and across multiple edge instances behind one
	// public URL. Empty keeps the default in-process store (single-instance
	// semantics). Any non-postgres value is a configuration error — never a
	// silent fallback.
	DPoPReplayStore string `yaml:"dpop_replay_store"`
}

// SessionsEnabled reports the effective session toggle (default true).
func (o OAuthConfig) SessionsEnabled() bool { return o.Sessions == nil || *o.Sessions }

// MeshConfig mirrors the gateway's mesh membership fields. The edge dials one
// backend over this mesh; it never binds a mesh listener of its own.
type MeshConfig struct {
	DeviceName    string `yaml:"device_name"`
	ManagementURL string `yaml:"management_url"`
	SetupKey      string `yaml:"setup_key"`
	SetupKeyEnv   string `yaml:"setup_key_env"`
	SetupKeyFile  string `yaml:"setup_key_file"`
	ConfigPath    string `yaml:"config_path"`
	LogLevel      string `yaml:"log_level"`
	WireguardPort int    `yaml:"wireguard_port"`
}

// BackendConfig is the single mesh backend this edge exposes at /mcp.
type BackendConfig struct {
	// Name is the capability audience and the audit backend label.
	Name string `yaml:"name"`
	// Addr is the backend's mesh address (host:port) speaking newline-framed
	// JSON-RPC — the wire meshmcp's stdio/resumable gateways expose.
	Addr string `yaml:"addr"`
	// Tools is the grant ceiling: the tools a minted capability may reference,
	// intersected with what an authorization requests.
	Tools []string `yaml:"tools"`
	// Policy is the standard meshmcp policy applied to oauth:<client_id>
	// identities. default_allow: true is a startup error.
	Policy policy.Policy `yaml:"policy"`
	// Payment, when present and enabled, gates priced tools behind an x402
	// payment (HTTP 402 → pay → retry) and optionally exposes a free dry-run
	// route. Absent/disabled keeps the edge byte-identical to a pre-payment
	// build. See PaymentConfig and docs/spec/PAYMENT-EVIDENCE.md.
	Payment PaymentConfig `yaml:"payment"`
}

// PaymentConfig configures x402 payment gating for the exposed backend. It is
// off unless Enabled; when off, no tool is priced and no dry-run route exists,
// so the edge behaves exactly as before. The actual payment verify/settle is
// performed by an injected PaymentVerifier (Options.PaymentVerifier); this
// block only declares WHAT is charged and advertises the challenge.
type PaymentConfig struct {
	// Enabled turns on payment gating for this backend.
	Enabled bool `yaml:"enabled"`
	// Scheme is the payment scheme advertised and recorded. Defaults to "x402".
	Scheme string `yaml:"scheme"`
	// Network is the settlement network label, e.g. "base-sepolia".
	Network string `yaml:"network"`
	// Asset is the settlement asset label, e.g. "USDC".
	Asset string `yaml:"asset"`
	// PayTo is the server's OWN receiving address, advertised publicly in the
	// 402 challenge. It is the payee, never a caller wallet, and is deliberately
	// the one address in this system that is public — it is not payment evidence.
	PayTo string `yaml:"pay_to"`
	// Facilitator is the advisory URL of the x402 facilitator that verifies and
	// settles payments; surfaced in the challenge so a client knows where its
	// payment is checked. The verify itself runs through the injected
	// PaymentVerifier, never by trusting this field.
	Facilitator string `yaml:"facilitator"`
	// Prices maps a tool-name glob (path.Match syntax, like policy tool rules) to
	// a price in the asset's minor units, kept as a string for exact precision. A
	// tool matching no entry is free (ungated). Overlapping globs are rejected at
	// Validate time (see globsOverlap) so at most one entry can match a tool, and
	// priceFor iterates in sorted order, keeping the charged price unambiguous and
	// independent of Go's randomized map iteration.
	Prices map[string]string `yaml:"prices"`
	// FreeDryRun exposes a free dry-run route: a request carrying the
	// X-Meshmcp-Dry-Run header is validated (identity + policy) and answered with
	// a synthetic result WITHOUT charging or invoking the backend, emitting a
	// dry-run-marked payment-evidence record so a client can rehearse the paid
	// flow and evidence shape at no cost.
	FreeDryRun bool `yaml:"free_dry_run"`
	// DevInsecureVerifier explicitly opts into the built-in dev verifier when no
	// real PaymentVerifier is injected at construction. The dev verifier checks
	// only payload well-formedness and amount — it performs NO on-chain
	// settlement and NO signature verification, so ANY well-formed X-PAYMENT is
	// accepted. It exists for local testing and demos ONLY. Enabling payment
	// without either injecting a verifier or setting this flag is a fail-closed
	// construction error (mirrors the DPoP replay-store and signing-key
	// precedents): a security-relevant collaborator is never silently
	// downgraded. NEVER set this in production.
	DevInsecureVerifier bool `yaml:"dev_insecure_verifier"`
	// Salt scopes the payer-ref hash in emitted evidence to this deployment.
	// Empty defaults to the backend name.
	Salt string `yaml:"salt"`
}

// scheme returns the effective payment scheme (default "x402").
func (p PaymentConfig) scheme() string {
	if p.Scheme == "" {
		return "x402"
	}
	return p.Scheme
}

// LimitsConfig bounds abuse at the public edge. Zero values take defaults.
type LimitsConfig struct {
	RegisterPerIPPerMin  int `yaml:"register_per_ip_per_min"`
	PreauthPerIPPerMin   int `yaml:"preauth_per_ip_per_min"`
	PerClientRPS         int `yaml:"per_client_rps"`
	PerClientBurst       int `yaml:"per_client_burst"`
	MaxSessionsPerClient int `yaml:"max_sessions_per_client"`
	MaxSSEBufferMsgs     int `yaml:"max_sse_buffer_msgs"`
	MaxMCPBodyBytes      int `yaml:"max_mcp_body_bytes"`
}

// withDefaults returns a copy of c with zero-valued optional fields filled in.
// Required fields are never defaulted — Validate rejects their absence.
func (c Config) withDefaults() Config {
	if c.Registration.Mode == "" {
		c.Registration.Mode = RegistrationOpenApproval
	}
	if c.Registration.MaxPending == 0 {
		c.Registration.MaxPending = defaultMaxPending
	}
	if c.Registration.PendingTTL == 0 {
		c.Registration.PendingTTL = Duration(defaultPendingTTL)
	}
	if c.OAuth.AccessTokenTTL == 0 {
		c.OAuth.AccessTokenTTL = Duration(defaultAccessTokenTTL)
	}
	if c.OAuth.RefreshTokenTTL == 0 {
		c.OAuth.RefreshTokenTTL = Duration(defaultRefreshTokenTTL)
	}
	if c.OAuth.AuthzPendingTTL == 0 {
		c.OAuth.AuthzPendingTTL = Duration(defaultAuthzPendingTTL)
	}
	if c.TLS.acme() {
		if c.TLS.ACME.Challenge == "" {
			c.TLS.ACME.Challenge = ChallengeTLSALPN01
		}
		if c.TLS.ACME.HTTPPort == 0 {
			c.TLS.ACME.HTTPPort = defaultACMEHTTPPort
		}
	}
	l := &c.Limits
	if l.RegisterPerIPPerMin == 0 {
		l.RegisterPerIPPerMin = defaultRegisterPerIPPerMin
	}
	if l.PreauthPerIPPerMin == 0 {
		l.PreauthPerIPPerMin = defaultPreauthPerIPPerMin
	}
	if l.PerClientRPS == 0 {
		l.PerClientRPS = defaultPerClientRPS
	}
	if l.PerClientBurst == 0 {
		l.PerClientBurst = defaultPerClientBurst
	}
	if l.MaxSessionsPerClient == 0 {
		l.MaxSessionsPerClient = defaultMaxSessionsPerClient
	}
	if l.MaxSSEBufferMsgs == 0 {
		l.MaxSSEBufferMsgs = defaultMaxSSEBufferMsgs
	}
	if l.MaxMCPBodyBytes == 0 {
		l.MaxMCPBodyBytes = defaultMaxMCPBodyBytes
	}
	return c
}

// Validate fills defaults and reports the first configuration error. It is the
// single authority on a well-formed, safe-by-default edge configuration.
func (c Config) Validate() (Config, error) {
	c = c.withDefaults()

	if c.Listen == "" {
		return c, fmt.Errorf("edge: listen is required (no default — the edge never binds a default-on public port)")
	}
	if c.PublicURL == "" {
		return c, fmt.Errorf("edge: public_url is required")
	}
	pu, err := url.Parse(c.PublicURL)
	if err != nil || pu.Scheme != "https" || pu.Host == "" {
		return c, fmt.Errorf("edge: public_url must be an absolute https URL, got %q", c.PublicURL)
	}
	if strings.HasSuffix(c.PublicURL, "/") {
		return c, fmt.Errorf("edge: public_url must not end with a trailing slash: %q", c.PublicURL)
	}
	if c.StateDir == "" {
		return c, fmt.Errorf("edge: state_dir is required")
	}
	if c.AuditLog == "" {
		return c, fmt.Errorf("edge: audit_log is required (the edge audit ledger is always fail-closed)")
	}
	if c.SigningKey == "" {
		return c, fmt.Errorf("edge: signing_key is required")
	}

	// Exactly one TLS mode.
	switch {
	case c.TLS.files() && c.TLS.acme():
		return c, fmt.Errorf("edge: tls has both cert_file/key_file and acme — choose exactly one")
	case c.TLS.files():
		if c.TLS.CertFile == "" || c.TLS.KeyFile == "" {
			return c, fmt.Errorf("edge: tls cert_file and key_file must both be set")
		}
	case c.TLS.acme():
		if len(c.TLS.ACME.Domains) == 0 {
			return c, fmt.Errorf("edge: tls.acme.domains must list at least one hostname")
		}
		if c.TLS.ACME.Challenge != ChallengeTLSALPN01 && c.TLS.ACME.Challenge != ChallengeHTTP01 {
			return c, fmt.Errorf("edge: tls.acme.challenge must be %q or %q", ChallengeTLSALPN01, ChallengeHTTP01)
		}
		if !containsFold(c.TLS.ACME.Domains, pu.Hostname()) {
			return c, fmt.Errorf("edge: public_url host %q must be one of tls.acme.domains %v", pu.Hostname(), c.TLS.ACME.Domains)
		}
	default:
		return c, fmt.Errorf("edge: tls requires either cert_file/key_file or an acme block")
	}

	switch c.Registration.Mode {
	case RegistrationOpenApproval:
	case RegistrationToken:
		if len(c.Registration.InitialAccessTokens) == 0 {
			return c, fmt.Errorf("edge: registration.mode=token requires at least one initial_access_tokens entry")
		}
	default:
		return c, fmt.Errorf("edge: registration.mode must be %q or %q", RegistrationOpenApproval, RegistrationToken)
	}

	if c.OAuth.AccessTokenTTL.Std() > maxAccessTokenTTL {
		return c, fmt.Errorf("edge: oauth.access_token_ttl %s exceeds the %s ceiling (the minted capability shares this TTL)", c.OAuth.AccessTokenTTL.Std(), maxAccessTokenTTL)
	}
	if c.OAuth.RefreshTokenTTL < c.OAuth.AccessTokenTTL {
		return c, fmt.Errorf("edge: oauth.refresh_token_ttl must be >= access_token_ttl")
	}
	if c.OAuth.DPoPReplayStore != "" && !isPostgresDSN(c.OAuth.DPoPReplayStore) {
		// The value is not echoed: a mistyped DSN may carry credentials.
		return c, fmt.Errorf("edge: oauth.dpop_replay_store must be a postgres:// or postgresql:// DSN")
	}

	if c.Backend.Name == "" {
		return c, fmt.Errorf("edge: backend.name is required")
	}
	if c.Backend.Addr == "" {
		return c, fmt.Errorf("edge: backend.addr is required (the mesh host:port of the one exposed backend)")
	}
	if c.Backend.Policy.DefaultAllow {
		return c, fmt.Errorf("edge: backend.policy.default_allow must be false — the public edge is deny-by-default")
	}
	if err := c.Backend.Payment.validate(); err != nil {
		return c, err
	}

	return c, nil
}

// validate checks the payment block. A disabled block is always valid (it is
// inert). An enabled block must name an asset, price at least one tool, and use
// well-formed, non-overlapping tool globs (overlap would make pricing depend on
// non-deterministic map iteration).
func (p PaymentConfig) validate() error {
	if !p.Enabled {
		return nil
	}
	if p.Asset == "" {
		return fmt.Errorf("edge: backend.payment.asset is required when payment is enabled")
	}
	if len(p.Prices) == 0 {
		return fmt.Errorf("edge: backend.payment.enabled is true but no prices are set (nothing would ever be charged)")
	}
	globs := make([]string, 0, len(p.Prices))
	for pattern, price := range p.Prices {
		if _, err := path.Match(pattern, ""); err != nil {
			return fmt.Errorf("edge: backend.payment.prices: bad tool glob %q: %w", pattern, err)
		}
		if price == "" {
			return fmt.Errorf("edge: backend.payment.prices[%q]: price must not be empty", pattern)
		}
		globs = append(globs, pattern)
	}
	for i := 0; i < len(globs); i++ {
		for j := i + 1; j < len(globs); j++ {
			if globsOverlap(globs[i], globs[j]) {
				return fmt.Errorf("edge: backend.payment.prices: tool globs %q and %q overlap; pricing must be unambiguous", globs[i], globs[j])
			}
		}
	}
	return nil
}

// globsOverlap reports whether two price globs could both match some tool name,
// which would make the charged price ambiguous. It is SOUND (no false
// negatives): it never reports "no overlap" for a pair that actually
// intersects, so a config that passes validation can never price a tool
// non-deterministically. It may be conservative (reject a disjoint pair), which
// only makes validation stricter — an operator can always rename a glob.
//
//   - Two distinct pure literals never overlap.
//   - Literal vs glob: exact path.Match test.
//   - Two globs: a common match would have to begin with BOTH patterns' fixed
//     literal prefixes (the text before the first metacharacter), so it exists
//     only if one prefix is a prefix of the other. Incompatible prefixes prove
//     disjointness; compatible prefixes are treated as a (possible) overlap.
func globsOverlap(a, b string) bool {
	if a == b {
		return true
	}
	aWild := strings.ContainsAny(a, "*?[")
	bWild := strings.ContainsAny(b, "*?[")
	switch {
	case !aWild && !bWild:
		return false // two distinct literals cannot both match one tool
	case !aWild:
		ok, _ := path.Match(b, a)
		return ok
	case !bWild:
		ok, _ := path.Match(a, b)
		return ok
	default:
		pa, pb := literalPrefix(a), literalPrefix(b)
		return strings.HasPrefix(pa, pb) || strings.HasPrefix(pb, pa)
	}
}

// literalPrefix returns the fixed leading text of a glob, up to (not including)
// the first path.Match metacharacter.
func literalPrefix(glob string) string {
	if i := strings.IndexAny(glob, "*?["); i >= 0 {
		return glob[:i]
	}
	return glob
}

// isPostgresDSN reports whether a store value selects a PostgreSQL backend.
// Mirrors cmd/meshmcp's session_store helper of the same name.
func isPostgresDSN(s string) bool {
	return strings.HasPrefix(s, "postgres://") || strings.HasPrefix(s, "postgresql://")
}

func containsFold(hay []string, needle string) bool {
	for _, h := range hay {
		if strings.EqualFold(h, needle) {
			return true
		}
	}
	return false
}
