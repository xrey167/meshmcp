package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/xrey167/meshmcp/air"
	"github.com/xrey167/meshmcp/policy"
	"github.com/xrey167/meshmcp/secrets"
)

// SecretsConfig configures the credential broker for a backend: a store to
// resolve secret names from, and grants that decide which identities may
// inject which secrets into which tools. Agents reference secrets by name
// ({{secret:NAME}}) and never hold the value.
type SecretsConfig struct {
	// File is a JSON secrets file ({"name":"value",...}); SHOULD be mode 0600.
	File string `yaml:"file"`
	// EnvPrefix reads secrets from environment variables named prefix+NAME.
	EnvPrefix string `yaml:"env_prefix"`
	// Grants authorize secret injection by identity, tool, and session label.
	Grants []secrets.Grant `yaml:"grants"`
}

// Config is the meshmcp serve configuration.
type Config struct {
	Mesh MeshConfig `yaml:"mesh"`
	// AuditLog, when set, is a single gateway-wide tamper-evident audit ledger
	// shared by every policy- or capability-enabled backend — one hash chain for
	// the whole gateway, which is what a unified live view (dash / room) reads.
	// When empty, each backend uses its own audit_log.
	AuditLog string `yaml:"audit_log"`
	// AuditFailClosed makes the gateway-wide shared ledger a hard control:
	// a record that cannot be written denies the call. Off by default.
	AuditFailClosed bool `yaml:"audit_fail_closed"`
	// AuditFsync fsyncs each committed audit record so the tamper-evident ledger
	// survives power loss (not just a process crash). ON BY DEFAULT — a nil value
	// means true; set `audit_fsync: false` to opt out on throughput-sensitive
	// deployments (one fsync per audited decision has a real hot-path cost).
	AuditFsync *bool `yaml:"audit_fsync"`
	// AuditRotateBytes, when > 0, rotates the shared ledger when the active
	// file would exceed this size: the segment is sealed (fsync+close), renamed
	// to <audit_log>.<UTC timestamp>, and a fresh file continues the SAME hash
	// chain (next seq, prev_hash into the archive). Verify the full history by
	// concatenating segments in name order. 0 (default) = no rotation.
	AuditRotateBytes int64 `yaml:"audit_rotate_bytes"`
	// AuditWebhook POSTs audit records to an external URL (SIEM / Slack /
	// PagerDuty) via a best-effort observer sink. AuditWebhookAll forwards every
	// record; by default only deny/cosign records are sent.
	AuditWebhook    string `yaml:"audit_webhook"`
	AuditWebhookAll bool   `yaml:"audit_webhook_all"`
	// MetricsListen serves Prometheus text-format metrics (aggregated from the
	// shared audit ledger; metadata-only labels, never a peer identity or
	// payload) on GET /metrics at this address. Bind it to localhost or a mesh
	// IP — the endpoint is unauthenticated by Prometheus convention. Empty
	// disables it. Requires audit_log (the sink observes the shared ledger).
	MetricsListen string `yaml:"metrics_listen"`
	// AuditOTLP exports committed audit records to an OTLP/HTTP logs endpoint
	// (an OpenTelemetry collector) via a best-effort observer sink — batched,
	// non-blocking, metadata-only. Requires audit_log (the sink observes the
	// shared ledger). See AuditOTLPConfig in otlpsink.go.
	AuditOTLP *AuditOTLPConfig `yaml:"audit_otlp"`
	Trace     *TraceConfig     `yaml:"trace"`
	Registry  string           `yaml:"registry"` // dir: register backends for router discovery
	// TrustDomain is this gateway's SPIFFE trust domain (Feature A). When set,
	// every local audit record is additively labeled with the caller's derived
	// identity, spiffe://<trust_domain>/peer/<key>, in peer_spiffe_id. A label
	// only — enforcement still keys solely on the WireGuard public key. Empty
	// (the default) means no label is ever emitted and records are
	// byte-identical to a build without the field. This is the LOCAL gateway
	// domain; it is never used for federation crossings (those use the per-org
	// mappings' trust_domain in the federate config, and vice versa).
	TrustDomain string `yaml:"trust_domain"`
	// Groups maps a group name to member patterns (pubkey:<key> or FQDN glob)
	// so policy rules can match `group:<name>` (F17). Shared by all backends.
	Groups map[string][]string `yaml:"groups"`
	// Operators names the people who may operate this gateway: approve co-signs,
	// approve/deny/revoke pairing, and list/steer sessions. Adding an operator
	// here (or with `air operator add`) grants the control/steer + pairing-approver
	// surface WITHOUT hand-editing control.allow — the second-operator onboarding
	// seam. Recognition is by the unforgeable WireGuard public key.
	Operators []OperatorConfig `yaml:"operators"`
	Control   *ControlConfig   `yaml:"control"` // optional: Air session-control endpoint
	Hooks     *HooksConfig     `yaml:"hooks"`   // publish policy decisions to the event bus and/or a webhook
	// OIDC enables SSO-mapped group attribution (F31): a verified external IdP
	// token presented over an already-authenticated mesh connection attributes
	// its `groups` claim to the caller's WireGuard TRANSPORT key, so existing
	// `group:<name>` policy rules match SSO-derived groups too. It is ADDITIVE —
	// the transport identity stays the root of trust; a forged/expired/
	// wrong-audience token maps to nothing (deny). nil (the default) = no SSO,
	// byte-identical to today. Requires control.port (the /v1/sso/attest binding
	// surface mounts on the mesh control listener).
	OIDC     *OIDCConfig `yaml:"oidc"`
	Backends []*Backend  `yaml:"backends"`
}

// Group bounds (F17 policy groups + `group:` fan-out). maxGroupMembers caps
// both the patterns per group AND the members one fan-out may resolve to;
// both it and the per-pattern byte bound alias the air envelope bounds so
// config and wire can never skew.
const (
	maxGroups            = 256
	maxGroupMembers      = air.MaxFanoutMembers
	maxGroupPatternBytes = air.MaxGroupPatternBytes
)

// validateGroups rejects a malformed top-level groups map at load time, so a
// group name always fits the `group:<name>` selector grammar (no ":", bounded,
// control-free — see air.ValidateGroupName) and every member pattern is a
// usable acl pattern. An EMPTY pattern list stays legal: a defined-but-empty
// group is a loud no-op at fan-out time, never a silent one.
func validateGroups(groups map[string][]string) error {
	if len(groups) > maxGroups {
		return fmt.Errorf("groups: %d groups defined; max is %d", len(groups), maxGroups)
	}
	for name, patterns := range groups {
		if err := air.ValidateGroupName(name); err != nil {
			return fmt.Errorf("groups: %q: %w", name, err)
		}
		if len(patterns) > maxGroupMembers {
			return fmt.Errorf("groups: %q has %d member patterns; max is %d", name, len(patterns), maxGroupMembers)
		}
		for i, p := range patterns {
			// The SAME rule the fan-out envelope applies to its unmatched echo
			// (air.ValidateGroupPattern), so a pattern this loader accepts can
			// never invalidate a result envelope after deliveries ran.
			if err := air.ValidateGroupPattern(p); err != nil {
				return fmt.Errorf("groups: %q member pattern #%d: %w", name, i+1, err)
			}
			if key, ok := strings.CutPrefix(p, "pubkey:"); ok && strings.TrimSpace(key) == "" {
				return fmt.Errorf("groups: %q member pattern #%d: the pubkey: form requires a key", name, i+1)
			}
		}
	}
	return nil
}

// OperatorConfig names one person permitted to operate this gateway. Identity is
// the unforgeable WireGuard public key; the FQDN is advisory (for readability),
// and Roles is reserved for finer control RBAC. It is recognized on the same
// control/steer + pairing-approver surface as control.allow, so a second operator
// can approve and pair without being hand-added to that allow list.
type OperatorConfig struct {
	PubKey string   `yaml:"pubkey"`          // WireGuard public key (unforgeable) — the primary identity
	FQDN   string   `yaml:"fqdn,omitempty"`  // advisory mesh FQDN, for human readability
	Roles  []string `yaml:"roles,omitempty"` // optional role labels (reserved for control RBAC)
}

// operatorPatterns yields the acl patterns (pubkey:<key> and any advisory FQDN)
// for the configured operators, so they are recognized on the control/steer and
// pairing-approver surface alongside control.allow.
func operatorPatterns(ops []OperatorConfig) []string {
	pats := make([]string, 0, len(ops))
	for _, o := range ops {
		if o.PubKey != "" {
			pats = append(pats, "pubkey:"+o.PubKey)
		}
		if o.FQDN != "" {
			pats = append(pats, o.FQDN)
		}
	}
	return pats
}

// ControlConfig enables the Air session-control endpoint: a mesh HTTP surface
// (GET /v1/sessions, POST /v1/steer) that lists and steers this gateway's live
// resumable sessions. It listens only on the mesh, resolves the caller's
// WireGuard identity, gates on Allow, and audits every steer.
type ControlConfig struct {
	Port  int      `yaml:"port"`  // mesh port to serve the control endpoint on
	Allow []string `yaml:"allow"` // identities permitted to list/steer (FQDN globs or pubkey:<key>); required (default-deny — empty is a startup error)
	// OnBehalfAllow lists the proxy identities (the air-serve relay) permitted
	// to attest an X-Air-On-Behalf browser identity for audit attribution. It
	// is deliberately SEPARATE from Allow so a general allowed caller cannot
	// forge attribution, and it fails closed: empty ⇒ no peer may attest, so
	// receipts stay attributed to the verified connecting peer.
	OnBehalfAllow []string `yaml:"on_behalf_allow"`
	// PairStore, when set, enables pairing: peers can request access with
	// `air join` and an operator approves with `air pair approve`, adding them
	// to a durable RECOGNIZED-peer store at this path (atomic, audited) WITHOUT
	// editing the allow list above. Recognition is NOT authorization — a paired
	// peer is a known identity, never auto-granted the privileged control-steer
	// allow or any tool ACL (that is grant-on-request, a separate explicit
	// step). Empty ⇒ pairing off. Approve/deny/revoke are gated on Allow above.
	PairStore string `yaml:"pair_store"`
}

// OIDCConfig configures SSO-mapped group attribution (F31). Keys are pinned
// STATICALLY per issuer (a JWKS document on disk, or a PEM public key) — there is
// no outbound network call on the verify path, mirroring
// federation/exchange.go's PinnedIssuers. A forged/expired/wrong-audience token
// attributes nothing; enforcement always keys on the WireGuard transport key.
type OIDCConfig struct {
	// Audience is meshmcp's identity that a presented token's `aud` MUST contain
	// (audience-confusion defense). Required when oidc is set.
	Audience string `yaml:"audience"`
	// GroupsClaim / EmailClaim name the token claim paths (defaults "groups" /
	// "email").
	GroupsClaim string `yaml:"groups_claim"`
	EmailClaim  string `yaml:"email_claim"`
	// BindTTLMaxSeconds caps a binding's lifetime: a bind lives for
	// min(token.exp, now + this). 0 means the default 3600s. Bounds the blast
	// radius of any single attribution.
	BindTTLMaxSeconds int `yaml:"bind_ttl_max"`
	// Issuers pins each trusted external issuer's algorithm and public key(s).
	Issuers []OIDCIssuerConfig `yaml:"issuers"`

	// resolved holds the parsed verifier issuers (populated at load); bindTTL is
	// the resolved cap. Unexported so serve.go reuses them without re-reading key
	// files.
	resolved map[string]*policy.OIDCIssuer
	bindTTL  time.Duration
}

// OIDCIssuerConfig pins one external issuer. Exactly one of JWKSFile or KeyFile
// must be set. Alg is PINNED here per issuer and is never read from a token's own
// header to choose a verification path.
type OIDCIssuerConfig struct {
	// Issuer is the exact `iss` string this key set verifies (no glob, no "*").
	Issuer string `yaml:"issuer"`
	// Alg is the pinned signing algorithm: "ES256" or "RS256".
	Alg string `yaml:"alg"`
	// JWKSFile is a path to a pinned RFC 7517 JWK Set document (the IdP's
	// published keys, saved locally). Supports multiple keys + `kid` rotation.
	JWKSFile string `yaml:"jwks_file"`
	// KeyFile is a path to a single PEM-encoded public key (an alternative to
	// jwks_file for a one-key issuer).
	KeyFile string `yaml:"key_file"`
	// JWKSURI is REJECTED in v1: an automatic cached fetch of the IdP's JWKS URI
	// is the documented v2 extension. v1 pins the JWKS document itself (jwks_file)
	// so verification stays offline and deterministic — the honesty boundary is
	// explicit. Setting it is a config error.
	JWKSURI string `yaml:"jwks_uri"`
}

const (
	maxOIDCIssuers     = 64
	defaultOIDCBindTTL = 3600  // seconds
	maxOIDCBindTTLSecs = 86400 // 24h ceiling on a single attribution
	maxOIDCIssuerLenB  = 512
)

// validateOIDC validates the OIDC config and resolves every pinned key at load
// (fail closed on an unreadable/unparseable key — a security-config error, never
// a silent skip; mirrors the LoadSigner startup convention). It populates
// cfg.OIDC.resolved / .bindTTL for serve.go to construct the verifier from.
func validateOIDC(oc *OIDCConfig) error {
	if oc == nil {
		return nil
	}
	if strings.TrimSpace(oc.Audience) == "" {
		return fmt.Errorf("oidc: audience is required (a token's aud must contain meshmcp's identity)")
	}
	if len(oc.Issuers) == 0 {
		return fmt.Errorf("oidc: at least one issuer must be pinned (an empty pin set verifies nothing)")
	}
	if len(oc.Issuers) > maxOIDCIssuers {
		return fmt.Errorf("oidc: %d issuers pinned; max is %d", len(oc.Issuers), maxOIDCIssuers)
	}
	if oc.BindTTLMaxSeconds < 0 {
		return fmt.Errorf("oidc: bind_ttl_max must be >= 0")
	}
	if oc.BindTTLMaxSeconds > maxOIDCBindTTLSecs {
		return fmt.Errorf("oidc: bind_ttl_max %d exceeds the %d-second ceiling", oc.BindTTLMaxSeconds, maxOIDCBindTTLSecs)
	}
	ttl := oc.BindTTLMaxSeconds
	if ttl == 0 {
		ttl = defaultOIDCBindTTL
	}
	oc.bindTTL = time.Duration(ttl) * time.Second

	resolved := make(map[string]*policy.OIDCIssuer, len(oc.Issuers))
	for i, ic := range oc.Issuers {
		iss := strings.TrimSpace(ic.Issuer)
		if iss == "" {
			return fmt.Errorf("oidc: issuer #%d: issuer string is required", i+1)
		}
		if len(iss) > maxOIDCIssuerLenB || hasCtrl(iss) {
			return fmt.Errorf("oidc: issuer #%d: issuer must be at most %d bytes with no control characters", i+1, maxOIDCIssuerLenB)
		}
		if _, dup := resolved[iss]; dup {
			return fmt.Errorf("oidc: issuer %q is pinned more than once", iss)
		}
		if ic.Alg != policy.OIDCAlgES256 && ic.Alg != policy.OIDCAlgRS256 {
			return fmt.Errorf("oidc: issuer %q: alg %q is not one of %s|%s", iss, ic.Alg, policy.OIDCAlgES256, policy.OIDCAlgRS256)
		}
		if ic.JWKSURI != "" {
			return fmt.Errorf("oidc: issuer %q: jwks_uri is a v2 feature and not supported — pin the JWKS document with jwks_file so verification stays offline", iss)
		}
		hasJWKS, hasKey := ic.JWKSFile != "", ic.KeyFile != ""
		if hasJWKS == hasKey {
			return fmt.Errorf("oidc: issuer %q: set exactly one of jwks_file or key_file", iss)
		}
		keys, err := resolveOIDCKeys(ic)
		if err != nil {
			return fmt.Errorf("oidc: issuer %q: %w", iss, err)
		}
		resolved[iss] = &policy.OIDCIssuer{Alg: ic.Alg, Keys: keys}
	}
	oc.resolved = resolved
	return nil
}

// resolveOIDCKeys reads and parses an issuer's pinned key material, validating
// that every key's type matches the pinned algorithm.
func resolveOIDCKeys(ic OIDCIssuerConfig) (map[string]crypto.PublicKey, error) {
	var keys map[string]crypto.PublicKey
	if ic.JWKSFile != "" {
		data, err := os.ReadFile(ic.JWKSFile)
		if err != nil {
			return nil, fmt.Errorf("read jwks_file %s: %w", ic.JWKSFile, err)
		}
		keys, err = policy.ParseJWKS(data)
		if err != nil {
			return nil, err
		}
	} else {
		pub, err := loadPEMPublicKey(ic.KeyFile)
		if err != nil {
			return nil, err
		}
		keys = map[string]crypto.PublicKey{"": pub}
	}
	for kid, k := range keys {
		if err := keyMatchesAlg(k, ic.Alg); err != nil {
			return nil, fmt.Errorf("key (kid %q): %w", kid, err)
		}
	}
	return keys, nil
}

// loadPEMPublicKey reads a single PEM-encoded (PKIX) public key from path.
func loadPEMPublicKey(path string) (crypto.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read key_file %s: %w", path, err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("key_file %s: no PEM block found", path)
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("key_file %s: parse PKIX public key: %w", path, err)
	}
	return pub, nil
}

// keyMatchesAlg fails closed when a pinned key's type cannot produce the pinned
// algorithm's signatures (RS256 needs RSA, ES256 needs ECDSA), so an operator can
// never pin a key that will silently never verify.
func keyMatchesAlg(k crypto.PublicKey, alg string) error {
	switch alg {
	case policy.OIDCAlgRS256:
		if _, ok := k.(*rsa.PublicKey); !ok {
			return fmt.Errorf("alg RS256 requires an RSA public key, got %T", k)
		}
	case policy.OIDCAlgES256:
		if _, ok := k.(*ecdsa.PublicKey); !ok {
			return fmt.Errorf("alg ES256 requires an ECDSA public key, got %T", k)
		}
	default:
		return fmt.Errorf("unsupported alg %q", alg)
	}
	return nil
}

// TraceConfig turns on a gateway-wide trace of every MCP message (both
// directions, every stdio backend) as newline-delimited JSON.
type TraceConfig struct {
	Log      string `yaml:"log"`       // file path (required to enable tracing)
	Payloads bool   `yaml:"payloads"`  // include request params / response results
	MaxBytes int    `yaml:"max_bytes"` // cap a recorded payload (default 2048)
}

// MeshConfig configures the gateway's mesh membership.
type MeshConfig struct {
	DeviceName    string   `yaml:"device_name"`
	ManagementURL string   `yaml:"management_url"`
	SetupKey      string   `yaml:"setup_key"`
	SetupKeyEnv   string   `yaml:"setup_key_env"`
	ConfigPath    string   `yaml:"config_path"`
	LogLevel      string   `yaml:"log_level"`
	DNSLabels     []string `yaml:"dns_labels"`
	WireguardPort int      `yaml:"wireguard_port"`
}

// Backend is one MCP server exposed on a mesh port.
// Exactly one of Stdio or HTTP must be set.
type Backend struct {
	Name string `yaml:"name"`
	// ID is the stable component-card identity. Set it explicitly when a
	// backend may be renamed; otherwise the gateway derives one from its mesh
	// public key, component kind, and Name.
	ID string `yaml:"id,omitempty"`
	// Version is the backend's advertised product/protocol version. It is
	// discovery metadata only and never changes authorization.
	Version string `yaml:"version,omitempty"`
	Port    int    `yaml:"port"`
	// Stdio spawns this command per inbound connection and pipes the
	// connection to its stdin/stdout (raw JSON-RPC transport).
	Stdio []string `yaml:"stdio"`
	// HTTP reverse-proxies inbound requests to this local base URL
	// (for MCP servers speaking Streamable HTTP).
	HTTP string `yaml:"http"`
	// Remote forwards inbound requests to a third-party MCP server over the
	// public internet, authenticating outbound with OAuth 2.1 + DPoP-bound
	// tokens (Feature B). Exactly one of stdio, http, or remote must be set.
	Remote *RemoteBackendConfig `yaml:"remote,omitempty"`
	// Allow lists peers permitted to use this backend: FQDN globs
	// (e.g. "laptop-*.netbird.cloud") or "pubkey:<wireguard-key>".
	// Empty means any mesh peer.
	Allow []string `yaml:"allow"`
	// Resumable keeps the backend subprocess alive across client
	// reconnects and replays missed messages, so a stdio MCP session
	// survives the mesh connection dropping (roaming, sleep/wake).
	// Only valid for stdio backends; clients must use "connect --resumable".
	Resumable bool `yaml:"resumable"`
	// SessionTTLSeconds is how long a detached resumable session is kept
	// waiting for reattach (default 120s).
	SessionTTLSeconds int `yaml:"session_ttl_seconds"`
	// SessionStore is a directory where resumable session state is
	// checkpointed, so another gateway process sharing this directory can
	// resume a session after a failover. A postgres:// (or postgresql://)
	// DSN checkpoints state in PostgreSQL instead, whose lease CAS is safe
	// for multi-gateway HA. Only valid for resumable stdio backends;
	// migration replays the handshake against a fresh backend, so the
	// backend must be stateless per request.
	SessionStore string `yaml:"session_store"`
	// SessionStoreMode selects how a resumed backend is reconstructed:
	// "handshake" (default, stateless backends), "full" (replay the whole
	// client->backend log, idempotent backends), or "backend" (the backend
	// restores its own state from MESHMCP_SESSION_ID).
	SessionStoreMode string `yaml:"session_store_mode"`
	// SessionFailover selects "standby" to run an expiry-driven sweep: this
	// gateway adopts sessions whose owner stopped renewing its lease (crashed
	// or paused past a conservative margin of 2x the session TTL), respawning
	// the backend before the client returns. Safety comes from the store's
	// lease generation CAS (exactly one adopter; the previous owner is fenced),
	// never from timing. Empty or "off" keeps failover reattach-driven.
	// Requires resumable + a PostgreSQL session_store (a file store's lock can
	// be stolen from a paused-not-dead gateway, which could regress the
	// generation an adoption committed).
	SessionFailover string `yaml:"session_failover"`
	// SessionSweepSeconds is how often the standby sweep scans the store for
	// adoptable sessions (default 30, minimum 5). Only meaningful with
	// session_failover: standby.
	SessionSweepSeconds int `yaml:"session_sweep_seconds"`
	// MovePort, when >0, makes this backend a live-session MOVE destination: it
	// serves a move-control listener on this mesh port so a source gateway can
	// hand it ownership of one live session (prepare->ready->commit, driven by
	// session.Server.ServeMoveControl). It is per-backend because the move
	// protocol carries a session id but not a backend name — each listener binds
	// to THIS backend's session server. Requires resumable + a session_store (a
	// move needs the CAS lease store) and a move-supported mode (handshake or
	// backend; "full" re-executes the input log and cannot be reconstructed).
	MovePort int `yaml:"move_port"`
	// MoveGrantStore is the single-use destination grant store the move commit
	// consumes (written by `air move grant`). Required when move_port is set:
	// deny-by-default, a move lands only if the operator pre-granted THIS gateway
	// (its WireGuard key) the exact session id, once.
	MoveGrantStore string `yaml:"move_grant_store"`
	// Policy authorizes individual tools/call requests by caller identity. For
	// stdio backends the gateway parses the JSON-RPC stream; for HTTP/remote
	// backends it parses each request body (F16). Rate limits, time windows,
	// co-sign, audit, taint labels, secret injection, and capabilities apply on
	// all three transports (HTTP/remote taint keys on Mcp-Session-Id; see the
	// Secrets/Capabilities field docs). DLP, shadow policies, and router
	// delegation remain stdio-only.
	Policy *policy.Policy `yaml:"policy"`
	// AuditLog is a file path for JSONL tool-call audit records. Empty
	// sends audit records to stderr. The log is a tamper-evident hash chain
	// (verify it with "meshmcp audit verify").
	AuditLog string `yaml:"audit_log"`
	// AuditFsync fsyncs each committed record (power-loss durability). On by
	// default (nil = true); set audit_fsync: false to opt out.
	AuditFsync *bool `yaml:"audit_fsync"`
	// AuditRotateBytes, when > 0, size-rotates this backend's audit_log (see
	// Config.AuditRotateBytes for the sealing/verification contract). Requires
	// audit_log (the stderr fallback cannot rotate). 0 = no rotation.
	AuditRotateBytes int64 `yaml:"audit_rotate_bytes"`
	// AuditCheckpoints is a file for signed Merkle checkpoints over the audit
	// log, making it non-repudiable and externally verifiable. Requires a
	// signing key (audit_signing_key). Verify with
	// "meshmcp audit verify <log> --checkpoints <f> --pubkey <hex>".
	AuditCheckpoints string `yaml:"audit_checkpoints"`
	// AuditSigningKey is the gateway Ed25519 key file (created by
	// "meshmcp audit keygen"). A missing file is fatal unless
	// audit_signing_key_autogen is set (see below).
	AuditSigningKey string `yaml:"audit_signing_key"`
	// AuditCheckpointEvery is how many records per checkpoint (default 128).
	AuditCheckpointEvery int `yaml:"audit_checkpoint_every"`
	// AuditAnchor is an append-only file where each checkpoint is also written
	// as an external witness (the transparency-log seam). Records are
	// self-linked (prev_anchor), so the anchor file is itself tamper-evident.
	AuditAnchor string `yaml:"audit_anchor"`
	// AuditAnchorURL POSTs each checkpoint to a peer gateway's witness endpoint
	// (the control plane's /v1/anchor, run with --anchor-witness). Best-effort
	// with a bounded retry queue: a witness outage never blocks a checkpoint,
	// and `meshmcp audit anchor` replays the checkpoints file idempotently
	// after an outage. May be combined with audit_anchor (both fire).
	AuditAnchorURL string `yaml:"audit_anchor_url"`
	// AuditFailClosed makes this backend's audit sink a hard control: when a
	// record cannot be written (full disk, I/O error), the call is denied
	// rather than proceeding unrecorded. Off by default (best-effort).
	AuditFailClosed bool `yaml:"audit_fail_closed"`
	// AuditSigningKeyAutogen permits generating audit_signing_key when the file
	// is absent. Off by default: a missing key is fatal, so an attacker cannot
	// force a fresh signing identity by deleting the file. Run
	// "meshmcp audit keygen --out <path>" to create one explicitly.
	AuditSigningKeyAutogen bool `yaml:"audit_signing_key_autogen"`
	// CosignStore is a shared directory holding human co-sign approvals for
	// rules with require_cosign. A human identity grants approvals with
	// "meshmcp approve". Only meaningful with a policy.
	CosignStore string `yaml:"cosign_store"`
	// CosignTTLSeconds bounds how long a co-sign approval stays valid
	// (0 = no expiry).
	CosignTTLSeconds int `yaml:"cosign_ttl_seconds"`
	// ApprovalSigningKey, when set, upgrades require_cosign from ambient
	// (peer, tool) grants to request-bound approvals: a held call is released only
	// by a signed, single-use token bound to its exact arguments (and policy
	// version). It is the Ed25519 key file SHARED with the approver
	// (`meshmcp approvals --approval-key`); the gateway pins its public key to
	// trust minted approvals. Requires cosign_store + a policy.
	ApprovalSigningKey string `yaml:"approval_signing_key"`
	// Secrets configures the credential broker: agents reference secrets by
	// name ({{secret:NAME}}) and the gateway injects the value by identity,
	// so the agent never holds the raw credential. Valid for stdio, http, and
	// remote backends with a policy. On http/remote, injected values are also
	// scrubbed from responses (JSON and SSE) per peer, and a response the
	// gateway cannot scan (compressed/oversized) is refused, never forwarded.
	Secrets *SecretsConfig `yaml:"secrets"`
	// Capabilities pins authority keys for signed capability grants. A valid
	// capability upgrades a policy-default-deny call to allow; required:true
	// makes the backend a capability-only surface. Valid for stdio, http, and
	// remote backends; the presented token is stripped from the body before it
	// reaches the backend on every transport.
	Capabilities *CapabilitiesConfig `yaml:"capabilities"`
	// RouterDelegation pins router delegation-authority keys ("meshmcp router
	// keygen"): a tools/call presenting a valid signed DelegationToken is
	// authorized as the INTERSECTION of the original caller's and the router's
	// permissions under this backend's policy; required:true makes every
	// tools/call carry a valid token. Delegation gates tools/call ONLY (v1):
	// other JSON-RPC methods (resources/read, prompts/get, tools/list, ...)
	// bypass it and stay governed by the policy's methods rules — add methods
	// rules to restrict those surfaces. Only valid for stdio backends with a
	// policy. Replay protection is per-gateway-process (in-memory nonce store).
	RouterDelegation *RouterDelegationConfig `yaml:"router_delegation"`
	// DLP declares content rules scanned against every tools/call's arguments:
	// a match can deny the call or emit a data-flow label (F18). Implemented as
	// a plugin decision hook; only valid for stdio backends with a policy.
	DLP []policy.DLPSpec `yaml:"dlp"`
	// ShadowPolicy is a CANDIDATE policy evaluated alongside the enforced one:
	// where the two disagree, the divergence is logged, but enforcement is
	// unchanged (F24). A live canary for a policy change. Stdio + a policy.
	ShadowPolicy *policy.Policy `yaml:"shadow_policy"`
	// EgressWrapper, when non-empty, prepends an operator-supplied OS
	// jailer/launcher to this backend's argv: wrapper[0] is exec'd and
	// wrapper[1:]+stdio become its arguments (it is expected to exec the tail
	// after applying containment, e.g. ["firejail","--net=none"]). meshmcp only
	// WIRES the argv — the OS enforces the network containment; meshmcp does
	// not, and pure Go cannot, restrict a child's egress cross-platform. This
	// is containment (defense-in-depth for the exfil-out-of-band residual on a
	// malicious backend that legitimately received an injected secret), not
	// cryptography; short-lived scoped credentials remain the primary
	// mitigation. Only valid for stdio backends (http/remote backends are not
	// spawned as a child process, so a wrapper is meaningless). Fail-closed: an
	// empty element, or a wrapper[0] that exec.LookPath cannot resolve, is a
	// startup error — a silently-unwrapped backend (full egress while the
	// operator believes it is contained) must never run. Empty = today's
	// behavior byte-for-byte.
	EgressWrapper []string `yaml:"egress_wrapper"`

	httpURL     *url.URL
	remoteURL   *url.URL            // parsed Remote.Endpoint, set at load
	groups      map[string][]string // resolved from Config.Groups at load
	trustDomain string              // resolved from Config.TrustDomain at load (Feature A)
	// allowACL is the RUNNING gateway's peer-admission handle for this backend,
	// set by cmdServe before the accept loops start. It shares its pattern list
	// atomically across copies, so a SIGHUP reload can swap the patterns and
	// every already-captured checker sees the change (see acl.swap).
	allowACL acl
}

// peerACL returns the backend's live admission handle when the gateway
// installed one, else a fresh ACL from the static config — the fallback keeps
// direct callers (tests exercising serveStdio and friends) working unchanged.
func (b *Backend) peerACL() acl {
	if b.allowACL.p != nil {
		return b.allowACL
	}
	return newACL(b.Allow)
}

// RemoteBackendConfig configures a "remote" backend: the gateway dials out to
// a third-party MCP server (Streamable HTTP), discovering its authorization
// server per the MCP authorization spec and presenting OAuth 2.1 access tokens
// bound with DPoP proofs (RFC 9449). Secrets are referenced by NAME through the
// existing secrets store — the config never holds a credential value, and the
// dpop key secret's value is a PATH to the key file ("meshmcp dpop keygen").
type RemoteBackendConfig struct {
	// Endpoint is the remote MCP server URL (https://host/path).
	Endpoint string `yaml:"endpoint"`
	// ClientID is this gateway's OAuth client id at the authorization server.
	ClientID string `yaml:"client_id"`
	// Scope is the optional space-separated scope string to request.
	Scope string `yaml:"scope"`
	// Secrets is the store holding the named secrets below (file and/or env).
	Secrets *SecretsConfig `yaml:"secrets"`
	// DPoPKeyName is the secret whose VALUE is the path of the ECDSA P-256
	// DPoP signing key file (default "dpop_private_key"). Missing key = fatal.
	DPoPKeyName string `yaml:"dpop_key_name"`
	// ClientSecretName is the secret holding the OAuth client secret
	// (default "oauth_client_secret"); absent = public client.
	ClientSecretName string `yaml:"client_secret_name"`
	// RefreshTokenName is the secret holding the current refresh token
	// (default "oauth_refresh_token"); rotated tokens are persisted back.
	RefreshTokenName string `yaml:"refresh_token_name"`
}

// RouterDelegationConfig configures signed router-delegation verification for
// a backend (docs/spec/ROUTER-DELEGATION.md). Deny-by-default: a token signed
// by an unpinned authority never verifies, and required:true refuses any
// tools/call without a valid token.
type RouterDelegationConfig struct {
	// Required makes every tools/call present a valid delegation token.
	// false verifies+intersects a call WITH a token and lets a token-less call
	// fall through to the ordinary single-hop policy path (mixed direct+routed
	// backends). NOTE: required gates tools/call only — it does NOT make the
	// whole backend router-only; non-tools/call methods bypass delegation and
	// need their own methods rules (see the RouterDelegation field doc).
	Required bool `yaml:"required"`
	// TrustedPublicKeys are the hex Ed25519 router-authority keys this gateway
	// pins; a token never supplies its own trust root.
	TrustedPublicKeys []string `yaml:"trusted_public_keys"`
}

// CapabilitiesConfig configures signed-capability admission for a backend.
type CapabilitiesConfig struct {
	// Required makes every tools/call present a valid capability.
	Required bool `yaml:"required"`
	// TrustedPublicKeys are the hex Ed25519 authority keys the gateway pins;
	// a token never supplies its own trust root.
	TrustedPublicKeys []string `yaml:"trusted_public_keys"`
	// RevocationStore is a directory of revoked capability ids. When set, a
	// token whose id was revoked ("meshmcp capability revoke") fails closed at
	// the enforcement point even before it expires.
	RevocationStore string `yaml:"revocation_store"`
}

func (b *Backend) kind() string {
	if b.Remote != nil {
		return "remote -> " + b.Remote.Endpoint
	}
	if b.HTTP != "" {
		return "http -> " + b.HTTP
	}
	if b.Resumable {
		return fmt.Sprintf("stdio(resumable) -> %v", b.Stdio)
	}
	return fmt.Sprintf("stdio -> %v", b.Stdio)
}

// loadConfig parses and validates a gateway config.
//
// Trust model: the config file is TRUSTED operator input (it names the backend
// commands the gateway will exec, the pinned trust roots, and the audit sinks).
// It is not attacker-controlled, so YAML alias/anchor expansion is not a
// hardening concern here. If a deployment ever renders configs from less-trusted
// input, template them into a fixed schema rather than unmarshalling them
// directly. Everything the config *governs* (peers, tool calls) remains
// untrusted and is enforced at request time.
// auditFsyncEnabled resolves the tri-state audit_fsync setting: a nil pointer
// means the default (on), matching the "durable by default, opt out" posture.
func auditFsyncEnabled(p *bool) bool { return p == nil || *p }

func loadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var cfg Config
	// Strict decoding: an unknown or misspelled key is a startup error, not a
	// silently ignored line. A typo in a SECURITY field (audit_fail_closed,
	// require_cosign, taint_guard, default_allow, ...) would otherwise fail open
	// — the control the operator thought they enabled simply never fires.
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}

	if len(cfg.Backends) == 0 {
		return nil, fmt.Errorf("config %s: no backends defined", path)
	}
	if cfg.AuditRotateBytes < 0 {
		return nil, fmt.Errorf("config %s: audit_rotate_bytes must be >= 0", path)
	}
	if cfg.AuditRotateBytes > 0 && cfg.AuditLog == "" {
		return nil, fmt.Errorf("config %s: audit_rotate_bytes requires audit_log", path)
	}
	// Validate the SPIFFE trust domain up front (Feature A, mirroring
	// federate.go): a malformed domain is a config error, not something to
	// silently derive empty labels from later. Empty stays valid (labels off).
	if cfg.TrustDomain != "" && !policy.ValidTrustDomain(cfg.TrustDomain) {
		return nil, fmt.Errorf("config %s: invalid trust_domain %q (want lowercase DNS-label form, e.g. mesh.example.org)", path, cfg.TrustDomain)
	}
	// OTLP export sink: validate FORM at startup (a malformed endpoint is a
	// config error); reachability is deliberately not checked — the collector
	// is an observer and may come up after the gateway.
	if cfg.AuditOTLP != nil {
		if cfg.AuditLog == "" {
			return nil, fmt.Errorf("config %s: audit_otlp requires audit_log (the OTLP sink observes the shared ledger)", path)
		}
		if err := cfg.AuditOTLP.validate(); err != nil {
			return nil, fmt.Errorf("config %s: %w", path, err)
		}
	}
	// Groups feed both policy `group:` peers (F17) and the `/v1/groups` fan-out
	// roster, so the map itself is validated before anything references it.
	if err := validateGroups(cfg.Groups); err != nil {
		return nil, fmt.Errorf("config %s: %w", path, err)
	}
	// OIDC (F31): validate + resolve pinned issuer keys at load. Absent ⇒ no SSO,
	// byte-identical to today.
	if err := validateOIDC(cfg.OIDC); err != nil {
		return nil, fmt.Errorf("config %s: %w", path, err)
	}
	seen := map[int]string{}
	seenNames := map[string]bool{}
	seenIDs := map[string]string{}
	for i, b := range cfg.Backends {
		b.groups = cfg.Groups
		b.trustDomain = cfg.TrustDomain
		// Canonicalize once before the name becomes a key in listener, ACL,
		// session-server, registry, and component-card maps. Letting the card
		// trim a different value later could miss the configured ACL and fall
		// back to the permissive empty-ACL behavior during discovery.
		b.Name = strings.TrimSpace(b.Name)
		if b.Name == "" {
			return nil, fmt.Errorf("backend #%d: name is required", i+1)
		}
		if len(b.Name) > 256 || strings.IndexFunc(b.Name, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
			return nil, fmt.Errorf("backend %q: name must be at most 256 bytes and contain no control characters", b.Name)
		}
		if seenNames[b.Name] {
			return nil, fmt.Errorf("backend %q: name is already used", b.Name)
		}
		seenNames[b.Name] = true
		b.Version = strings.TrimSpace(b.Version)
		if b.ID != "" {
			if err := air.ValidateComponentID(b.ID); err != nil {
				return nil, fmt.Errorf("backend %q: id: %w", b.Name, err)
			}
			if other, dup := seenIDs[b.ID]; dup {
				return nil, fmt.Errorf("backend %q: component id %q already used by %q", b.Name, b.ID, other)
			}
			seenIDs[b.ID] = b.Name
		}
		if len(b.Version) > 128 || strings.IndexFunc(b.Version, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
			return nil, fmt.Errorf("backend %q: version must be at most 128 bytes and contain no control characters", b.Name)
		}
		if b.Port <= 0 || b.Port > 65535 {
			return nil, fmt.Errorf("backend %q: port must be 1-65535", b.Name)
		}
		if other, dup := seen[b.Port]; dup {
			return nil, fmt.Errorf("backend %q: port %d already used by %q", b.Name, b.Port, other)
		}
		seen[b.Port] = b.Name
		hasStdio, hasHTTP, hasRemote := len(b.Stdio) > 0, b.HTTP != "", b.Remote != nil
		kinds := 0
		for _, set := range []bool{hasStdio, hasHTTP, hasRemote} {
			if set {
				kinds++
			}
		}
		if kinds != 1 {
			return nil, fmt.Errorf("backend %q: exactly one of stdio, http, or remote must be set", b.Name)
		}
		if b.Resumable && !hasStdio {
			return nil, fmt.Errorf("backend %q: resumable is only valid for stdio backends", b.Name)
		}
		if b.SessionStore != "" && !b.Resumable {
			return nil, fmt.Errorf("backend %q: session_store requires resumable: true", b.Name)
		}
		if len(b.EgressWrapper) > 0 {
			// http/remote backends are not spawned as a child process, so a
			// launcher wrapper is meaningless — refuse rather than silently
			// ignore (matching the resumable/session_store stdio gates above).
			if !hasStdio {
				return nil, fmt.Errorf("backend %q: egress_wrapper is only valid for stdio backends", b.Name)
			}
			for j, part := range b.EgressWrapper {
				if strings.TrimSpace(part) == "" {
					return nil, fmt.Errorf("backend %q: egress_wrapper[%d] must not be empty", b.Name, j)
				}
			}
			// Fail-closed: resolve wrapper[0] at load. A wrapper that cannot be
			// resolved must NOT fall through to an unwrapped spawn — that would
			// run the backend with full egress while the operator believes it
			// is contained. Containment itself is enforced by the OS jailer,
			// not by meshmcp; this only guarantees the configured jailer is
			// present before the backend can start.
			if _, err := exec.LookPath(b.EgressWrapper[0]); err != nil {
				return nil, fmt.Errorf("backend %q: egress_wrapper command %q could not be resolved (fail-closed: a wrapper that cannot start must not run the backend unwrapped): %w", b.Name, b.EgressWrapper[0], err)
			}
		}
		if b.Policy != nil {
			if err := b.Policy.Validate(); err != nil {
				return nil, fmt.Errorf("backend %q: policy: %w", b.Name, err)
			}
			// A group:<name> peer must reference a defined group (F17).
			for ri, r := range b.Policy.Rules {
				for _, p := range r.Peers {
					if g, ok := strings.CutPrefix(p, "group:"); ok {
						if _, defined := cfg.Groups[g]; !defined {
							return nil, fmt.Errorf("backend %q rule #%d: peer group %q is not defined in the top-level groups map", b.Name, ri+1, g)
						}
					}
				}
			}
		}
		switch b.SessionStoreMode {
		case "", "handshake", "full", "backend":
		default:
			return nil, fmt.Errorf("backend %q: session_store_mode %q is not one of handshake|full|backend", b.Name, b.SessionStoreMode)
		}
		switch b.SessionFailover {
		case "", "off", "standby":
		default:
			return nil, fmt.Errorf("backend %q: session_failover %q is not one of standby|off", b.Name, b.SessionFailover)
		}
		if b.SessionFailover == "standby" && (!b.Resumable || b.SessionStore == "") {
			return nil, fmt.Errorf("backend %q: session_failover: standby requires resumable: true and a session_store (the sweep adopts sessions from the shared store)", b.Name)
		}
		if b.SessionFailover == "standby" && b.SessionStore != "" && !isPostgresDSN(b.SessionStore) {
			// The file store's cross-process lock steals stale locks from
			// paused-not-dead holders, which can regress the lease generation
			// the sweep's adoption committed — the split-brain the sweep must
			// never create. Only a store with genuine atomic CAS may back the
			// autonomous sweep; reattach-driven failover keeps working on the
			// file store.
			return nil, fmt.Errorf("backend %q: session_failover: standby requires a PostgreSQL session_store (a file-based store's lock cannot fence a paused gateway; got %q)", b.Name, b.SessionStore)
		}
		if b.SessionSweepSeconds != 0 {
			if b.SessionFailover != "standby" {
				return nil, fmt.Errorf("backend %q: session_sweep_seconds requires session_failover: standby", b.Name)
			}
			if b.SessionSweepSeconds < 5 {
				return nil, fmt.Errorf("backend %q: session_sweep_seconds must be at least 5 (got %d)", b.Name, b.SessionSweepSeconds)
			}
		}
		if b.MovePort != 0 {
			if b.MovePort < 0 || b.MovePort > 65535 {
				return nil, fmt.Errorf("backend %q: move_port must be 1-65535", b.Name)
			}
			if !b.Resumable || b.SessionStore == "" {
				return nil, fmt.Errorf("backend %q: move_port requires resumable: true and a session_store (a live-session move needs the CAS lease store)", b.Name)
			}
			if b.SessionStoreMode == "full" {
				return nil, fmt.Errorf("backend %q: move_port supports only session_store_mode handshake or backend (full re-executes the input log; a move cannot safely reconstruct it)", b.Name)
			}
			if strings.TrimSpace(b.MoveGrantStore) == "" {
				return nil, fmt.Errorf("backend %q: move_port requires move_grant_store (the single-use destination authorization the commit consumes; deny-by-default)", b.Name)
			}
			if other, dup := seen[b.MovePort]; dup {
				return nil, fmt.Errorf("backend %q: move_port %d already used by %q", b.Name, b.MovePort, other)
			}
			seen[b.MovePort] = b.Name
		} else if strings.TrimSpace(b.MoveGrantStore) != "" {
			return nil, fmt.Errorf("backend %q: move_grant_store requires move_port (the move-control listener that consumes the grant)", b.Name)
		}
		if len(b.DLP) > 0 {
			if !hasStdio || b.Policy == nil {
				return nil, fmt.Errorf("backend %q: dlp requires a stdio backend with a policy", b.Name)
			}
			if _, err := policy.NewPatternDLP(b.DLP); err != nil {
				return nil, fmt.Errorf("backend %q: %w", b.Name, err)
			}
		}
		if b.ShadowPolicy != nil {
			if !hasStdio || b.Policy == nil {
				return nil, fmt.Errorf("backend %q: shadow_policy requires a stdio backend with a policy", b.Name)
			}
			if err := b.ShadowPolicy.Validate(); err != nil {
				return nil, fmt.Errorf("backend %q: shadow_policy: %w", b.Name, err)
			}
		}
		if b.CosignStore != "" && b.Policy == nil {
			return nil, fmt.Errorf("backend %q: cosign_store requires a policy", b.Name)
		}
		if b.ApprovalSigningKey != "" && b.CosignStore == "" {
			return nil, fmt.Errorf("backend %q: approval_signing_key requires cosign_store (the shared approval directory)", b.Name)
		}
		if b.AuditRotateBytes < 0 {
			return nil, fmt.Errorf("backend %q: audit_rotate_bytes must be >= 0", b.Name)
		}
		if b.AuditRotateBytes > 0 && b.AuditLog == "" {
			return nil, fmt.Errorf("backend %q: audit_rotate_bytes requires audit_log (the stderr fallback cannot rotate)", b.Name)
		}
		if b.AuditCheckpoints != "" && b.AuditSigningKey == "" {
			return nil, fmt.Errorf("backend %q: audit_checkpoints requires audit_signing_key", b.Name)
		}
		if b.AuditCheckpoints != "" && b.Policy == nil {
			return nil, fmt.Errorf("backend %q: audit_checkpoints requires a policy (nothing to audit otherwise)", b.Name)
		}
		if (b.AuditAnchor != "" || b.AuditAnchorURL != "") && b.AuditCheckpoints == "" {
			return nil, fmt.Errorf("backend %q: audit_anchor/audit_anchor_url require audit_checkpoints (anchoring witnesses signed checkpoints)", b.Name)
		}
		if b.AuditAnchorURL != "" {
			u, err := url.Parse(b.AuditAnchorURL)
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
				return nil, fmt.Errorf("backend %q: invalid audit_anchor_url %q (want http(s)://host[:port]/v1/anchor)", b.Name, b.AuditAnchorURL)
			}
		}
		if b.Capabilities != nil {
			if len(b.Capabilities.TrustedPublicKeys) == 0 {
				return nil, fmt.Errorf("backend %q: capabilities need at least one trusted_public_keys entry", b.Name)
			}
			for _, k := range b.Capabilities.TrustedPublicKeys {
				raw, err := hex.DecodeString(k)
				if err != nil || len(raw) != ed25519.PublicKeySize {
					return nil, fmt.Errorf("backend %q: capabilities trusted_public_keys entry %q is not a %d-byte hex Ed25519 key", b.Name, k, ed25519.PublicKeySize)
				}
			}
			// required:false only makes sense against a deny-by-default policy: a
			// capability can only upgrade a policy-default deny, so a default-allow
			// policy would make it a silent no-op.
			if !b.Capabilities.Required && (b.Policy == nil || b.Policy.DefaultAllow) {
				return nil, fmt.Errorf("backend %q: capabilities with required:false need a deny-by-default policy (a capability only upgrades a policy-default call)", b.Name)
			}
		}
		if b.RouterDelegation != nil {
			// v1 scope: stdio only (the HTTP enforcer has no body-rewrite strip
			// yet) — reject rather than silently not enforce.
			if !hasStdio {
				return nil, fmt.Errorf("backend %q: router_delegation is only valid for stdio backends (HTTP parity is a follow-up)", b.Name)
			}
			// The delegated decision is the intersection of caller AND router
			// under this backend's OWN policy — without one there is nothing to
			// intersect and no call could ever be allowed.
			if b.Policy == nil {
				return nil, fmt.Errorf("backend %q: router_delegation requires a policy (the upstream authorizes caller ∩ router under its own rules)", b.Name)
			}
			if len(b.RouterDelegation.TrustedPublicKeys) == 0 {
				return nil, fmt.Errorf("backend %q: router_delegation needs at least one trusted_public_keys entry (an empty pin never verifies)", b.Name)
			}
			for _, k := range b.RouterDelegation.TrustedPublicKeys {
				raw, err := hex.DecodeString(k)
				if err != nil || len(raw) != ed25519.PublicKeySize {
					return nil, fmt.Errorf("backend %q: router_delegation trusted_public_keys entry %q is not a %d-byte hex Ed25519 key", b.Name, k, ed25519.PublicKeySize)
				}
			}
		}
		if b.Secrets != nil {
			if b.Policy == nil {
				return nil, fmt.Errorf("backend %q: secrets requires a policy (injection happens at the enforcement point)", b.Name)
			}
			if b.Secrets.File == "" && b.Secrets.EnvPrefix == "" {
				return nil, fmt.Errorf("backend %q: secrets needs a file or env_prefix store", b.Name)
			}
			// A grant with no peers would inject a credential for ANY mesh peer.
			// Require an explicit identity list so a secret is never granted to
			// everyone by omission.
			for gi, g := range b.Secrets.Grants {
				if len(g.Peers) == 0 {
					return nil, fmt.Errorf("backend %q: secret grant #%d must list peers (an empty peers list would grant the secret to every mesh peer)", b.Name, gi+1)
				}
			}
		}
		if hasHTTP {
			u, err := url.Parse(b.HTTP)
			if err != nil || u.Scheme == "" || u.Host == "" {
				return nil, fmt.Errorf("backend %q: invalid http url %q", b.Name, b.HTTP)
			}
			b.httpURL = u
		}
		if hasRemote {
			if b.Remote.Endpoint == "" {
				return nil, fmt.Errorf("backend %q: remote endpoint is required", b.Name)
			}
			u, err := url.Parse(b.Remote.Endpoint)
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
				return nil, fmt.Errorf("backend %q: invalid remote endpoint url %q", b.Name, b.Remote.Endpoint)
			}
			b.remoteURL = u
			if b.Remote.ClientID == "" {
				return nil, fmt.Errorf("backend %q: remote client_id is required", b.Name)
			}
			if b.Remote.Secrets == nil || (b.Remote.Secrets.File == "" && b.Remote.Secrets.EnvPrefix == "") {
				return nil, fmt.Errorf("backend %q: remote secrets (file or env_prefix) are required — they name the dpop key file and OAuth credentials", b.Name)
			}
			if b.Remote.DPoPKeyName == "" {
				b.Remote.DPoPKeyName = "dpop_private_key"
			}
			if b.Remote.ClientSecretName == "" {
				b.Remote.ClientSecretName = "oauth_client_secret"
			}
			if b.Remote.RefreshTokenName == "" {
				b.Remote.RefreshTokenName = "oauth_refresh_token"
			}
		}
	}
	if cfg.Control != nil && cfg.Control.Port != 0 {
		if cfg.Control.Port < 0 || cfg.Control.Port > 65535 {
			return nil, fmt.Errorf("control: port must be 1-65535")
		}
		if other, dup := seen[cfg.Control.Port]; dup {
			return nil, fmt.Errorf("control: port %d already used by backend %q", cfg.Control.Port, other)
		}
		// The Air control endpoint lists and steers live sessions — privileged.
		// Refuse to expose it without an explicit allow list (default-deny) rather
		// than silently admitting any mesh peer. A configured operator counts as an
		// allowed identity, so an operators-only gateway is valid. Per-backend ACLs
		// add depth, but the global endpoint must not be open by omission.
		if len(cfg.Control.Allow) == 0 && len(cfg.Operators) == 0 {
			return nil, fmt.Errorf("control: the Air control endpoint is enabled but has no allow list — set control.allow (or operators) to the WireGuard keys/FQDNs permitted to list/steer (default-deny)")
		}
	}
	if err := validateOperators(cfg.Operators); err != nil {
		return nil, err
	}
	// The SSO attestation surface (/v1/sso/attest) binds a verified token to the
	// caller's WireGuard TRANSPORT key, which only exists on a mesh connection —
	// so it mounts on the mesh control listener. Require that listener to be
	// enabled when OIDC is configured (fail closed at load, not with a silently
	// missing endpoint at runtime).
	if cfg.OIDC != nil && (cfg.Control == nil || cfg.Control.Port <= 0) {
		return nil, fmt.Errorf("config %s: oidc requires control.port (the /v1/sso/attest binding surface mounts on the mesh control listener)", path)
	}
	return &cfg, nil
}

// validateOperators rejects an unusable operator entry: each must carry at least
// an identity (pubkey or fqdn), bounded and control-character free, so a
// malformed operator can never widen the control/pairing surface by accident.
func validateOperators(ops []OperatorConfig) error {
	seen := map[string]bool{}
	for i, o := range ops {
		if strings.TrimSpace(o.PubKey) == "" && strings.TrimSpace(o.FQDN) == "" {
			return fmt.Errorf("operator #%d: needs a pubkey or fqdn", i+1)
		}
		if len(o.PubKey) > 512 || len(o.FQDN) > 512 || hasCtrl(o.PubKey) || hasCtrl(o.FQDN) {
			return fmt.Errorf("operator #%d: pubkey/fqdn must be at most 512 bytes and contain no control characters", i+1)
		}
		if o.PubKey != "" {
			if seen[o.PubKey] {
				return fmt.Errorf("operator #%d: pubkey %q is listed more than once", i+1, o.PubKey)
			}
			seen[o.PubKey] = true
		}
	}
	return nil
}

// hasCtrl reports whether s contains an ASCII control character (rejected in
// identities that are later matched, logged, and rendered).
func hasCtrl(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

// options converts the mesh section into meshOptions, resolving the
// setup key from the environment when not given literally.
func (m MeshConfig) options() *meshOptions {
	key := m.SetupKey
	if key == "" {
		env := m.SetupKeyEnv
		if env == "" {
			env = "NB_SETUP_KEY"
		}
		key = os.Getenv(env)
	}
	mgmt := m.ManagementURL
	if mgmt == "" {
		mgmt = os.Getenv("NB_MANAGEMENT_URL")
	}
	logLevel := m.LogLevel
	if logLevel == "" {
		logLevel = "warn"
	}
	return &meshOptions{
		DeviceName:    m.DeviceName,
		ManagementURL: mgmt,
		SetupKey:      key,
		ConfigPath:    m.ConfigPath,
		LogLevel:      logLevel,
		DNSLabels:     m.DNSLabels,
		BlockInbound:  false, // the gateway must accept inbound mesh connections
		WireguardPort: m.WireguardPort,
	}
}
