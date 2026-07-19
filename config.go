package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"

	"gopkg.in/yaml.v3"

	"meshmcp/policy"
	"meshmcp/secrets"
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
	// shared by every policy-enabled backend — one hash chain for the whole
	// gateway, which is what a unified live view (dash / room) reads. When
	// empty, each backend uses its own audit_log.
	AuditLog string         `yaml:"audit_log"`
	Trace    *TraceConfig   `yaml:"trace"`
	Registry string         `yaml:"registry"` // dir: register backends for router discovery
	Control  *ControlConfig `yaml:"control"`  // optional: Air session-control endpoint
	Hooks    *HooksConfig   `yaml:"hooks"`    // publish policy decisions to the event bus and/or a webhook
	Backends []*Backend     `yaml:"backends"`
}

// ControlConfig enables the Air session-control endpoint: a mesh HTTP surface
// (GET /v1/sessions, POST /v1/steer) that lists and steers this gateway's live
// resumable sessions. It listens only on the mesh, resolves the caller's
// WireGuard identity, gates on Allow, and audits every steer.
type ControlConfig struct {
	Port  int      `yaml:"port"`  // mesh port to serve the control endpoint on
	Allow []string `yaml:"allow"` // identities permitted to list/steer (FQDN globs or pubkey:<key>); empty = any mesh peer
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
	Port int    `yaml:"port"`
	// Stdio spawns this command per inbound connection and pipes the
	// connection to its stdin/stdout (raw JSON-RPC transport).
	Stdio []string `yaml:"stdio"`
	// HTTP reverse-proxies inbound requests to this local base URL
	// (for MCP servers speaking Streamable HTTP).
	HTTP string `yaml:"http"`
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
	// resume a session after a failover. Only valid for resumable stdio
	// backends; migration replays the handshake against a fresh backend, so
	// the backend must be stateless per request.
	SessionStore string `yaml:"session_store"`
	// SessionStoreMode selects how a resumed backend is reconstructed:
	// "handshake" (default, stateless backends), "full" (replay the whole
	// client->backend log, idempotent backends), or "backend" (the backend
	// restores its own state from MESHMCP_SESSION_ID).
	SessionStoreMode string `yaml:"session_store_mode"`
	// Policy authorizes individual tools/call requests by caller identity.
	// Only valid for stdio backends (the gateway parses their JSON-RPC).
	Policy *policy.Policy `yaml:"policy"`
	// AuditLog is a file path for JSONL tool-call audit records. Empty
	// sends audit records to stderr. The log is a tamper-evident hash chain
	// (verify it with "meshmcp audit verify").
	AuditLog string `yaml:"audit_log"`
	// AuditCheckpoints is a file for signed Merkle checkpoints over the audit
	// log, making it non-repudiable and externally verifiable. Requires a
	// signing key (audit_signing_key). Verify with
	// "meshmcp audit verify <log> --checkpoints <f> --pubkey <hex>".
	AuditCheckpoints string `yaml:"audit_checkpoints"`
	// AuditSigningKey is the gateway Ed25519 key file (created by
	// "meshmcp audit keygen"). If it does not exist it is generated on start.
	AuditSigningKey string `yaml:"audit_signing_key"`
	// AuditCheckpointEvery is how many records per checkpoint (default 128).
	AuditCheckpointEvery int `yaml:"audit_checkpoint_every"`
	// AuditAnchor is an append-only file where each checkpoint is also written
	// as an external witness (the transparency-log seam).
	AuditAnchor string `yaml:"audit_anchor"`
	// CosignStore is a shared directory holding human co-sign approvals for
	// rules with require_cosign. A human identity grants approvals with
	// "meshmcp approve". Only meaningful with a policy.
	CosignStore string `yaml:"cosign_store"`
	// CosignTTLSeconds bounds how long a co-sign approval stays valid
	// (0 = no expiry).
	CosignTTLSeconds int `yaml:"cosign_ttl_seconds"`
	// Secrets configures the credential broker: agents reference secrets by
	// name ({{secret:NAME}}) and the gateway injects the value by identity,
	// so the agent never holds the raw credential. Only valid for stdio
	// backends with a policy.
	Secrets *SecretsConfig `yaml:"secrets"`
	// Capabilities pins authority keys for signed capability grants. A valid
	// capability upgrades a policy-default-deny call to allow; required:true
	// makes the backend a capability-only surface. Only valid for stdio.
	Capabilities *CapabilitiesConfig `yaml:"capabilities"`

	httpURL *url.URL
}

// CapabilitiesConfig configures signed-capability admission for a backend.
type CapabilitiesConfig struct {
	// Required makes every tools/call present a valid capability.
	Required bool `yaml:"required"`
	// TrustedPublicKeys are the hex Ed25519 authority keys the gateway pins;
	// a token never supplies its own trust root.
	TrustedPublicKeys []string `yaml:"trusted_public_keys"`
}

func (b *Backend) kind() string {
	if b.HTTP != "" {
		return "http -> " + b.HTTP
	}
	if b.Resumable {
		return fmt.Sprintf("stdio(resumable) -> %v", b.Stdio)
	}
	return fmt.Sprintf("stdio -> %v", b.Stdio)
}

func loadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}

	if len(cfg.Backends) == 0 {
		return nil, fmt.Errorf("config %s: no backends defined", path)
	}
	seen := map[int]string{}
	for i, b := range cfg.Backends {
		if b.Name == "" {
			return nil, fmt.Errorf("backend #%d: name is required", i+1)
		}
		if b.Port <= 0 || b.Port > 65535 {
			return nil, fmt.Errorf("backend %q: port must be 1-65535", b.Name)
		}
		if other, dup := seen[b.Port]; dup {
			return nil, fmt.Errorf("backend %q: port %d already used by %q", b.Name, b.Port, other)
		}
		seen[b.Port] = b.Name
		hasStdio, hasHTTP := len(b.Stdio) > 0, b.HTTP != ""
		if hasStdio == hasHTTP {
			return nil, fmt.Errorf("backend %q: exactly one of stdio or http must be set", b.Name)
		}
		if b.Resumable && !hasStdio {
			return nil, fmt.Errorf("backend %q: resumable is only valid for stdio backends", b.Name)
		}
		if b.SessionStore != "" && !b.Resumable {
			return nil, fmt.Errorf("backend %q: session_store requires resumable: true", b.Name)
		}
		if b.Policy != nil && !hasStdio {
			return nil, fmt.Errorf("backend %q: policy is only valid for stdio backends", b.Name)
		}
		if b.CosignStore != "" && b.Policy == nil {
			return nil, fmt.Errorf("backend %q: cosign_store requires a policy", b.Name)
		}
		if b.AuditCheckpoints != "" && b.AuditSigningKey == "" {
			return nil, fmt.Errorf("backend %q: audit_checkpoints requires audit_signing_key", b.Name)
		}
		if b.AuditCheckpoints != "" && b.Policy == nil {
			return nil, fmt.Errorf("backend %q: audit_checkpoints requires a policy (nothing to audit otherwise)", b.Name)
		}
		if b.Capabilities != nil {
			if !hasStdio {
				return nil, fmt.Errorf("backend %q: capabilities are only valid for stdio backends", b.Name)
			}
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
		if b.Secrets != nil {
			if !hasStdio {
				return nil, fmt.Errorf("backend %q: secrets injection is only valid for stdio backends", b.Name)
			}
			if b.Policy == nil {
				return nil, fmt.Errorf("backend %q: secrets requires a policy (injection happens at the enforcement point)", b.Name)
			}
			if b.Secrets.File == "" && b.Secrets.EnvPrefix == "" {
				return nil, fmt.Errorf("backend %q: secrets needs a file or env_prefix store", b.Name)
			}
		}
		if hasHTTP {
			u, err := url.Parse(b.HTTP)
			if err != nil || u.Scheme == "" || u.Host == "" {
				return nil, fmt.Errorf("backend %q: invalid http url %q", b.Name, b.HTTP)
			}
			b.httpURL = u
		}
	}
	if cfg.Control != nil && cfg.Control.Port != 0 {
		if cfg.Control.Port < 0 || cfg.Control.Port > 65535 {
			return nil, fmt.Errorf("control: port must be 1-65535")
		}
		if other, dup := seen[cfg.Control.Port]; dup {
			return nil, fmt.Errorf("control: port %d already used by backend %q", cfg.Control.Port, other)
		}
	}
	return &cfg, nil
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
