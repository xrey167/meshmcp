package main

import (
	"fmt"
	"net/url"
	"os"

	"gopkg.in/yaml.v3"

	"meshmcp/policy"
)

// Config is the meshmcp serve configuration.
type Config struct {
	Mesh     MeshConfig   `yaml:"mesh"`
	Trace    *TraceConfig `yaml:"trace"`
	Registry string       `yaml:"registry"` // dir: register backends for router discovery
	Backends []*Backend   `yaml:"backends"`
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
	// CosignStore is a shared directory holding human co-sign approvals for
	// rules with require_cosign. A human identity grants approvals with
	// "meshmcp approve". Only meaningful with a policy.
	CosignStore string `yaml:"cosign_store"`
	// CosignTTLSeconds bounds how long a co-sign approval stays valid
	// (0 = no expiry).
	CosignTTLSeconds int `yaml:"cosign_ttl_seconds"`

	httpURL *url.URL
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
		if hasHTTP {
			u, err := url.Parse(b.HTTP)
			if err != nil || u.Scheme == "" || u.Host == "" {
				return nil, fmt.Errorf("backend %q: invalid http url %q", b.Name, b.HTTP)
			}
			b.httpURL = u
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
