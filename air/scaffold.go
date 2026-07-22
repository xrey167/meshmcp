package air

import (
	"fmt"
	"strings"
)

// This file is the mesh-independent core of `air init` / `air up`: deriving a
// safe device identity, parsing a --backend spec into a transport, and shaping
// the bootstrap summary. It touches no mesh, no filesystem, and no policy
// engine, so every rule here is provable in a unit test. The CLI wiring that
// turns these into a real *Config, writes it, and joins the mesh lives in the
// main package.

// meshDomain is the default NetBird DNS domain a peer's FQDN lives under. It is
// only used to render a human-facing "pair address" hint before the gateway has
// actually joined and learned its real FQDN; the live value from the mesh
// status always wins once known.
const meshDomain = "netbird.cloud"

// DeviceNameFromHost derives a stable, mesh-safe device name from a hostname,
// matching the gateway's own default (meshmcp-<lowercased-host>). An empty or
// all-invalid hostname falls back to a fixed name so the identity is never
// blank. The result is lowercased and restricted to [a-z0-9-] so it is a valid
// DNS label component.
func DeviceNameFromHost(hostname string) string {
	h := sanitizeLabel(strings.ToLower(strings.TrimSpace(hostname)))
	if h == "" {
		return "meshmcp-gateway"
	}
	return "meshmcp-" + h
}

// sanitizeLabel keeps only DNS-label-safe runes, collapsing anything else to a
// single hyphen and trimming leading/trailing hyphens.
func sanitizeLabel(s string) string {
	var b strings.Builder
	prevHyphen := false
	for _, r := range s {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'):
			b.WriteRune(r)
			prevHyphen = false
		default:
			if !prevHyphen {
				b.WriteByte('-')
				prevHyphen = true
			}
		}
	}
	return strings.Trim(b.String(), "-")
}

// BackendSpec is a parsed --backend argument: a name plus exactly one
// transport. A value beginning with http:// or https:// is an HTTP backend;
// anything else is a stdio command split on whitespace.
type BackendSpec struct {
	Name  string
	Stdio []string // set for a stdio backend
	HTTP  string   // set for an http backend
}

// ParseBackendSpec parses "name=stdio command args" or "name=http://addr".
// The name must be non-empty and control-character free; the transport value
// must be non-empty. It performs no network or filesystem access.
func ParseBackendSpec(spec string) (BackendSpec, error) {
	name, value, ok := strings.Cut(spec, "=")
	if !ok {
		return BackendSpec{}, fmt.Errorf("backend %q: want name=stdio-cmd or name=http-addr", spec)
	}
	name = strings.TrimSpace(name)
	value = strings.TrimSpace(value)
	if name == "" {
		return BackendSpec{}, fmt.Errorf("backend %q: name is empty", spec)
	}
	if strings.IndexFunc(name, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
		return BackendSpec{}, fmt.Errorf("backend %q: name has control characters", spec)
	}
	if value == "" {
		return BackendSpec{}, fmt.Errorf("backend %q: transport (stdio command or http addr) is empty", spec)
	}
	if strings.HasPrefix(value, "http://") || strings.HasPrefix(value, "https://") {
		return BackendSpec{Name: name, HTTP: value}, nil
	}
	fields := strings.Fields(value)
	if len(fields) == 0 {
		return BackendSpec{}, fmt.Errorf("backend %q: empty stdio command", spec)
	}
	return BackendSpec{Name: name, Stdio: fields}, nil
}

// DeviceFQDN renders the mesh FQDN a device is expected to have under the
// default NetBird domain: <device>.<meshDomain>. It is a hint derived from the
// device name before the gateway has joined; the live FQDN from mesh status is
// authoritative once known.
func DeviceFQDN(deviceName string) string {
	return deviceName + "." + meshDomain
}

// PairAddress renders the mesh join address a peer would use to pair with this
// gateway's Air control endpoint: <device>.<meshDomain>:<port>. It is a hint
// derived from the device name before the gateway has joined; once the mesh is
// up the gateway's real FQDN is authoritative.
func PairAddress(deviceName string, controlPort int) string {
	return fmt.Sprintf("%s:%d", DeviceFQDN(deviceName), controlPort)
}

// BackendInfo is one backend line in a ScaffoldSummary.
type BackendInfo struct {
	Name      string `json:"name"`
	Port      int    `json:"port"`
	Transport string `json:"transport"` // "stdio" | "http"
}

// ScaffoldSummary is the machine-readable result of `air init` (and the status
// header of `air up`): what was written and the safe defaults chosen. The CLI
// renders it as a human summary or, with --json, marshals it directly.
type ScaffoldSummary struct {
	ConfigPath    string        `json:"config_path"`
	DeviceName    string        `json:"device_name"`
	Backends      []BackendInfo `json:"backends"`
	AuditLog      string        `json:"audit_log"`
	DenyByDefault bool          `json:"deny_by_default"`
	ControlPort   int           `json:"control_port"`
	PairAddress   string        `json:"pair_address"`
	SetupKeyEnv   string        `json:"setup_key_env"`
	SetupKeyFound bool          `json:"setup_key_found"`
	Created       bool          `json:"created"` // true if this run wrote the file
	NextStep      string        `json:"next_step"`
}
