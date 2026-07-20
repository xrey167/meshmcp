package secrets

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"strconv"
	"strings"

	"github.com/xrey167/meshmcp/policy"
)

// refRe matches a secret reference: {{secret:NAME}} (optional surrounding
// whitespace). NAME is [A-Za-z0-9_.-].
var refRe = regexp.MustCompile(`\{\{\s*secret:([A-Za-z0-9_.\-]+)\s*\}\}`)

// refMarker is a cheap pre-check to skip lines with no references.
var refMarker = []byte("{{secret:")

// Grant permits a set of identities to inject a set of secrets, optionally
// restricted to certain tools and refused when the session carries a label.
type Grant struct {
	// Peers that may use the secrets: "pubkey:<key>" or an FQDN glob. Empty
	// matches any mesh peer (the mesh is already the outer boundary).
	Peers []string `yaml:"peers"`
	// Secrets is the set of secret-name globs this grant covers (required —
	// a grant with no secrets grants nothing).
	Secrets []string `yaml:"secrets"`
	// Tools restricts injection to these tool-name globs (empty = any tool).
	Tools []string `yaml:"tools"`
	// Locations restricts injection to these argument paths (dotted globs within
	// params.arguments, e.g. "headers.Authorization" or "items.*.token"). Empty =
	// any location within arguments. A secret reference at a non-matching
	// location is denied — binding a grant to the declared argument location.
	Locations []string `yaml:"locations"`
	// BlockLabels refuse injection when the session carries any of these
	// data-flow labels — e.g. ["tainted"] so untrusted content can never
	// trigger a credential use.
	BlockLabels []string `yaml:"block_labels"`
}

// Broker resolves secret references in outbound tool calls.
type Broker struct {
	store  Store
	grants []Grant
	audit  *policy.AuditLog
}

// New builds a broker. audit (optional) receives one hash-chained record per
// secret use — the secret NAME and caller, never the value.
func New(store Store, grants []Grant, audit *policy.AuditLog) *Broker {
	return &Broker{store: store, grants: grants, audit: audit}
}

// Resolve implements policy.SecretResolver. Given an outbound tools/call line,
// it substitutes every {{secret:NAME}} reference with the resolved value —
// returning ok=false (and a reason for the JSON-RPC denial) if any referenced
// secret is not granted to the caller, is blocked by the session's labels, or
// is unavailable. A line with no references passes through untouched.
func (b *Broker) Resolve(caller policy.Caller, tool string, line []byte, labels map[string]bool) (out []byte, injected [][]byte, ok bool, reason string) {
	if !bytes.Contains(line, refMarker) {
		return line, nil, true, ""
	}
	// Parse the request and locate params.arguments — the ONLY place a secret is
	// injected. A marker anywhere else (method, id, params.name, _meta) is left
	// as a literal and never resolved, so a caller cannot smuggle a secret out of
	// a non-argument field.
	var msg map[string]json.RawMessage
	if json.Unmarshal(line, &msg) != nil {
		return line, nil, true, "" // not our shape; nothing to inject
	}
	var params map[string]json.RawMessage
	if raw, has := msg["params"]; !has || json.Unmarshal(raw, &params) != nil {
		return line, nil, true, ""
	}
	argsRaw, has := params["arguments"]
	if !has {
		return line, nil, true, "" // no argument surface
	}
	var args any
	if json.Unmarshal(argsRaw, &args) != nil {
		return line, nil, true, ""
	}

	// Pass 1: collect marker occurrences (secret name + dotted path) within
	// arguments only.
	var sites []markerSite
	collectMarkers(args, "", &sites)
	if len(sites) == 0 {
		return line, nil, true, "" // markers only outside arguments: leave literal
	}

	// Authorize + resolve every referenced secret up front (binding to the
	// argument location), so a denial blocks the whole call before substitution.
	values := map[string]string{}
	for _, s := range sites {
		allowed, why := b.authorize(caller, s.name, tool, s.path, labels)
		if !allowed {
			b.record(caller, tool, s.name, "deny", why)
			return nil, nil, false, why
		}
		if _, done := values[s.name]; done {
			continue
		}
		v, found := b.store.Get(s.name)
		if !found {
			reason = fmt.Sprintf("secret %q is not available in the store", s.name)
			b.record(caller, tool, s.name, "deny", "unavailable")
			return nil, nil, false, reason
		}
		values[s.name] = v
	}

	// Pass 2: substitute markers inside arguments only. json.Marshal re-escapes
	// each value, so a value with quotes/backslashes/newlines can never break the
	// message or escape its string context.
	newArgs := replaceMarkers(args, values)
	nb, err := json.Marshal(newArgs)
	if err != nil {
		return nil, nil, false, "secret injection failed to re-encode arguments"
	}
	params["arguments"] = nb
	pb, _ := json.Marshal(params)
	msg["params"] = pb
	ob, _ := json.Marshal(msg)
	if len(line) > 0 && line[len(line)-1] == '\n' {
		ob = append(ob, '\n') // preserve line framing for the backend
	}

	// Report the injected values (raw AND JSON-escaped form) so the filter can
	// scrub either form a backend might echo back. In-memory redaction only —
	// never audited, traced, or logged.
	seen := map[string]bool{}
	for _, s := range sites {
		if seen[s.name] {
			continue
		}
		seen[s.name] = true
		raw := values[s.name]
		injected = append(injected, []byte(raw))
		if esc := jsonInner(raw); esc != raw {
			injected = append(injected, []byte(esc))
		}
		b.record(caller, tool, s.name, "allow", "injected")
	}
	return ob, injected, true, ""
}

// markerSite is one secret-reference occurrence within arguments.
type markerSite struct {
	name string // secret name
	path string // dotted path within arguments (e.g. "headers.Authorization")
}

func joinPath(base, seg string) string {
	if base == "" {
		return seg
	}
	return base + "." + seg
}

// collectMarkers walks a decoded arguments value and records every secret
// reference found in a STRING value, with its dotted path.
func collectMarkers(v any, path string, out *[]markerSite) {
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			collectMarkers(val, joinPath(path, k), out)
		}
	case []any:
		for i, val := range t {
			collectMarkers(val, joinPath(path, strconv.Itoa(i)), out)
		}
	case string:
		for _, m := range refRe.FindAllStringSubmatch(t, -1) {
			*out = append(*out, markerSite{name: m[1], path: path})
		}
	}
}

// replaceMarkers returns a copy of v with every secret marker in a string value
// replaced by its resolved value.
func replaceMarkers(v any, values map[string]string) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			out[k] = replaceMarkers(val, values)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, val := range t {
			out[i] = replaceMarkers(val, values)
		}
		return out
	case string:
		return refRe.ReplaceAllStringFunc(t, func(m string) string {
			name := refRe.FindStringSubmatch(m)[1]
			return values[name]
		})
	default:
		return v
	}
}

// authorize reports whether caller may inject secret into tool given the
// session labels. It distinguishes "no grant" from "blocked by label" so the
// denial reason is actionable.
func (b *Broker) authorize(caller policy.Caller, secret, tool, path string, labels map[string]bool) (bool, string) {
	matchedButBlocked := ""
	matchedButLocation := false
	for _, g := range b.grants {
		if !matchPeer(g.Peers, caller.Peer, caller.PeerKey) {
			continue
		}
		if !matchGlob(g.Secrets, secret) {
			continue
		}
		if len(g.Tools) > 0 && !matchGlob(g.Tools, tool) {
			continue
		}
		if len(g.Locations) > 0 && !matchGlob(g.Locations, path) {
			matchedButLocation = true
			continue // this grant restricts locations and this one doesn't match
		}
		if blocked := firstPresent(g.BlockLabels, labels); blocked != "" {
			matchedButBlocked = fmt.Sprintf("secret %q blocked: session carries label %q", secret, blocked)
			continue
		}
		return true, ""
	}
	if matchedButBlocked != "" {
		return false, matchedButBlocked
	}
	if matchedButLocation {
		return false, fmt.Sprintf("secret %q not permitted at argument location %q", secret, path)
	}
	return false, fmt.Sprintf("secret %q not granted to %s", secret, callerName(caller))
}

func (b *Broker) record(caller policy.Caller, tool, secret, decision, reason string) {
	if b.audit == nil {
		return
	}
	b.audit.Append(policy.AuditRecord{
		Backend:  caller.Backend,
		Peer:     caller.Peer,
		PeerKey:  caller.PeerKey,
		PeerAddr: caller.PeerAddr,
		Method:   "secrets/inject",
		Tool:     tool,
		Decision: decision,
		Reason:   secret + ": " + reason, // the NAME, never the value
	})
}

// jsonInner returns the JSON-escaped body of v without the surrounding quotes,
// so it can be spliced into an existing JSON string value.
func jsonInner(v string) string {
	b, _ := json.Marshal(v)
	return string(b[1 : len(b)-1])
}

func callerName(c policy.Caller) string {
	if c.Peer != "" {
		return c.Peer
	}
	if c.PeerKey != "" {
		return "pubkey:" + c.PeerKey
	}
	return "unknown peer"
}

func matchPeer(patterns []string, fqdn, key string) bool {
	if len(patterns) == 0 {
		return true
	}
	for _, p := range patterns {
		if k, ok := strings.CutPrefix(p, "pubkey:"); ok {
			if k == key && key != "" {
				return true
			}
			continue
		}
		if p == "*" || p == fqdn {
			return true
		}
		if ok, _ := path.Match(p, fqdn); ok {
			return true
		}
	}
	return false
}

func matchGlob(patterns []string, v string) bool {
	for _, p := range patterns {
		if p == "*" || p == v {
			return true
		}
		if ok, _ := path.Match(p, v); ok {
			return true
		}
	}
	return false
}

func firstPresent(want []string, have map[string]bool) string {
	for _, l := range want {
		if have[l] {
			return l
		}
	}
	return ""
}
