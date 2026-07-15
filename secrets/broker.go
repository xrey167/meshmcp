package secrets

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"strings"

	"meshmcp/policy"
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
func (b *Broker) Resolve(caller policy.Caller, tool string, line []byte, labels map[string]bool) (out []byte, ok bool, reason string) {
	if !bytes.Contains(line, refMarker) {
		return line, true, ""
	}

	// Collect the distinct referenced names.
	names := map[string]bool{}
	for _, m := range refRe.FindAllSubmatch(line, -1) {
		names[string(m[1])] = true
	}

	// Authorize and resolve every name up front, so a denial blocks the whole
	// call before any value is substituted.
	values := make(map[string]string, len(names))
	for name := range names {
		allowed, why := b.authorize(caller, name, tool, labels)
		if !allowed {
			b.record(caller, tool, name, "deny", why)
			return nil, false, why
		}
		v, found := b.store.Get(name)
		if !found {
			reason = fmt.Sprintf("secret %q is not available in the store", name)
			b.record(caller, tool, name, "deny", "unavailable")
			return nil, false, reason
		}
		values[name] = v
	}

	// Substitute inside the (JSON) line, JSON-escaping each value so a value
	// containing quotes/backslashes/newlines cannot break the message or
	// escape its string context.
	out = refRe.ReplaceAllFunc(line, func(m []byte) []byte {
		name := string(refRe.FindSubmatch(m)[1])
		return []byte(jsonInner(values[name]))
	})
	for name := range names {
		b.record(caller, tool, name, "allow", "injected")
	}
	return out, true, ""
}

// authorize reports whether caller may inject secret into tool given the
// session labels. It distinguishes "no grant" from "blocked by label" so the
// denial reason is actionable.
func (b *Broker) authorize(caller policy.Caller, secret, tool string, labels map[string]bool) (bool, string) {
	matchedButBlocked := ""
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
		if blocked := firstPresent(g.BlockLabels, labels); blocked != "" {
			matchedButBlocked = fmt.Sprintf("secret %q blocked: session carries label %q", secret, blocked)
			continue
		}
		return true, ""
	}
	if matchedButBlocked != "" {
		return false, matchedButBlocked
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
