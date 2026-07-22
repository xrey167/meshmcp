package policy

import (
	"encoding/base64"
	"fmt"
	"regexp"
)

// SpiffeLabel is a derived, additive identity label
// (spiffe://<trust-domain>/peer/<key>) surfaced in audit records and
// federation mappings. It is a distinct type — never a bare string — so that
// a future decision function accepting it where a Caller/PeerKey-typed value
// is expected is a compile error, not a silent grep-miss: the WireGuard
// public key remains the only thing enforcement decisions key on.
type SpiffeLabel string

// trustDomainPattern matches a syntactically valid SPIFFE trust domain:
// lowercase, dot-separated DNS labels, no scheme, no path.
var trustDomainPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)

// ValidTrustDomain reports whether s is a syntactically valid SPIFFE trust
// domain (lowercase DNS-label shape). Used at config load for
// Config.TrustDomain and federation.Mapping.TrustDomain.
func ValidTrustDomain(s string) bool {
	if s == "" || len(s) > 255 {
		return false
	}
	return trustDomainPattern.MatchString(s)
}

// SpiffeID derives the spiffe://<trust-domain>/peer/<key> label for a mesh
// peer. Plain return, no error, matching "label, not control": a malformed
// key or an empty trustDomain returns SpiffeLabel(""), the same as an empty
// peerKeyBase64 (no stable key to label, e.g. an FQDN-glob-mapped federation
// peer).
//
// Encoding decision: peerKeyBase64 is standard-padded base64 (the form
// client.IdentityForIP actually returns, per acl.go). It is decoded to raw
// bytes and re-encoded with base64.RawURLEncoding, which is legal in a SPIFFE
// path segment ([a-zA-Z0-9._-]+) — the standard alphabet's '+'/'/' are not.
// Only the padded standard form is accepted on input; unpadded/URL-safe
// variants are rejected rather than silently decoded, so the same key never
// round-trips to two different-looking labels depending on input form.
func SpiffeID(trustDomain string, peerKeyBase64 string) SpiffeLabel {
	if trustDomain == "" || peerKeyBase64 == "" {
		return ""
	}
	raw, err := base64.StdEncoding.DecodeString(peerKeyBase64)
	if err != nil {
		return ""
	}
	encoded := base64.RawURLEncoding.EncodeToString(raw)
	return SpiffeLabel(fmt.Sprintf("spiffe://%s/peer/%s", trustDomain, encoded))
}
