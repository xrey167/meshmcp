package policy

import (
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"
)

// SpiffeLabel is a derived, additive identity label
// (spiffe://<trust-domain>/peer/<key>) surfaced in audit records and
// federation mappings. It is a distinct type — never a bare string — so that
// a future decision function accepting it where a Caller/PeerKey-typed value
// is expected is a compile error, not a silent grep-miss: the WireGuard
// public key remains the only thing enforcement decisions key on.
type SpiffeLabel string

// maxSpiffeKeyBase64 bounds the peer-key input SpiffeID will label. A real
// WireGuard public key is exactly 44 bytes of padded standard base64; anything
// far beyond that is not a mesh peer key and must not grow an audit label.
const maxSpiffeKeyBase64 = 128

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
// Inputs are bounded and sanitized here, not just at config load: a trust
// domain that fails ValidTrustDomain (bad shape, control chars, >255 bytes)
// yields "" rather than a malformed URI, and a key longer than
// maxSpiffeKeyBase64 yields "" rather than an unbounded label (a WireGuard
// public key is 44 bytes of padded base64; the cap is generous headroom).
func SpiffeID(trustDomain string, peerKeyBase64 string) SpiffeLabel {
	if trustDomain == "" || peerKeyBase64 == "" {
		return ""
	}
	if !ValidTrustDomain(trustDomain) || len(peerKeyBase64) > maxSpiffeKeyBase64 {
		return ""
	}
	// base64.StdEncoding silently skips \r\n, which would let two spellings of
	// a key round-trip to one label — the exact ambiguity the padded-input-only
	// rule above exists to prevent. Reject them like any other malformation.
	// (Strict() below still ignores CR/LF per its docs, so this check stays.)
	if strings.ContainsAny(peerKeyBase64, "\r\n") {
		return ""
	}
	// Strict() rejects non-zero trailing padding bits (e.g. "AB==" vs "AA=="),
	// closing the last way two key spellings could map to one label.
	raw, err := base64.StdEncoding.Strict().DecodeString(peerKeyBase64)
	if err != nil {
		return ""
	}
	encoded := base64.RawURLEncoding.EncodeToString(raw)
	return SpiffeLabel(fmt.Sprintf("spiffe://%s/peer/%s", trustDomain, encoded))
}
