package policy

import (
	"encoding/base64"
	"regexp"
	"testing"
)

// netbirdShapedKey is a real NetBird/WireGuard-shaped public key: 32 raw
// bytes, standard padded base64 — chosen because it contains both '+' and '/'
// (neither is legal in a SPIFFE path segment), which is exactly the case the
// design doc's re-encoding decision exists to handle.
const netbirdShapedKey = "76SpfHTmmNI0CvRjH/y2ntoe0zdzeACvkl+IKrHlqYA="

var spiffePathSegment = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)

func TestSpiffeID_RoundTripsRealNetBirdKey(t *testing.T) {
	raw, err := base64.StdEncoding.DecodeString(netbirdShapedKey)
	if err != nil {
		t.Fatalf("test fixture key does not decode as standard base64: %v", err)
	}
	if len(raw) != 32 {
		t.Fatalf("test fixture key should decode to 32 bytes, got %d", len(raw))
	}

	id := SpiffeID("meshmcp.example.org", netbirdShapedKey)
	const prefix = "spiffe://meshmcp.example.org/peer/"
	s := string(id)
	if len(s) <= len(prefix) || s[:len(prefix)] != prefix {
		t.Fatalf("expected id to start with %q, got %q", prefix, s)
	}
	segment := s[len(prefix):]
	if !spiffePathSegment.MatchString(segment) {
		t.Fatalf("peer path segment %q is not SPIFFE-legal ([a-zA-Z0-9._-]+)", segment)
	}
	got, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		t.Fatalf("peer path segment does not decode as RawURLEncoding: %v", err)
	}
	if string(got) != string(raw) {
		t.Fatalf("round-tripped key bytes do not match original")
	}
}

func TestSpiffeID_EmptyTrustDomain(t *testing.T) {
	if id := SpiffeID("", netbirdShapedKey); id != "" {
		t.Fatalf("empty trust domain should yield SpiffeLabel(\"\"), got %q", id)
	}
}

func TestSpiffeID_MalformedKey(t *testing.T) {
	// Not valid base64 at all (illegal characters), and separately not a
	// multiple-of-4-length padded string — both are "malformed" per the
	// design doc, and both must return "", never an error (the signature is
	// (SpiffeLabel), no error).
	for _, bad := range []string{"not base64 at all!!", "abc", "===="} {
		if id := SpiffeID("meshmcp.example.org", bad); id != "" {
			t.Fatalf("malformed key %q should yield SpiffeLabel(\"\"), got %q", bad, id)
		}
	}
}

func TestSpiffeID_Deterministic(t *testing.T) {
	a := SpiffeID("meshmcp.example.org", netbirdShapedKey)
	b := SpiffeID("meshmcp.example.org", netbirdShapedKey)
	if a != b {
		t.Fatalf("same inputs should produce byte-identical output: %q != %q", a, b)
	}
}

func TestSpiffeID_StandardPaddedInputOnly(t *testing.T) {
	// The padded standard form must decode and produce a label.
	if id := SpiffeID("meshmcp.example.org", netbirdShapedKey); id == "" {
		t.Fatalf("standard padded key should produce a non-empty label")
	}
	// Stripping the padding changes the length to 43, not a multiple of 4,
	// which base64.StdEncoding must reject rather than silently accepting.
	unpadded := netbirdShapedKey[:len(netbirdShapedKey)-1]
	if id := SpiffeID("meshmcp.example.org", unpadded); id != "" {
		t.Fatalf("unpadded input must not be silently accepted, got %q", id)
	}
	// The URL-safe alphabet ('-', '_') is not the standard alphabet ('+',
	// '/'); feeding a URL-safe re-spelling of the same bytes must not decode
	// under the standard decoder either.
	urlSafe := "76SpfHTmmNI0CvRjH_y2ntoe0zdzeACvkl-IKrHlqYA="
	if id := SpiffeID("meshmcp.example.org", urlSafe); id != "" {
		t.Fatalf("URL-safe input must not be silently accepted, got %q", id)
	}
}

func TestValidTrustDomain(t *testing.T) {
	valid := []string{"meshmcp.example.org", "acme", "a.b.c", "a-b.example-corp.io"}
	for _, v := range valid {
		if !ValidTrustDomain(v) {
			t.Errorf("expected %q to be a valid trust domain", v)
		}
	}
	invalid := []string{"", "Meshmcp.example.org", "spiffe://meshmcp.example.org", "meshmcp.example.org/path", "-leading-hyphen.org", "trailing-.org", "has space.org"}
	for _, v := range invalid {
		if ValidTrustDomain(v) {
			t.Errorf("expected %q to be an invalid trust domain", v)
		}
	}
}
