package federation

import (
	"strings"
	"testing"
)

// spiffeTestKey is a real NetBird/WireGuard-shaped standard-padded base64 public
// key (32 raw bytes), the form client.IdentityForIP actually returns.
const spiffeTestKey = "76SpfHTmmNI0CvRjH/y2ntoe0zdzeACvkl+IKrHlqYA="

// TestBoundary_SpiffeID_KnownOrg: a pubkey-mapped org with a configured trust
// domain yields a well-formed spiffe:// label, and the boundary derives the
// same label at emission time without a caller-supplied key.
func TestBoundary_SpiffeID_KnownOrg(t *testing.T) {
	b := NewBoundary(nil, []Mapping{
		{Match: "pubkey:" + spiffeTestKey, Org: "acme", TrustDomain: "acme.example.org"},
	}, nil)

	got := b.SpiffeID("acme", spiffeTestKey)
	if got == "" {
		t.Fatal("expected a SPIFFE id for a known org with a trust domain and a stable key")
	}
	if !strings.HasPrefix(string(got), "spiffe://acme.example.org/peer/") {
		t.Fatalf("got %q, want spiffe://acme.example.org/peer/...", got)
	}
	if b.spiffeForOrg("acme") != got {
		t.Fatalf("spiffeForOrg(acme) = %q, want %q (emission must derive the key from the pubkey mapping)", b.spiffeForOrg("acme"), got)
	}
}

// TestBoundary_SpiffeID_UnknownOrgOrNoTrustDomain: no trust domain, or an
// unknown org, yields "" — never a malformed URI, never a default domain.
func TestBoundary_SpiffeID_UnknownOrgOrNoTrustDomain(t *testing.T) {
	b := NewBoundary(nil, []Mapping{
		{Match: "pubkey:" + spiffeTestKey, Org: "acme"}, // no trust domain
		{Match: "pubkey:OTHER", Org: "globex", TrustDomain: "globex.example.org"},
	}, nil)

	if got := b.SpiffeID("acme", spiffeTestKey); got != "" {
		t.Fatalf("org with no configured trust domain must yield \"\", got %q", got)
	}
	if got := b.SpiffeID("nope", spiffeTestKey); got != "" {
		t.Fatalf("unknown org must yield \"\", got %q", got)
	}
}

// TestBoundary_SpiffeID_FQDNMappedPeerHasNoStableKey: an org matched only by an
// FQDN glob has no individual key, so both the explicit-empty-key call and the
// emission helper yield "" rather than a synthetic label.
func TestBoundary_SpiffeID_FQDNMappedPeerHasNoStableKey(t *testing.T) {
	b := NewBoundary(nil, []Mapping{
		{Match: "*.acme.netbird.cloud", Org: "acme", TrustDomain: "acme.example.org"},
	}, nil)

	if got := b.SpiffeID("acme", ""); got != "" {
		t.Fatalf("no stable key must yield \"\", got %q", got)
	}
	if got := b.spiffeForOrg("acme"); got != "" {
		t.Fatalf("an FQDN-mapped org has no pubkey; spiffeForOrg must yield \"\", got %q", got)
	}
}

// TestBoundary_TrustDomainCollisionDetected: two different orgs claiming the
// same non-empty trust domain is flagged; one org repeating its own domain
// across mappings is not.
func TestBoundary_TrustDomainCollisionDetected(t *testing.T) {
	collide := NewBoundary(nil, []Mapping{
		{Match: "pubkey:K1", Org: "acme", TrustDomain: "shared.example.org"},
		{Match: "pubkey:K2", Org: "globex", TrustDomain: "shared.example.org"},
	}, nil)
	if len(collide.TrustDomainCollisions()) == 0 {
		t.Fatal("two orgs sharing one trust domain must be flagged as a collision")
	}

	ok := NewBoundary(nil, []Mapping{
		{Match: "pubkey:K1", Org: "acme", TrustDomain: "acme.example.org"},
		{Match: "*.acme.cloud", Org: "acme", TrustDomain: "acme.example.org"},
	}, nil)
	if cols := ok.TrustDomainCollisions(); len(cols) != 0 {
		t.Fatalf("one org repeating its own trust domain is not a collision, got %v", cols)
	}
}
