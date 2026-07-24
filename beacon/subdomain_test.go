package beacon

import (
	"regexp"
	"testing"
)

func TestSubdomainLabel(t *testing.T) {
	a := SubdomainLabel([]byte("gateway-key-A"))
	b := SubdomainLabel([]byte("gateway-key-B"))

	// Deterministic (stable public name across restarts).
	if a != SubdomainLabel([]byte("gateway-key-A")) {
		t.Fatal("label is not deterministic")
	}
	// Distinct keys -> distinct labels.
	if a == b {
		t.Fatal("distinct keys produced the same label")
	}
	// DNS-label-safe: lowercase base32 alphabet, fixed length.
	if len(a) != labelLen {
		t.Fatalf("label length = %d, want %d", len(a), labelLen)
	}
	if !regexp.MustCompile(`^[a-z2-7]+$`).MatchString(a) {
		t.Fatalf("label %q is not DNS-label-safe base32", a)
	}
}

func TestLabelFromSNI(t *testing.T) {
	zone := "beacon.example.com"
	cases := []struct {
		sni  string
		want string
	}{
		{"gw-abc.beacon.example.com", "gw-abc"},
		{"gw-abc.beacon.example.com.", "gw-abc"}, // trailing dot tolerated
		{"GW-ABC.Beacon.Example.Com", "gw-abc"},  // case-insensitive
		{"other.example.com", ""},                // wrong zone
		{"beacon.example.com", ""},               // zone itself, no label
		{"a.b.beacon.example.com", ""},           // nested label rejected
		{"evil.com", ""},                         // unrelated
		{"", ""},                                 // empty
	}
	for _, tc := range cases {
		if got := labelFromSNI(tc.sni, zone); got != tc.want {
			t.Errorf("labelFromSNI(%q) = %q, want %q", tc.sni, got, tc.want)
		}
	}
}
