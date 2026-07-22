package know

import (
	"strings"
	"testing"
)

func baseTriple() KnowTriple {
	return KnowTriple{
		S:         "e_atlas",
		P:         "ownedBy",
		O:         "e_platform",
		Peer:      "wg:alice",
		Source:    "roadmap.md",
		ValidFrom: "2026-07-22T00:00:00Z",
	}
}

func TestKnowHash_DeterministicAndPrefixed(t *testing.T) {
	tr := baseTriple()
	h1 := tr.KnowHash()
	h2 := tr.KnowHash()
	if h1 != h2 {
		t.Fatalf("hash not deterministic: %q != %q", h1, h2)
	}
	if !strings.HasPrefix(h1, "kh_") {
		t.Fatalf("hash missing kh_ prefix: %q", h1)
	}
	// kh_ + 64 hex chars of sha256.
	if len(h1) != len("kh_")+64 {
		t.Fatalf("unexpected hash length %d: %q", len(h1), h1)
	}
}

// TestKnowHash_ChainPositionIndependent proves the hash depends only on content,
// not on any chain position: two independently-built triples with identical
// content hash identically, and a fresh recompute (re-encoding) is stable.
func TestKnowHash_ChainPositionIndependent(t *testing.T) {
	a := baseTriple()
	b := baseTriple() // a distinct value, same content — as if re-appended on another replica
	if a.KnowHash() != b.KnowHash() {
		t.Fatalf("identical content produced different hashes")
	}
	// Re-encode via receipt round-trip; the recomputed hash must still match.
	r := NewReceipt(a)
	if r.KnowHash != a.KnowHash() {
		t.Fatalf("receipt hash %q != triple hash %q", r.KnowHash, a.KnowHash())
	}
	if !r.Verify() {
		t.Fatalf("receipt failed to verify against its own triple")
	}
}

// TestKnowHash_ChangesWhenAnyFieldChanges checks cross-field sensitivity: every
// single field flip must change the hash.
func TestKnowHash_ChangesWhenAnyFieldChanges(t *testing.T) {
	base := baseTriple()
	baseH := base.KnowHash()

	mutations := map[string]KnowTriple{
		"S":         {S: "x", P: base.P, O: base.O, Peer: base.Peer, Source: base.Source, ValidFrom: base.ValidFrom},
		"P":         {S: base.S, P: "x", O: base.O, Peer: base.Peer, Source: base.Source, ValidFrom: base.ValidFrom},
		"O":         {S: base.S, P: base.P, O: "x", Peer: base.Peer, Source: base.Source, ValidFrom: base.ValidFrom},
		"Peer":      {S: base.S, P: base.P, O: base.O, Peer: "x", Source: base.Source, ValidFrom: base.ValidFrom},
		"Source":    {S: base.S, P: base.P, O: base.O, Peer: base.Peer, Source: "x", ValidFrom: base.ValidFrom},
		"ValidFrom": {S: base.S, P: base.P, O: base.O, Peer: base.Peer, Source: base.Source, ValidFrom: "x"},
	}
	seen := map[string]string{baseH: "base"}
	for field, m := range mutations {
		h := m.KnowHash()
		if h == baseH {
			t.Errorf("changing %s did not change the hash", field)
		}
		if other, dup := seen[h]; dup {
			t.Errorf("changing %s collided with %s", field, other)
		}
		seen[h] = field
	}
}

// TestKnowHash_NoFieldDelimiterInjection is the security-critical case: length
// prefixing must make it impossible to shift bytes across a field boundary to
// forge a collision. Two DISTINCT triples that a naive S+"|"+P join would
// flatten to the same string must hash differently.
func TestKnowHash_NoFieldDelimiterInjection(t *testing.T) {
	cases := []struct {
		name string
		a, b KnowTriple
	}{
		{
			// A naive "S|P" join yields "ab|c" for both.
			name: "shift-across-S-P",
			a:    KnowTriple{S: "a", P: "b|c", O: "o", Peer: "p"},
			b:    KnowTriple{S: "a|b", P: "c", O: "o", Peer: "p"},
		},
		{
			// Move the boundary between O and Peer.
			name: "shift-across-O-Peer",
			a:    KnowTriple{S: "s", P: "p", O: "x", Peer: "yz"},
			b:    KnowTriple{S: "s", P: "p", O: "xy", Peer: "z"},
		},
		{
			// Empty field vs. delimiter absorbed: distinct tuples.
			name: "empty-vs-absorbed",
			a:    KnowTriple{S: "", P: "ab", O: "o", Peer: "p"},
			b:    KnowTriple{S: "a", P: "b", O: "o", Peer: "p"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.a.KnowHash() == c.b.KnowHash() {
				t.Fatalf("distinct triples collided: %+v vs %+v", c.a, c.b)
			}
		})
	}
}

func TestKnowReceipt_VerifyRejectsTampered(t *testing.T) {
	r := NewReceipt(baseTriple())
	// Tamper with the object after the receipt was minted.
	r.Triple.O = "e_attacker"
	if r.Verify() {
		t.Fatalf("verify accepted a receipt whose triple was altered")
	}
	// An empty hash never verifies.
	if (KnowReceipt{Triple: baseTriple()}).Verify() {
		t.Fatalf("verify accepted an empty KnowHash")
	}
}
