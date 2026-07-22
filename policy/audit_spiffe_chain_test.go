package policy

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// These tests cover Feature A's additive AuditRecord.PeerSpiffeID field
// (docs/spec/OAUTH-STANDARDS.md / OAUTH-STANDARDS-tests.md): the field must be
// omitempty-elided when empty, must not disturb the hash chain when absent,
// must keep the chain verifiable when present, and must (by design) change a
// record's hash so the mixed-fleet incompatibility is explicit and locked in.

// TestAuditRecord_PeerSpiffeIDOmittedWhenEmpty proves omitempty actually elides
// the field: an empty PeerSpiffeID produces JSON with no peer_spiffe_id key,
// not "peer_spiffe_id":"".
func TestAuditRecord_PeerSpiffeIDOmittedWhenEmpty(t *testing.T) {
	rec := AuditRecord{Backend: "kg", Peer: "p", Method: "tools/call", Decision: "allow"}
	b, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if bytes.Contains(b, []byte("peer_spiffe_id")) {
		t.Fatalf("empty PeerSpiffeID must be elided by omitempty, got: %s", b)
	}
}

// TestAuditRecord_HashChainUnaffectedByNewField proves the additive field is
// truly additive: a chain of records that never set it verifies, and the
// canonical bytes the hash covers are byte-identical across builds (no
// time/random perturbation, and the elided field cannot shift the hash).
func TestAuditRecord_HashChainUnaffectedByNewField(t *testing.T) {
	build := func() string {
		var buf bytes.Buffer
		a := NewAuditLog(&buf, func() string { return "T" })
		for i := 0; i < 3; i++ {
			a.write(AuditRecord{Backend: "kg", Peer: "p", Method: "tools/call", Decision: "allow"})
		}
		return buf.String()
	}
	out := build()
	res, err := VerifyChain(strings.NewReader(out))
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !res.OK {
		t.Fatalf("chain of records with empty PeerSpiffeID did not verify: %s", res.Reason)
	}
	if out2 := build(); out2 != out {
		t.Fatalf("hash chain is not deterministic across builds; the new field perturbed canonical bytes")
	}
}

// TestAuditRecord_HashChainWithSpiffeIDPresent proves that a chain where every
// record carries a PeerSpiffeID still verifies end to end — the new field does
// not break the canonical serialization/ordering the hash chain relies on.
func TestAuditRecord_HashChainWithSpiffeIDPresent(t *testing.T) {
	var buf bytes.Buffer
	a := NewAuditLog(&buf, func() string { return "T" })
	for i := 0; i < 3; i++ {
		a.write(AuditRecord{
			Backend:      "federation-boundary",
			Peer:         "acme",
			Method:       "federation/tools/call",
			Decision:     "allow",
			PeerSpiffeID: SpiffeID("acme.example.org", netbirdShapedKey),
		})
	}
	res, err := VerifyChain(strings.NewReader(buf.String()))
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !res.OK {
		t.Fatalf("chain where every record has PeerSpiffeID set did not verify: %s", res.Reason)
	}
	if res.Count != 3 {
		t.Fatalf("verified count = %d, want 3", res.Count)
	}
}

// TestAuditRecord_MixedFleetHashMismatchIsExpected documents and locks in the
// accepted mixed-fleet incompatibility: the same logical record hashes
// differently depending on whether the field is present, so an old verifier
// binary that omits peer_spiffe_id computes a different hash than the new one.
// That is expected, not a bug — this test fails loudly if a future change
// silently makes the field hash-invisible (which would be its own hazard).
func TestAuditRecord_MixedFleetHashMismatchIsExpected(t *testing.T) {
	firstHash := func(rec AuditRecord) string {
		var buf bytes.Buffer
		a := NewAuditLog(&buf, func() string { return "T" })
		a.write(rec)
		var got AuditRecord
		if err := json.Unmarshal([]byte(strings.TrimRight(buf.String(), "\n")), &got); err != nil {
			t.Fatalf("unmarshal written record: %v", err)
		}
		return got.Hash
	}
	base := AuditRecord{Backend: "federation-boundary", Peer: "acme", Method: "federation/tools/call", Decision: "allow"}
	withField := base
	withField.PeerSpiffeID = SpiffeID("acme.example.org", netbirdShapedKey)

	h1 := firstHash(withField) // new binary: field present
	h2 := firstHash(base)      // old binary: field absent
	if h1 == "" || h2 == "" {
		t.Fatal("expected non-empty hashes")
	}
	if h1 == h2 {
		t.Fatal("a record with PeerSpiffeID must hash differently than one without it (the mixed-fleet incompatibility is expected and must stay observable)")
	}
}
