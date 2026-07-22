package know

import (
	"bytes"
	"testing"

	"github.com/xrey167/meshmcp/policy"
)

func TestVerbConstructors_ShapeFields(t *testing.T) {
	cases := []struct {
		name       string
		rec        policy.AuditRecord
		wantMethod string
	}{
		{"assert", Assert(Event{Peer: "wg:alice", Corpus: "acme"}), "know.assert"},
		{"supersede", Supersede(Event{Peer: "wg:alice", Corpus: "acme"}), "know.supersede"},
		{"retrieve", Retrieve(Event{Peer: "wg:alice", Corpus: "acme"}), "know.retrieve"},
		{"extract", Extract(Event{Peer: "wg:alice", Corpus: "acme"}), "know.extract"},
		{"node-enter", NodeEnter(Event{Peer: "wg:alice", Corpus: "node1"}), "graph.node-enter"},
		{"checkpoint", Checkpoint(Event{Peer: "wg:alice", Corpus: "run1"}), "graph.checkpoint"},
		{"cosign", Cosign(Event{Peer: "wg:alice", Corpus: "send-report"}), "graph.cosign"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.rec.Method != c.wantMethod {
				t.Errorf("Method = %q, want %q", c.rec.Method, c.wantMethod)
			}
			if c.rec.Backend != Backend {
				t.Errorf("Backend = %q, want %q", c.rec.Backend, Backend)
			}
			if c.rec.Decision != "allow" {
				t.Errorf("Decision = %q, want default allow", c.rec.Decision)
			}
			if c.rec.Peer != "wg:alice" {
				t.Errorf("Peer = %q, want wg:alice", c.rec.Peer)
			}
		})
	}
}

func TestVerbConstructors_CarryProvenanceAndDecision(t *testing.T) {
	kh := baseTriple().KnowHash()
	rec := Retrieve(Event{
		Peer:       "wg:alice",
		PeerKey:    "abc123",
		Corpus:     "acme/product",
		Decision:   "deny",
		Reason:     "not granted",
		Provenance: []string{kh},
		Cost:       3,
	})
	if rec.Decision != "deny" {
		t.Errorf("explicit Decision not honored: %q", rec.Decision)
	}
	if rec.Tool != "acme/product" {
		t.Errorf("Corpus should land in Tool: %q", rec.Tool)
	}
	if rec.PeerKey != "abc123" {
		t.Errorf("PeerKey = %q", rec.PeerKey)
	}
	if rec.Cost != 3 {
		t.Errorf("Cost = %d", rec.Cost)
	}
	if len(rec.Provenance) != 1 || rec.Provenance[0] != kh {
		t.Errorf("Provenance = %v, want [%s]", rec.Provenance, kh)
	}
}

// TestVerbRecords_ChainAndVerify proves the whole point of S4: records from the
// knowledge-op constructors, appended in sequence to one policy.AuditLog, form a
// single unbroken chain that policy.VerifyChain accepts.
func TestVerbRecords_ChainAndVerify(t *testing.T) {
	var buf bytes.Buffer
	log := policy.NewAuditLog(&buf, func() string { return "2026-07-22T00:00:00Z" })

	tr := baseTriple()
	kh := tr.KnowHash()
	records := []policy.AuditRecord{
		Retrieve(Event{Peer: "wg:alice", Corpus: "acme/product", Provenance: []string{kh}}),
		NodeEnter(Event{Peer: "wg:alice", Corpus: "assess"}),
		Assert(Event{Peer: "wg:alice", Corpus: "acme/product", Provenance: []string{kh}}),
		Supersede(Event{Peer: "wg:alice", Corpus: "acme/product"}),
		Cosign(Event{Peer: "wg:alice", Corpus: "send-report", Decision: "cosign"}),
	}
	for i, r := range records {
		if err := log.Append(r); err != nil {
			t.Fatalf("append record %d: %v", i, err)
		}
	}

	res, err := policy.VerifyChain(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("VerifyChain error: %v", err)
	}
	if !res.OK {
		t.Fatalf("chain not OK: break at seq %d: %s", res.BreakSeq, res.Reason)
	}
	if res.Count != len(records) {
		t.Fatalf("verified %d records, wrote %d", res.Count, len(records))
	}
}
