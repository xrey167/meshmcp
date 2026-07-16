package policy

import (
	"testing"
	"time"
)

func TestFilePendingRecordListClear(t *testing.T) {
	dir := t.TempDir()
	ps := &FilePending{Dir: dir}

	if got, _ := ps.List(); len(got) != 0 {
		t.Fatalf("expected empty pending, got %v", got)
	}
	if err := ps.Record(Pending{Peer: "agent.mesh", Backend: "pay", Tool: "transfer_funds", RPCID: "7"}); err != nil {
		t.Fatal(err)
	}
	got, err := ps.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Tool != "transfer_funds" || got[0].Peer != "agent.mesh" {
		t.Fatalf("pending list wrong: %+v", got)
	}
	if got[0].Requested == "" {
		t.Fatalf("Record should stamp a Requested time")
	}
	if err := ps.Clear("agent.mesh", "transfer_funds"); err != nil {
		t.Fatal(err)
	}
	if got, _ := ps.List(); len(got) != 0 {
		t.Fatalf("expected empty after clear, got %v", got)
	}
}

func TestFilePendingTTLExpires(t *testing.T) {
	dir := t.TempDir()
	ps := &FilePending{Dir: dir, TTL: time.Hour}
	// Record with an explicit stale timestamp.
	if err := ps.Record(Pending{Peer: "a", Tool: "x", Requested: time.Now().Add(-2 * time.Hour).UTC().Format(time.RFC3339)}); err != nil {
		t.Fatal(err)
	}
	if got, _ := ps.List(); len(got) != 0 {
		t.Fatalf("expired pending should not be listed, got %v", got)
	}
}

// TestFilterRecordsPendingOnCosign drives a require_cosign call through the
// real filter and asserts the held request lands in the pending registry, so an
// approver (a phone on the mesh) can see it.
func TestFilterRecordsPendingOnCosign(t *testing.T) {
	dir := t.TempDir()
	pending := &FilePending{Dir: dir}
	backend := newEchoBackend()
	pol := &Policy{
		DefaultAllow: false,
		Rules: []Rule{
			{Peers: []string{"*"}, Tools: []string{"transfer_funds"}, Allow: true, RequireCosign: true},
		},
	}
	eng := NewEngine(pol, nil, nil) // no cosign store → the call is held
	f := NewFilterEngine(backend, Caller{Backend: "pay", Peer: "agent.mesh", PeerKey: "K"}, eng, NewAuditLog(nil, nil), nil)
	f.SetPendingStore(pending)

	// consume replies
	go func() {
		buf := make([]byte, 4096)
		for {
			if _, err := f.Read(buf); err != nil {
				return
			}
		}
	}()
	if _, err := f.Write([]byte(`{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"transfer_funds","arguments":{"amount":500}}}` + "\n")); err != nil {
		t.Fatal(err)
	}

	// The held request should appear in the registry.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		got, _ := pending.List()
		if len(got) == 1 && got[0].Tool == "transfer_funds" && got[0].RPCID == "9" {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	got, _ := pending.List()
	t.Fatalf("cosign call should have recorded a pending request, got %+v", got)
}
