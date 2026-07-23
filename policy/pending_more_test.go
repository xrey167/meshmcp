package policy

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestFilePendingGetReturnsBinding: Get returns the exact record with its
// request-bound fields (ArgsHash/PolicyHash) intact, and reports false for a
// (peer, tool) never recorded.
func TestFilePendingGetReturnsBinding(t *testing.T) {
	ps := &FilePending{Dir: t.TempDir()}
	in := Pending{
		Peer: "agent.mesh", PeerKey: "PK", Backend: "pay", Tool: "transfer",
		RPCID: "7", ArgsHash: "aa11", PolicyHash: "pp22",
	}
	if err := ps.Record(in); err != nil {
		t.Fatal(err)
	}
	got, ok := ps.Get("agent.mesh", "transfer")
	if !ok {
		t.Fatal("recorded pending must be gettable")
	}
	if got.PeerKey != "PK" || got.Backend != "pay" || got.RPCID != "7" ||
		got.ArgsHash != "aa11" || got.PolicyHash != "pp22" {
		t.Fatalf("Get lost binding fields: %+v", got)
	}
	if got.Requested == "" {
		t.Fatal("Record must have stamped Requested")
	}
	if _, ok := ps.Get("agent.mesh", "other"); ok {
		t.Fatal("Get for an unrecorded (peer, tool) must report false")
	}
	// Expired under a TTL: Get must not return it.
	stale := &FilePending{Dir: t.TempDir(), TTL: time.Hour}
	old := Pending{Peer: "a", Tool: "x", Requested: time.Now().Add(-2 * time.Hour).UTC().Format(time.RFC3339)}
	if err := stale.Record(old); err != nil {
		t.Fatal(err)
	}
	if _, ok := stale.Get("a", "x"); ok {
		t.Fatal("expired pending must not be returned by Get")
	}
}

// TestFilePendingHas pins Has across the lifecycle, including its lenient
// existence semantics: a pending file that exists but does not parse still
// reports the call as held (the file's presence, not its content, marks the
// hold), while List and Get skip it.
func TestFilePendingHas(t *testing.T) {
	dir := t.TempDir()
	ps := &FilePending{Dir: dir, TTL: time.Hour}

	if ps.Has("agent.mesh", "transfer") {
		t.Fatal("Has must be false before any record")
	}
	if err := ps.Record(Pending{Peer: "agent.mesh", Tool: "transfer"}); err != nil {
		t.Fatal(err)
	}
	if !ps.Has("agent.mesh", "transfer") {
		t.Fatal("Has must be true after Record")
	}
	if err := ps.Clear("agent.mesh", "transfer"); err != nil {
		t.Fatal(err)
	}
	if ps.Has("agent.mesh", "transfer") {
		t.Fatal("Has must be false after Clear")
	}
	// Expired: recorded long before the TTL window.
	if err := ps.Record(Pending{Peer: "agent.mesh", Tool: "transfer",
		Requested: time.Now().Add(-2 * time.Hour).UTC().Format(time.RFC3339)}); err != nil {
		t.Fatal(err)
	}
	if ps.Has("agent.mesh", "transfer") {
		t.Fatal("Has must be false for an expired pending")
	}
	// A malformed pending file: Has still true (existence marks the hold), but
	// Get fails and List skips it.
	if err := os.WriteFile(pendingFile(dir, "b.mesh", "run"), []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !ps.Has("b.mesh", "run") {
		t.Fatal("Has treats an existing-but-unparseable pending file as held")
	}
	if _, ok := ps.Get("b.mesh", "run"); ok {
		t.Fatal("Get must fail on a malformed pending file")
	}
	if got, _ := ps.List(); len(got) != 0 {
		t.Fatalf("List must skip malformed pending files, got %+v", got)
	}
}

// TestFilePendingKeyAndApprovalRequest: Key ties a pending to the co-sign key
// an approval would use, and ApprovalRequest rebuilds the request-bound
// operation with Session intentionally unset.
func TestFilePendingKeyAndApprovalRequest(t *testing.T) {
	p := Pending{
		Peer: "agent.mesh", PeerKey: "PK", Backend: "pay", Tool: "transfer",
		ArgsHash: "aa", PolicyHash: "pp",
	}
	if p.Key() != CosignKey("agent.mesh", "transfer") {
		t.Fatalf("Key = %q, want CosignKey(peer, tool)", p.Key())
	}
	req := p.ApprovalRequest()
	want := ApprovalRequest{PeerKey: "PK", Backend: "pay", Tool: "transfer", ArgsHash: "aa", PolicyHash: "pp"}
	if req != want {
		t.Fatalf("ApprovalRequest = %+v, want %+v", req, want)
	}
	if req.Session != "" {
		t.Fatal("Session must be left unset to match DecideToolCallBound")
	}
}

// TestFilePendingListNewestFirstAndSkipsForeignFiles: List sorts by Requested
// descending and ignores files that are not well-formed pending records
// (malformed JSON, non-pending names, subdirectories).
func TestFilePendingListNewestFirstAndSkipsForeignFiles(t *testing.T) {
	dir := t.TempDir()
	ps := &FilePending{Dir: dir}

	stamp := func(h int) string { return time.Date(2026, 7, 20, h, 0, 0, 0, time.UTC).Format(time.RFC3339) }
	// Record out of chronological order.
	for _, p := range []Pending{
		{Peer: "a", Tool: "mid", Requested: stamp(12)},
		{Peer: "a", Tool: "new", Requested: stamp(18)},
		{Peer: "a", Tool: "old", Requested: stamp(6)},
	} {
		if err := ps.Record(p); err != nil {
			t.Fatal(err)
		}
	}
	// Noise the listing must ignore.
	if err := os.WriteFile(filepath.Join(dir, "pending-garbage.json"), []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cosign-aaaa.json"), []byte(`{"key":"x"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "pending-subdir.json"), 0o755); err != nil {
		t.Fatal(err)
	}

	got, err := ps.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 pendings, got %d: %+v", len(got), got)
	}
	if got[0].Tool != "new" || got[1].Tool != "mid" || got[2].Tool != "old" {
		t.Fatalf("List must be newest first, got %s, %s, %s", got[0].Tool, got[1].Tool, got[2].Tool)
	}
}

// TestFilePendingNilAndEmptyDirNoOps: an unconfigured registry is inert — no
// errors, nothing held.
func TestFilePendingNilAndEmptyDirNoOps(t *testing.T) {
	for _, ps := range []*FilePending{nil, {}} {
		if err := ps.Record(Pending{Peer: "a", Tool: "x"}); err != nil {
			t.Fatalf("Record on unconfigured store must be a no-op, got %v", err)
		}
		if got, err := ps.List(); err != nil || got != nil {
			t.Fatalf("List on unconfigured store must be empty, got %v, %v", got, err)
		}
		if _, ok := ps.Get("a", "x"); ok {
			t.Fatal("Get on unconfigured store must report false")
		}
		if ps.Has("a", "x") {
			t.Fatal("Has on unconfigured store must report false")
		}
		if err := ps.Clear("a", "x"); err != nil {
			t.Fatalf("Clear on unconfigured store must be a no-op, got %v", err)
		}
	}
}
