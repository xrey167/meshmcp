package session

import (
	"testing"
)

// TestFileStoreRoundTripAndLease exercises the durable file store: a full
// persisted session round-trips (with fsync + locking), and the ownership
// lease is enforced on delete.
func TestFileStoreRoundTripAndLease(t *testing.T) {
	s, err := NewFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ps := PersistedSession{
		ID:              "abc123",
		Owner:           "gw1",
		SendSeq:         5,
		Acked:           2,
		RecvSeq:         3,
		Replay:          []byte("handshake"),
		ReplayResponses: 1,
		SendBuf:         []PersistedFrame{{Seq: 4, Payload: []byte("x")}},
	}
	if err := s.Save(ps); err != nil {
		t.Fatalf("save: %v", err)
	}

	got, ok, err := s.Load("abc123")
	if err != nil || !ok {
		t.Fatalf("load: ok=%v err=%v", ok, err)
	}
	if got.SendSeq != 5 || got.RecvSeq != 3 || got.Owner != "gw1" ||
		string(got.Replay) != "handshake" || got.ReplayResponses != 1 || len(got.SendBuf) != 1 {
		t.Fatalf("round-trip mismatch: %+v", got)
	}

	// Lease: a non-owner cannot delete; the owner can.
	if err := s.DeleteIfOwner("abc123", "gw2"); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.Load("abc123"); !ok {
		t.Fatal("non-owner delete removed the session")
	}
	if err := s.DeleteIfOwner("abc123", "gw1"); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.Load("abc123"); ok {
		t.Fatal("owner delete did not remove the session")
	}
}
