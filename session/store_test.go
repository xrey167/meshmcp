package session

import (
	"testing"
	"time"
)

// TestStoreList checks that both stores enumerate every persisted session.
func TestStoreList(t *testing.T) {
	for _, tc := range []struct {
		name string
		make func(t *testing.T) SessionStore
	}{
		{"mem", func(t *testing.T) SessionStore { return NewMemStore() }},
		{"file", func(t *testing.T) SessionStore {
			s, err := NewFileStore(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			return s
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := tc.make(t)
			if l, err := s.List(); err != nil || len(l) != 0 {
				t.Fatalf("empty store: len=%d err=%v", len(l), err)
			}
			for _, id := range []string{"aa", "bb", "cc"} {
				if err := s.Save(PersistedSession{ID: id, Owner: "gw1"}); err != nil {
					t.Fatalf("save %s: %v", id, err)
				}
			}
			l, err := s.List()
			if err != nil {
				t.Fatalf("list: %v", err)
			}
			got := map[string]bool{}
			for _, ps := range l {
				got[ps.ID] = true
			}
			if len(got) != 3 || !got["aa"] || !got["bb"] || !got["cc"] {
				t.Fatalf("expected aa,bb,cc; got %v", got)
			}
			// A delete is reflected in the next List.
			if err := s.DeleteIfOwner("bb", "gw1"); err != nil {
				t.Fatal(err)
			}
			l, _ = s.List()
			if len(l) != 2 {
				t.Fatalf("expected 2 after delete, got %d", len(l))
			}
		})
	}
}

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

// TestRestoreEndpointRejectsOversizedSendBuf proves a persisted session whose
// SendBuf exceeds the send-frame cap is rejected rather than draining the
// semaphore and blocking forever on <-e.slots — which, since restoreEndpoint
// runs under the server's global mutex, would wedge the whole session server.
func TestRestoreEndpointRejectsOversizedSendBuf(t *testing.T) {
	over := make([]PersistedFrame, defaultMaxSendFrames+1)
	for i := range over {
		over[i] = PersistedFrame{Seq: uint64(i + 1), Payload: []byte("x")}
	}
	ps := PersistedSession{ID: "00112233445566778899aabbccddeeff", SendBuf: over}
	done := make(chan struct{})
	go func() {
		defer close(done)
		if _, err := restoreEndpoint(ps); err == nil {
			t.Errorf("restoreEndpoint must reject an oversized SendBuf, not accept it")
		}
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("restoreEndpoint blocked (deadlock) on an oversized SendBuf instead of returning an error")
	}

	// A buffer at the cap is still accepted.
	ok := make([]PersistedFrame, defaultMaxSendFrames)
	for i := range ok {
		ok[i] = PersistedFrame{Seq: uint64(i + 1), Payload: []byte("x")}
	}
	if _, err := restoreEndpoint(PersistedSession{ID: "00112233445566778899aabbccddeeff", SendBuf: ok}); err != nil {
		t.Fatalf("a SendBuf at the cap must be accepted: %v", err)
	}
}
