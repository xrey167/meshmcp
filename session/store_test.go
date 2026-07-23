package session

import (
	"testing"
	"time"
)

// Save/Load/List/DeleteIfOwner and the full lease CAS contract are proven by
// the shared conformance harness (storetest_file_test.go, via
// session/storetest) against both MemStore and FileStore.

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
