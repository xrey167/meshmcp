package session

import (
	"testing"
	"time"
)

// TestSendBufferBackpressure verifies that Send blocks once the unacked
// buffer is full (no connection to drain it) and resumes when an ack frees
// a slot — i.e. the buffer is bounded, not unbounded.
func TestSendBufferBackpressure(t *testing.T) {
	e := newEndpointCap(sessionID{}, 3)

	// Fill the buffer: 3 sends with no bound connection must not block.
	for i := 0; i < 3; i++ {
		done := make(chan struct{})
		go func() { _ = e.Send([]byte("x")); close(done) }()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatalf("Send %d blocked unexpectedly", i)
		}
	}

	// The 4th send must block (buffer full, nothing acked).
	blocked := make(chan struct{})
	go func() { _ = e.Send([]byte("y")); close(blocked) }()
	select {
	case <-blocked:
		t.Fatal("4th Send should block on a full buffer")
	case <-time.After(150 * time.Millisecond):
		// expected: still blocked
	}

	// Acknowledge one frame; a slot frees and the blocked Send proceeds.
	e.mu.Lock()
	e.ackLocked(1)
	e.mu.Unlock()
	select {
	case <-blocked:
		// unblocked as expected
	case <-time.After(time.Second):
		t.Fatal("Send did not resume after ack freed a slot")
	}
}

// TestSendUnblocksOnClose verifies a blocked Send returns when the endpoint
// closes (no goroutine leak).
func TestSendUnblocksOnClose(t *testing.T) {
	e := newEndpointCap(sessionID{}, 1)
	_ = e.Send([]byte("x")) // fill

	done := make(chan error, 1)
	go func() { done <- e.Send([]byte("y")) }()
	select {
	case <-done:
		t.Fatal("Send should be blocked")
	case <-time.After(100 * time.Millisecond):
	}

	e.closeWith(nil)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("blocked Send did not return after close")
	}
}
