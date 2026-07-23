package session

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ackHoldBackend is a steer-inbox-shaped backend: on receiving the first
// complete request line it queues one reply line, then holds Read open until
// Close (mirroring cmd/meshmcp's steerAckSink). remove() closing it turns the
// held Read into EOF.
type ackHoldBackend struct {
	mu      sync.Mutex
	cond    *sync.Cond
	in      []byte
	out     []byte
	replied bool
	closed  bool
}

func newAckHoldBackend() *ackHoldBackend {
	b := &ackHoldBackend{}
	b.cond = sync.NewCond(&b.mu)
	return b
}

func (b *ackHoldBackend) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return 0, errors.New("backend closed")
	}
	b.in = append(b.in, p...)
	if !b.replied && bytes.IndexByte(b.in, '\n') >= 0 {
		b.replied = true
		b.out = append(b.out, []byte("{\"status\":\"delivered\"}\n")...)
		b.cond.Broadcast()
	}
	return len(p), nil
}

func (b *ackHoldBackend) Read(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for len(b.out) == 0 && !b.closed {
		b.cond.Wait()
	}
	if len(b.out) == 0 {
		return 0, io.EOF
	}
	n := copy(p, b.out)
	b.out = append(b.out[:0], b.out[n:]...)
	return n, nil
}

func (b *ackHoldBackend) Close() error {
	b.mu.Lock()
	b.closed = true
	b.cond.Broadcast()
	b.mu.Unlock()
	return nil
}

// oneShotAckLocal is the client-side stream of a one-shot sender (mirroring
// cmd/meshmcp's steerEnvelopeStream): Read serves the payload, then blocks
// until the peer's reply line arrives via Write, then reports EOF — which
// makes Client.Run drain and gracefully close.
type oneShotAckLocal struct {
	payload *bytes.Reader

	mu      sync.Mutex
	got     []byte
	once    sync.Once
	ackDone chan struct{}
}

func newOneShotAckLocal(payload []byte) *oneShotAckLocal {
	return &oneShotAckLocal{payload: bytes.NewReader(payload), ackDone: make(chan struct{})}
}

func (l *oneShotAckLocal) Read(p []byte) (int, error) {
	if n, err := l.payload.Read(p); n > 0 || err != io.EOF {
		return n, err
	}
	<-l.ackDone
	return 0, io.EOF
}

func (l *oneShotAckLocal) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.got = append(l.got, p...)
	if bytes.IndexByte(l.got, '\n') >= 0 {
		l.once.Do(func() { close(l.ackDone) })
	}
	return len(p), nil
}

func (l *oneShotAckLocal) Close() error {
	l.once.Do(func() { close(l.ackDone) })
	return nil
}

// TestGracefulDrainCloseNeverReattaches is the regression test for the steer
// delivery flake once quarantined in CI: a one-shot client whose peer processes
// CLOSE and finalizes the session immediately (net.Pipe's synchronous writes
// make the reaction instant) must never treat the resulting transport error as
// a drop, redial, and have its resume of the just-finalized id rejected with
// "requested resume session is no longer available". After a fully acknowledged
// drain + graceful close, Run must return nil and exactly one dial ever happens
// per session. Guarded by the atomic close-commit in endpoint.sendClose.
func TestGracefulDrainCloseNeverReattaches(t *testing.T) {
	factory := func(Meta) (Backend, error) { return newAckHoldBackend(), nil }
	srv := NewServer(factory, time.Minute, nil)
	var dials atomic.Int64
	dial := func(context.Context) (net.Conn, error) {
		dials.Add(1)
		client, server := net.Pipe()
		go srv.Handle(server, Meta{PeerFQDN: "sender.mesh", PeerKey: "sender-key"})
		return client, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	const iterations = 50
	for i := 0; i < iterations; i++ {
		local := newOneShotAckLocal([]byte("{\"type\":\"task\",\"id\":\"h\"}\n"))
		if err := NewClient(dial, nil).Run(ctx, local); err != nil {
			t.Fatalf("iteration %d: drained graceful close reported failure: %v", i, err)
		}
		if got := dials.Load(); got != int64(i+1) {
			t.Fatalf("iteration %d: dials = %d, want %d (a drained closing client must never reattach)", i, got, i+1)
		}
	}

	// The graceful close must still reach the server: every session finalizes.
	deadline := time.Now().Add(5 * time.Second)
	for srv.Count() != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("server still holds %d sessions; CLOSE frames were lost", srv.Count())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestUnknownResumeStaysTerminal proves the graceful-close fix did not soften
// errSessionNotFound: a resume of an id the server does not know must stay a
// terminal attach rejection (no retry, no silently created fresh session that
// could replay a suffix after side effects).
func TestUnknownResumeStaysTerminal(t *testing.T) {
	factory := func(Meta) (Backend, error) { return newAckHoldBackend(), nil }
	srv := NewServer(factory, time.Minute, nil)
	var dials atomic.Int64
	dial := func(context.Context) (net.Conn, error) {
		dials.Add(1)
		client, server := net.Pipe()
		go srv.Handle(server, Meta{PeerFQDN: "sender.mesh", PeerKey: "sender-key"})
		return client, nil
	}

	id, err := randID()
	if err != nil {
		t.Fatal(err)
	}
	client := NewClient(dial, nil)
	client.ep.id = id // as if a previous attach negotiated an id the server since lost

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	local := newOneShotAckLocal([]byte("payload\n"))
	defer local.Close()
	runErr := client.Run(ctx, local)
	if !errors.Is(runErr, errAttachRejected) {
		t.Fatalf("unknown resume Run = %v, want errAttachRejected", runErr)
	}
	if !strings.Contains(runErr.Error(), "no longer available") {
		t.Fatalf("unknown resume error = %q, want the not-found rejection", runErr)
	}
	if got := dials.Load(); got != 1 {
		t.Fatalf("dials = %d, want exactly 1 (unknown resume is terminal, never retried)", got)
	}
	if got := srv.Count(); got != 0 {
		t.Fatalf("server sessions = %d, want 0 (unknown resume must not create a session)", got)
	}
}
