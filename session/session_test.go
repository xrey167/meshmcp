package session

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// pipeBackend is an in-process echo backend: every line written by the
// client is echoed back with a "reply:" prefix. It stands in for a real
// stdio MCP subprocess.
type pipeBackend struct {
	toServer *io.PipeReader // client -> backend
	toServW  *io.PipeWriter
	toClient *io.PipeReader // backend -> client
	toClentW *io.PipeWriter
	once     sync.Once
}

func newPipeBackend() *pipeBackend {
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	b := &pipeBackend{toServer: inR, toServW: inW, toClient: outR, toClentW: outW}
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := inR.Read(buf)
			if n > 0 {
				fmt.Fprintf(outW, "reply:%s", buf[:n])
			}
			if err != nil {
				outW.CloseWithError(err)
				return
			}
		}
	}()
	return b
}

func (b *pipeBackend) Read(p []byte) (int, error)  { return b.toClient.Read(p) }
func (b *pipeBackend) Write(p []byte) (int, error) { return b.toServW.Write(p) }
func (b *pipeBackend) Close() error {
	b.once.Do(func() { b.toServW.Close(); b.toClentW.Close() })
	return nil
}

// harness wires a session.Server behind a loopback TCP listener and a
// controllable dialer that lets the test sever the live connection.
type harness struct {
	srv      *Server
	ln       net.Listener
	mu       sync.Mutex
	live     net.Conn // most recent client-side conn, for forced drops
	dialects int32
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	h := &harness{ln: ln}
	h.srv = NewServer(
		func(meta Meta) (Backend, error) { return newPipeBackend(), nil },
		2*time.Minute, nil,
	)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go h.srv.Handle(conn, Meta{PeerFQDN: "test-peer"})
		}
	}()
	return h
}

func (h *harness) dialer() Dialer {
	return func(ctx context.Context) (net.Conn, error) {
		d := net.Dialer{}
		conn, err := d.DialContext(ctx, "tcp", h.ln.Addr().String())
		if err != nil {
			return nil, err
		}
		atomic.AddInt32(&h.dialects, 1)
		h.mu.Lock()
		h.live = conn
		h.mu.Unlock()
		return conn, nil
	}
}

// severLive force-closes the current client transport, simulating a mesh
// drop / roam. The session state on both ends must survive it.
func (h *harness) severLive() {
	h.mu.Lock()
	c := h.live
	h.mu.Unlock()
	if c != nil {
		_ = c.Close()
	}
}

// localEnd is the "MCP client" side: the test writes requests to it and
// reads replies from it.
type localEnd struct {
	in  *io.PipeReader // Run reads from here (our writes)
	inW *io.PipeWriter
	out *io.PipeWriter // Run writes here (our reads)
	outR *io.PipeReader
}

func newLocalEnd() *localEnd {
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	return &localEnd{in: inR, inW: inW, out: outW, outR: outR}
}

func (l *localEnd) Read(p []byte) (int, error)  { return l.in.Read(p) }
func (l *localEnd) Write(p []byte) (int, error) { return l.out.Write(p) }
func (l *localEnd) Close() error                { l.inW.Close(); l.out.Close(); return nil }

func TestResumeAcrossDisconnect(t *testing.T) {
	h := newHarness(t)
	local := newLocalEnd()
	client := NewClient(h.dialer(), nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runErr := make(chan error, 1)
	go func() { runErr <- client.Run(ctx, local) }()

	// Collect echoed replies in the background.
	const total = 200
	got := make(chan string, total)
	go func() {
		r := local.outR
		buf := make([]byte, 64*1024)
		acc := ""
		for {
			n, err := r.Read(buf)
			acc += string(buf[:n])
			for {
				idx := indexByte(acc, '\n')
				if idx < 0 {
					break
				}
				got <- acc[:idx]
				acc = acc[idx+1:]
			}
			if err != nil {
				return
			}
		}
	}()

	// Fire requests; sever the transport partway through. No message may
	// be lost or duplicated despite the mid-stream drop.
	severAt := 90
	for i := 0; i < total; i++ {
		if _, err := fmt.Fprintf(local.inW, "req-%d\n", i); err != nil {
			t.Fatalf("write req %d: %v", i, err)
		}
		if i == severAt {
			time.Sleep(20 * time.Millisecond) // let some in-flight traffic exist
			h.severLive()
		}
		time.Sleep(time.Millisecond)
	}

	want := map[string]bool{}
	for i := 0; i < total; i++ {
		want[fmt.Sprintf("reply:req-%d", i)] = true
	}

	seen := map[string]int{}
	timeout := time.After(20 * time.Second)
	for len(seen) < total {
		select {
		case line := <-got:
			if !want[line] {
				t.Fatalf("unexpected reply %q", line)
			}
			seen[line]++
			if seen[line] > 1 {
				t.Fatalf("duplicate delivery of %q (exactly-once violated)", line)
			}
		case <-timeout:
			t.Fatalf("timed out: got %d/%d replies after reconnect", len(seen), total)
		}
	}

	if atomic.LoadInt32(&h.dialects) < 2 {
		t.Fatalf("expected at least one reconnect, got %d dials", h.dialects)
	}
	t.Logf("delivered %d/%d replies exactly once across %d transport connections",
		len(seen), total, atomic.LoadInt32(&h.dialects))

	local.Close()
	select {
	case <-runErr:
	case <-time.After(2 * time.Second):
	}
}

func TestResumeAcrossManyDisconnects(t *testing.T) {
	h := newHarness(t)
	local := newLocalEnd()
	client := NewClient(h.dialer(), nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = client.Run(ctx, local) }()

	const total = 300
	got := make(chan string, total)
	go func() {
		buf := make([]byte, 64*1024)
		acc := ""
		for {
			n, err := local.outR.Read(buf)
			acc += string(buf[:n])
			for {
				idx := indexByte(acc, '\n')
				if idx < 0 {
					break
				}
				got <- acc[:idx]
				acc = acc[idx+1:]
			}
			if err != nil {
				return
			}
		}
	}()

	for i := 0; i < total; i++ {
		if _, err := fmt.Fprintf(local.inW, "req-%d\n", i); err != nil {
			t.Fatalf("write req %d: %v", i, err)
		}
		if i%50 == 49 { // sever every 50 requests
			time.Sleep(15 * time.Millisecond)
			h.severLive()
		}
		time.Sleep(time.Millisecond)
	}

	want := map[string]bool{}
	for i := 0; i < total; i++ {
		want[fmt.Sprintf("reply:req-%d", i)] = true
	}
	seen := map[string]int{}
	timeout := time.After(30 * time.Second)
	for len(seen) < total {
		select {
		case line := <-got:
			if !want[line] {
				t.Fatalf("unexpected reply %q", line)
			}
			if seen[line]++; seen[line] > 1 {
				t.Fatalf("duplicate delivery of %q", line)
			}
		case <-timeout:
			t.Fatalf("timed out: %d/%d after %d dials", len(seen), total, atomic.LoadInt32(&h.dialects))
		}
	}
	t.Logf("delivered %d/%d exactly once across %d transport connections", len(seen), total, atomic.LoadInt32(&h.dialects))
	local.Close()
}

func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}
