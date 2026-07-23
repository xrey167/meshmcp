package session

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// scriptBackend is a backend whose server->client output the test drives byte
// chunk by byte chunk (including deliberately splitting a JSON line), so a test
// can prove Server.Steer never splices into a partial backend line. Its
// client->backend side is swallowed.
type scriptBackend struct {
	mu   sync.Mutex
	buf  []byte
	more chan struct{}
	done bool
}

func newScriptBackend() *scriptBackend { return &scriptBackend{more: make(chan struct{}, 64)} }

func (b *scriptBackend) emit(p []byte) {
	b.mu.Lock()
	b.buf = append(b.buf, p...)
	b.mu.Unlock()
	select {
	case b.more <- struct{}{}:
	default:
	}
}

func (b *scriptBackend) Read(p []byte) (int, error) {
	for {
		b.mu.Lock()
		if len(b.buf) > 0 {
			n := copy(p, b.buf)
			b.buf = b.buf[n:]
			b.mu.Unlock()
			return n, nil
		}
		done := b.done
		b.mu.Unlock()
		if done {
			return 0, io.EOF
		}
		<-b.more
	}
}

func (b *scriptBackend) Write(p []byte) (int, error) { return len(p), nil }

func (b *scriptBackend) Close() error {
	b.mu.Lock()
	b.done = true
	b.mu.Unlock()
	select {
	case b.more <- struct{}{}:
	default:
	}
	return nil
}

// TestSteerLineFraming is the core P2 guarantee: a server->client Steer
// notification, even when injected while a backend JSON-RPC line is only
// half-emitted, reaches the client as its own complete, well-formed line —
// never spliced into another. It also exercises a backend line larger than the
// frame cap (chunked reassembly).
func TestSteerLineFraming(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	var (
		beMu sync.Mutex
		be   *scriptBackend
	)
	srv := NewServer(func(meta Meta) (Backend, error) {
		b := newScriptBackend()
		beMu.Lock()
		be = b
		beMu.Unlock()
		return b, nil
	}, 2*time.Minute, nil)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go srv.Handle(conn, Meta{PeerFQDN: "agent.mesh", PeerKey: "AGENTKEY"})
		}
	}()

	local := newLocalEnd()
	dialer := func(ctx context.Context) (net.Conn, error) {
		return net.Dial("tcp", ln.Addr().String())
	}
	client := NewClient(dialer, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = client.Run(ctx, local) }()

	// Reassemble client-side lines.
	lines := make(chan string, 64)
	go func() {
		r := local.outR
		buf := make([]byte, 128*1024)
		acc := ""
		for {
			n, err := r.Read(buf)
			acc += string(buf[:n])
			for {
				i := indexByte(acc, '\n')
				if i < 0 {
					break
				}
				lines <- acc[:i]
				acc = acc[i+1:]
			}
			if err != nil {
				return
			}
		}
	}()

	// Wait for the session to exist and grab its id (also exercises Sessions()).
	var id string
	for i := 0; i < 200 && id == ""; i++ {
		if ss := srv.Sessions(); len(ss) > 0 {
			if ss[0].Peer != "agent.mesh" {
				t.Fatalf("Sessions() peer = %q, want agent.mesh", ss[0].Peer)
			}
			if ss[0].PeerKey != "AGENTKEY" {
				t.Fatalf("Sessions() peer key = %q, want AGENTKEY", ss[0].PeerKey)
			}
			id = ss[0].ID
		}
		time.Sleep(5 * time.Millisecond)
	}
	if id == "" {
		t.Fatal("session never appeared in Sessions()")
	}

	beMu.Lock()
	b := be
	beMu.Unlock()

	big := strings.Repeat("x", maxPayload*2+7) // spans multiple frames

	// Emit a backend line in two halves; steer BETWEEN the halves. The steer
	// must not splice into the half-emitted line.
	b.emit([]byte(`{"jsonrpc":"2.0","id":1,"result":{"half":`)) // no newline yet
	if err := srv.Steer(id, "notifications/air/steer", map[string]any{"text": "focus"}); err != nil {
		t.Fatalf("steer 1: %v", err)
	}
	b.emit([]byte("\"done\"}}\n")) // complete line 1
	b.emit([]byte(`{"jsonrpc":"2.0","id":2,"result":"` + big + `"}` + "\n"))
	if err := srv.Steer(id, "notifications/air/steer", map[string]any{"text": "again"}); err != nil {
		t.Fatalf("steer 2: %v", err)
	}
	b.emit([]byte(`{"jsonrpc":"2.0","id":3,"result":"ok"}` + "\n"))

	// Expect 3 backend result lines + 2 steer notifications, each a complete,
	// well-formed JSON object — proof nothing spliced.
	steers, results := 0, map[float64]string{}
	deadline := time.After(10 * time.Second)
	for steers+len(results) < 5 {
		select {
		case line := <-lines:
			var m struct {
				Method string          `json:"method"`
				ID     *float64        `json:"id"`
				Params json.RawMessage `json:"params"`
				Result json.RawMessage `json:"result"`
			}
			if err := json.Unmarshal([]byte(line), &m); err != nil {
				t.Fatalf("spliced/invalid line delivered: %q: %v", line, err)
			}
			switch {
			case m.Method == "notifications/air/steer":
				steers++
			case m.ID != nil:
				results[*m.ID] = string(m.Result)
			default:
				t.Fatalf("unexpected line: %q", line)
			}
		case <-deadline:
			t.Fatalf("timeout: steers=%d results=%d", steers, len(results))
		}
	}
	if steers != 2 {
		t.Fatalf("expected 2 steer notifications, got %d", steers)
	}
	if len(results) != 3 {
		t.Fatalf("expected 3 backend result lines, got %d", len(results))
	}
	// The oversize line reassembled intact across frames.
	if want := `"` + big + `"`; results[2] != want {
		t.Fatalf("big line corrupted: len(got)=%d want=%d", len(results[2]), len(want))
	}

	local.Close()
}

// TestSteerUnknownSession: steering an id with no live session errors.
func TestSteerUnknownSession(t *testing.T) {
	srv := NewServer(func(meta Meta) (Backend, error) { return newScriptBackend(), nil }, time.Minute, nil)
	// A well-formed but absent id (32 hex chars) resolves and then misses.
	err := srv.Steer(strings.Repeat("ab", 16), "notifications/air/steer", nil)
	if err != ErrNoSession {
		t.Fatalf("expected ErrNoSession, got %v", err)
	}
}
