package session

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"
)

// These tests pin the documented residual-dispatch bound of the fencing
// design (see the pump/checkpoint comments in server.go): after gateway B
// takes over a session via an identity-bound reattach, gateway A — whose
// in-memory session is still live — may dispatch AT MOST ONE more inbound
// message to its backend, because backend.Write precedes the checkpoint and
// the very next checkpoint hits SaveIfOwned with a stale generation, is
// fenced, and yields (removes the session). The store's persisted state must
// remain B's throughout: a fenced gateway can neither overwrite nor delete it.

// countingBackend wraps a Backend and records every Write payload, so a test
// can count exactly how many inbound messages a gateway dispatched.
type countingBackend struct {
	b  Backend
	mu sync.Mutex
	ws [][]byte
}

func (c *countingBackend) Write(p []byte) (int, error) {
	cp := append([]byte(nil), p...)
	c.mu.Lock()
	c.ws = append(c.ws, cp)
	c.mu.Unlock()
	return c.b.Write(p)
}
func (c *countingBackend) Read(p []byte) (int, error) { return c.b.Read(p) }
func (c *countingBackend) Close() error               { return c.b.Close() }

func (c *countingBackend) total() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.ws)
}

func (c *countingBackend) countContaining(sub string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, w := range c.ws {
		if bytes.Contains(w, []byte(sub)) {
			n++
		}
	}
	return n
}

// startFenceServer is startSessionServer, but it also returns the *Server so
// the test can observe the gateway's live-session map and instance id.
func startFenceServer(t *testing.T, store SessionStore, factory BackendFactory, mode MigrationMode) (*Server, string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer(factory, 2*time.Minute, nil).WithStore(store, mode)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go srv.Handle(c, Meta{PeerFQDN: "test"})
		}
	}()
	return srv, ln.Addr().String(), func() { ln.Close() }
}

// waitUntil polls cond with a deadline — deterministic synchronization
// instead of bare sleeps.
func waitUntil(t *testing.T, d time.Duration, desc string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", desc)
}

// rawAttach opens a raw transport connection to addr and reattaches to sid,
// modeling a stale client connection that still points at the fenced gateway.
// It returns the connection, its reader, and the server's receive cursor from
// ATTACH_OK (the next DATA frame must carry cursor+1).
func rawAttach(t *testing.T, addr string, sid sessionID) (net.Conn, *bufio.Reader, uint64) {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	w := bufio.NewWriter(conn)
	if err := writeFrame(w, frame{typ: frameAttach, id: sid, seq: 0}); err != nil {
		t.Fatalf("raw ATTACH: %v", err)
	}
	r := bufio.NewReaderSize(conn, maxPayload+64)
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	f, err := readFrame(r)
	if err != nil {
		t.Fatalf("raw ATTACH_OK read: %v", err)
	}
	if f.typ != frameAttachOK {
		t.Fatalf("raw attach: got frame type %d, want ATTACH_OK", f.typ)
	}
	_ = conn.SetReadDeadline(time.Time{})
	return conn, r, f.seq
}

// rawSendData injects one application line into a session over a raw
// connection, at the given inbound sequence number.
func rawSendData(t *testing.T, conn net.Conn, seq uint64, line string) {
	t.Helper()
	w := bufio.NewWriter(conn)
	if err := writeFrame(w, frame{typ: frameData, seq: seq, payload: []byte(line + "\n")}); err != nil {
		t.Fatalf("raw DATA: %v", err)
	}
}

// fenceClient bundles the standard client harness (dialer + local pipe +
// id-keyed response collector) used by the migration tests.
type fenceClient struct {
	d      *switchDialer
	local  *localEnd
	client *Client
	got    chan int
	cancel context.CancelFunc
}

func startFenceClient(t *testing.T, addr string) *fenceClient {
	t.Helper()
	d := &switchDialer{addr: addr}
	local := newLocalEnd()
	client := NewClient(d.dial, nil)
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = client.Run(ctx, local) }()
	got := make(chan int, 32)
	go func() {
		sc := bufio.NewScanner(local.outR)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		for sc.Scan() {
			var r struct {
				ID *int `json:"id"`
			}
			if json.Unmarshal(sc.Bytes(), &r) == nil && r.ID != nil {
				got <- *r.ID
			}
		}
	}()
	return &fenceClient{d: d, local: local, client: client, got: got, cancel: cancel}
}

func (fc *fenceClient) write(s string) { io.WriteString(fc.local.inW, s+"\n") }

func (fc *fenceClient) waitFor(t *testing.T, id int) {
	t.Helper()
	deadline := time.After(10 * time.Second)
	for {
		select {
		case g := <-fc.got:
			if g == id {
				return
			}
		case <-deadline:
			t.Fatalf("timed out waiting for response id %d", id)
		}
	}
}

func (fc *fenceClient) close() {
	fc.local.Close()
	fc.cancel()
}

// establishOnA runs the MCP handshake plus one request (id 2, method) on
// gateway A and waits until A's checkpoint of the complete handshake is
// durable in the store — the state B will rehydrate from.
func establishOnA(t *testing.T, fc *fenceClient, store *MemStore, srvA *Server, method string, wantReplayCapture bool) string {
	t.Helper()
	fc.write(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
	fc.waitFor(t, 1)
	// Small pauses keep each message a separate transport frame so the
	// captured handshake stays minimal (same shape as the migration tests).
	time.Sleep(50 * time.Millisecond)
	fc.write(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	time.Sleep(50 * time.Millisecond)
	fc.write(fmt.Sprintf(`{"jsonrpc":"2.0","id":2,"method":%q}`, method))
	fc.waitFor(t, 2)

	sid := fc.client.SessionID()
	waitUntil(t, 5*time.Second, "gateway A's checkpoint to be durable", func() bool {
		ps, ok, _ := store.Load(sid)
		if !ok || ps.Owner != srvA.instance || ps.Generation != 1 {
			return false
		}
		if wantReplayCapture && !bytes.Contains(ps.Replay, []byte("notifications/initialized")) {
			return false
		}
		// The ack-driven checkpoint ran: everything A sent is acknowledged.
		return ps.SendSeq > 0 && ps.Acked == ps.SendSeq
	})
	return sid
}

// TestFenceResidualDispatchBoundedHandshakeMode drives the residual window in
// MigrateHandshake mode: B takes over while A stays alive, a stale client
// connection pushes one more message into A, and A's backend must see exactly
// that one message before A's next checkpoint fences it and A yields.
func TestFenceResidualDispatchBoundedHandshakeMode(t *testing.T) {
	store := NewMemStore()

	// Capture A's (sole) backend so the residual dispatch is observable.
	backendCh := make(chan *countingBackend, 1)
	factoryA := func(Meta) (Backend, error) {
		cb := &countingBackend{b: newMigBackend()}
		select {
		case backendCh <- cb:
		default:
		}
		return cb, nil
	}
	factoryB := func(Meta) (Backend, error) { return newMigBackend(), nil }

	srvA, addrA, stopA := startFenceServer(t, store, factoryA, MigrateHandshake)
	srvB, addrB, stopB := startFenceServer(t, store, factoryB, MigrateHandshake)
	defer stopA()
	defer stopB()

	fc := startFenceClient(t, addrA)
	defer fc.close()

	sid := establishOnA(t, fc, store, srvA, "ping", true)
	backendA := <-backendCh

	// Fail over: sever the client's connection to A and reattach through B.
	// A is NOT stopped — its in-memory session survives (TTL reaper armed).
	fc.d.failoverTo(addrB)
	fc.write(`{"jsonrpc":"2.0","id":3,"method":"after-failover"}`)
	fc.waitFor(t, 3)
	waitUntil(t, 5*time.Second, "store ownership to move to gateway B", func() bool {
		ps, ok, _ := store.Load(sid)
		return ok && ps.Owner == srvB.instance && ps.Generation == 2
	})
	if got := srvA.Count(); got != 1 {
		t.Fatalf("gateway A live sessions after takeover = %d, want 1 (session must still be live to expose the residual window)", got)
	}

	// Inject exactly one message into A's still-live session over a raw stale
	// connection. backend.Write runs before the checkpoint, so this must reach
	// A's backend; the checkpoint right after it must fence A.
	id, err := parseSessionID(sid)
	if err != nil {
		t.Fatal(err)
	}
	baseline := backendA.total()
	rawConn, rawR, rc := rawAttach(t, addrA, id)
	defer rawConn.Close()
	rawSendData(t, rawConn, rc+1, `{"jsonrpc":"2.0","id":99,"method":"residual"}`)

	// The one residual message is dispatched to A's backend...
	waitUntil(t, 5*time.Second, "the residual message to reach gateway A's backend", func() bool {
		return backendA.countContaining("residual") == 1
	})
	// ...and A's very next checkpoint detects the fence and yields.
	waitUntil(t, 5*time.Second, "gateway A to fence and yield the session", func() bool {
		return srvA.Count() == 0
	})

	// Bound: exactly one post-takeover dispatch, nothing more.
	if got := backendA.countContaining("residual"); got != 1 {
		t.Fatalf("residual messages dispatched to A's backend = %d, want exactly 1", got)
	}
	if got := backendA.total(); got != baseline+1 {
		t.Fatalf("A's backend writes after takeover = %d, want 1 (total %d, baseline %d)", got-baseline, got, baseline)
	}

	// Yielding severed the stale transport: the raw connection must be closed
	// by A (not merely idle), so no further inbound can ever be dispatched.
	_ = rawConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	var readErr error
	for {
		if _, readErr = readFrame(rawR); readErr != nil {
			break
		}
	}
	if errors.Is(readErr, os.ErrDeadlineExceeded) {
		t.Fatal("gateway A left the stale connection open after yielding")
	}

	// The persisted state still belongs to B: A's fenced checkpoint did not
	// overwrite it, and A's remove (DeleteIfOwner) did not delete it.
	ps, ok, _ := store.Load(sid)
	if !ok {
		t.Fatal("persisted session vanished after A yielded (fenced delete leaked through)")
	}
	if ps.Owner != srvB.instance || ps.Generation != 2 {
		t.Fatalf("persisted owner/gen = %q/%d, want gateway B %q/2", ps.Owner, ps.Generation, srvB.instance)
	}

	// B keeps serving the session, unaffected.
	fc.write(`{"jsonrpc":"2.0","id":4,"method":"still-on-b"}`)
	fc.waitFor(t, 4)
}

// --- MigrateBackend variant ---

// The backend's own authoritative per-session store (the EventStore stand-in),
// local to this file so no other test's counters interfere.
var (
	fenceStMu     sync.Mutex
	fenceCounters = map[string]int{}
)

func fenceIncr(id string) int {
	fenceStMu.Lock()
	defer fenceStMu.Unlock()
	fenceCounters[id]++
	return fenceCounters[id]
}

func fenceCount(id string) int {
	fenceStMu.Lock()
	defer fenceStMu.Unlock()
	return fenceCounters[id]
}

// fenceStatefulBackend is a backend-managed (MigrateBackend) backend: its
// state is the shared counter keyed by session id, which a freshly spawned
// instance on another gateway restores from.
type fenceStatefulBackend struct {
	inR  *io.PipeReader
	inW  *io.PipeWriter
	outR *io.PipeReader
	outW *io.PipeWriter
}

func newFenceStatefulBackend(id string) *fenceStatefulBackend {
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	b := &fenceStatefulBackend{inR, inW, outR, outW}
	go func() {
		sc := bufio.NewScanner(inR)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		for sc.Scan() {
			var m struct {
				ID     *int   `json:"id"`
				Method string `json:"method"`
			}
			_ = json.Unmarshal(sc.Bytes(), &m)
			if m.ID == nil {
				continue
			}
			switch m.Method {
			case "initialize":
				fmt.Fprintf(outW, `{"jsonrpc":"2.0","id":%d,"result":{"init":true}}`+"\n", *m.ID)
			case "incr":
				fmt.Fprintf(outW, `{"jsonrpc":"2.0","id":%d,"result":{"count":%d}}`+"\n", *m.ID, fenceIncr(id))
			}
		}
		outW.Close()
	}()
	return b
}

func (b *fenceStatefulBackend) Read(p []byte) (int, error)  { return b.outR.Read(p) }
func (b *fenceStatefulBackend) Write(p []byte) (int, error) { return b.inW.Write(p) }
func (b *fenceStatefulBackend) Close() error                { b.inW.Close(); b.outW.Close(); return nil }

// TestFenceResidualBackendModeAuthoritative exercises the same window in
// MigrateBackend mode and pins the documented contract that removes the
// residual *concern*: the dispatch to the fenced gateway's backend still
// happens (backend.Write precedes the fence check in every mode), but its
// side effect lands exactly once in the backend's own authoritative store —
// there is no meshmcp replay log to re-dispatch it, so B's next request
// observes it exactly once and no state is lost or duplicated. Fencing still
// makes A yield immediately after that one dispatch.
func TestFenceResidualBackendModeAuthoritative(t *testing.T) {
	store := NewMemStore()

	backendCh := make(chan *countingBackend, 1)
	factoryA := func(meta Meta) (Backend, error) {
		cb := &countingBackend{b: newFenceStatefulBackend(meta.SessionID)}
		select {
		case backendCh <- cb:
		default:
		}
		return cb, nil
	}
	factoryB := func(meta Meta) (Backend, error) { return newFenceStatefulBackend(meta.SessionID), nil }

	srvA, addrA, stopA := startFenceServer(t, store, factoryA, MigrateBackend)
	srvB, addrB, stopB := startFenceServer(t, store, factoryB, MigrateBackend)
	defer stopA()
	defer stopB()

	fc := startFenceClient(t, addrA)
	defer fc.close()

	// No replay capture in MigrateBackend mode — only cursor state persists.
	sid := establishOnA(t, fc, store, srvA, "incr", false)
	backendA := <-backendCh
	if got := fenceCount(sid); got != 1 {
		t.Fatalf("counter after first incr on A = %d, want 1", got)
	}

	// Fail over to B; its fresh backend restores state from the session id.
	fc.d.failoverTo(addrB)
	fc.write(`{"jsonrpc":"2.0","id":3,"method":"incr"}`)
	fc.waitFor(t, 3)
	waitUntil(t, 5*time.Second, "store ownership to move to gateway B", func() bool {
		ps, ok, _ := store.Load(sid)
		return ok && ps.Owner == srvB.instance && ps.Generation == 2
	})
	if got := fenceCount(sid); got != 2 {
		t.Fatalf("counter after incr on B = %d, want 2", got)
	}
	if got := srvA.Count(); got != 1 {
		t.Fatalf("gateway A live sessions after takeover = %d, want 1", got)
	}

	// One residual message into A's still-live session.
	id, err := parseSessionID(sid)
	if err != nil {
		t.Fatal(err)
	}
	baseline := backendA.total()
	rawConn, _, rc := rawAttach(t, addrA, id)
	defer rawConn.Close()
	rawSendData(t, rawConn, rc+1, `{"jsonrpc":"2.0","id":99,"method":"incr"}`)

	// The residual side effect lands exactly once in the authoritative store.
	waitUntil(t, 5*time.Second, "the residual incr to reach the backend store", func() bool {
		return fenceCount(sid) == 3
	})
	// A fences on the checkpoint right after the dispatch and yields.
	waitUntil(t, 5*time.Second, "gateway A to fence and yield the session", func() bool {
		return srvA.Count() == 0
	})
	if got := backendA.total(); got != baseline+1 {
		t.Fatalf("A's backend writes after takeover = %d, want exactly 1", got-baseline)
	}

	// B observes the residual exactly once: next incr is 4, not 3 (lost) and
	// not 5 (duplicated) — the backend, not a replay log, is the state source.
	fc.write(`{"jsonrpc":"2.0","id":4,"method":"incr"}`)
	fc.waitFor(t, 4)
	if got := fenceCount(sid); got != 4 {
		t.Fatalf("counter after post-residual incr on B = %d, want 4", got)
	}

	ps, ok, _ := store.Load(sid)
	if !ok || ps.Owner != srvB.instance || ps.Generation != 2 {
		t.Fatalf("persisted owner/gen = %q/%d (ok=%v), want gateway B %q/2", ps.Owner, ps.Generation, ok, srvB.instance)
	}
}
