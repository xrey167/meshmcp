package session

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// This file proves the v1-of-v2 live-session move: the happy path end to end
// (two servers, session on A, prepare->ready->commit to B, client reattaches to
// B on a WARM backend, A fenced), abort at every pre-commit step, and the full
// crash-recovery matrix from the design — each crash point leaves EXACTLY one
// resumable owner. The crash-matrix and abort tests are deterministic (no sleeps:
// waitResp blocks on real responses and checkpointNow forces store state), so
// they are meaningful under -count=20.

// moveCreatorMeta is the single creator identity both gateways see for the moved
// session (the same client reattaches to whichever gateway owns it). Identity
// binding requires a non-empty creator key.
var moveCreatorMeta = Meta{PeerFQDN: "creator.mesh.example", PeerAddr: "100.64.0.9:41641", PeerKey: "wg-creator-pubkey"}

// moveDestKey is the destination gateway's identity (the single-use grant subject
// at the CLI/air layer; at the session layer authorization is an injected gate).
const moveDestKey = "wg-destination-gateway-key"

type spawnCounter struct {
	mu sync.Mutex
	n  int
}

func (c *spawnCounter) inc()       { c.mu.Lock(); c.n++; c.mu.Unlock() }
func (c *spawnCounter) count() int { c.mu.Lock(); defer c.mu.Unlock(); return c.n }

// onceGrant is a single-use authorization gate: true the first time, false after,
// standing in for GrantStore.ConsumeOnceMatching at the session layer (the real
// grant integration is proven in air/move_grant_test.go, which can import air).
func onceGrant() func() (bool, error) {
	used := false
	return func() (bool, error) {
		if used {
			return false, nil
		}
		used = true
		return true, nil
	}
}

func denyAll(string) (bool, error) { return false, nil }

func statefulFactory(c *spawnCounter) BackendFactory {
	return func(meta Meta) (Backend, error) {
		if c != nil {
			c.inc()
		}
		return newStatefulBackend(meta.SessionID), nil
	}
}

func echoFactory(c *spawnCounter) BackendFactory {
	return func(meta Meta) (Backend, error) {
		if c != nil {
			c.inc()
		}
		return newMigBackend(), nil
	}
}

func startMoveServer(t *testing.T, store SessionStore, factory BackendFactory, mode MigrationMode) (*Server, string, func()) {
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
			go srv.Handle(c, moveCreatorMeta)
		}
	}()
	return srv, ln.Addr().String(), func() { ln.Close() }
}

// deadAddress returns an address with nothing listening (dials fail fast), used
// to park the client where it cannot re-serve during a move.
func deadAddress(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

type moveResp struct {
	id, count int
}

func wireClient(t *testing.T, d *switchDialer) (*localEnd, chan moveResp, context.CancelFunc) {
	t.Helper()
	local := newLocalEnd()
	client := NewClient(d.dial, nil)
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = client.Run(ctx, local) }()
	ch := make(chan moveResp, 64)
	go func() {
		sc := bufio.NewScanner(local.outR)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		for sc.Scan() {
			var r struct {
				ID     *int `json:"id"`
				Result struct {
					Count int `json:"count"`
				} `json:"result"`
			}
			if json.Unmarshal(sc.Bytes(), &r) == nil && r.ID != nil {
				ch <- moveResp{*r.ID, r.Result.Count}
			}
		}
	}()
	return local, ch, cancel
}

func waitResp(t *testing.T, ch chan moveResp, id int) int {
	t.Helper()
	deadline := time.After(10 * time.Second)
	for {
		select {
		case r := <-ch:
			if r.id == id {
				return r.count
			}
		case <-deadline:
			t.Fatalf("timed out waiting for response id %d", id)
		}
	}
}

// --- in-package accessors (unexported state reached only in tests) ---

func firstSessionID(s *Server) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id := range s.sessions {
		return id.String()
	}
	return ""
}

func sessionGen(s *Server, id string) uint64 {
	sid, _ := parseSessionID(id)
	s.mu.Lock()
	defer s.mu.Unlock()
	if sess, ok := s.sessions[sid]; ok {
		return sess.leaseGen
	}
	return 0
}

// checkpointNow forces a synchronous checkpoint so the store reflects the current
// session state without waiting on the async ack-driven checkpoint.
func checkpointNow(s *Server, id string) {
	sid, _ := parseSessionID(id)
	s.mu.Lock()
	sess := s.sessions[sid]
	s.mu.Unlock()
	if sess != nil {
		s.checkpoint(sess)
	}
}

func loadPS(t *testing.T, store *MemStore, id string) PersistedSession {
	t.Helper()
	ps, ok, err := store.Load(id)
	if err != nil || !ok {
		t.Fatalf("load %s: ok=%v err=%v", id, ok, err)
	}
	return ps
}

// assertOwner checks the store's authoritative owner + generation for a session.
func assertOwner(t *testing.T, store *MemStore, id, owner string, gen uint64) {
	t.Helper()
	ps := loadPS(t, store, id)
	if ps.Owner != owner || ps.Generation != gen {
		t.Fatalf("store owner=%q gen=%d, want owner=%q gen=%d", ps.Owner, ps.Generation, owner, gen)
	}
}

// assertFenced confirms owner@gen can no longer write (superseded).
func assertFenced(t *testing.T, store *MemStore, id, owner string, gen uint64) {
	t.Helper()
	if ok, _ := store.SaveIfOwned(PersistedSession{ID: id}, owner, gen); ok {
		t.Fatalf("owner %q gen %d should be fenced but SaveIfOwned succeeded", owner, gen)
	}
}

// establishBackendSession opens a MigrateBackend session on source via a real
// client, deterministically (init + one incr, both awaited), forces a checkpoint,
// and returns the session id + client handles. No sleeps.
func establishBackendSession(t *testing.T, source *Server, d *switchDialer) (string, chan moveResp, *localEnd, context.CancelFunc) {
	t.Helper()
	local, ch, cancel := wireClient(t, d)
	write := func(s string) { io.WriteString(local.inW, s+"\n") }
	write(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
	waitResp(t, ch, 1)
	write(`{"jsonrpc":"2.0","id":2,"method":"incr"}`)
	if c := waitResp(t, ch, 2); c != 1 {
		t.Fatalf("first incr = %d, want 1", c)
	}
	id := firstSessionID(source)
	if id == "" {
		t.Fatal("source has no session after establish")
	}
	checkpointNow(source, id)
	return id, ch, local, cancel
}

// ============================ happy path ============================

// TestMoveHappyPath_Backend proves an end-to-end move of a MigrateBackend
// (checkpoint-capable) session: source serves, B is pre-warmed, the commit swaps
// ownership in one CAS, the client reattaches to B on the WARM backend (spawned
// exactly once), and A is fenced.
func TestMoveHappyPath_Backend(t *testing.T) {
	store := NewMemStore()
	srcSpawns, dstSpawns := &spawnCounter{}, &spawnCounter{}
	source, addrA, stopA := startMoveServer(t, store, statefulFactory(srcSpawns), MigrateBackend)
	dest, addrB, stopB := startMoveServer(t, store, statefulFactory(dstSpawns), MigrateBackend)
	defer stopA()
	defer stopB()

	d := &switchDialer{addr: addrA}
	id, ch, local, cancel := establishBackendSession(t, source, d)
	defer cancel()
	defer local.Close()

	g := sessionGen(source, id)
	if g != 1 {
		t.Fatalf("source generation = %d, want 1", g)
	}

	// Park the client so it cannot re-serve on A during the move; the operator
	// redirects it to B only after commit.
	d.failoverTo(deadAddress(t))

	// Run the move over an identity-agnostic in-process control channel.
	runMove(t, source, dest, id)

	// Ownership swapped atomically; source fenced; local session moved.
	assertOwner(t, store, id, dest.instance, g+1)
	assertFenced(t, store, id, source.instance, g)
	if source.Count() != 0 {
		t.Fatalf("source still holds %d sessions after yield", source.Count())
	}
	if dest.Count() != 1 {
		t.Fatalf("dest holds %d sessions, want 1", dest.Count())
	}

	// Client reattaches to B and is served by the pre-warmed backend.
	d.failoverTo(addrB)
	write := func(s string) { io.WriteString(local.inW, s+"\n") }
	write(`{"jsonrpc":"2.0","id":3,"method":"incr"}`)
	if c := waitResp(t, ch, 3); c != 2 {
		t.Fatalf("incr after move = %d, want 2 (backend state continuous on warm backend)", c)
	}
	if dstSpawns.count() != 1 {
		t.Fatalf("dest spawned %d backends, want exactly 1 (warm at prepare, none at reattach)", dstSpawns.count())
	}
}

// TestMoveHappyPath_Handshake proves the same for a stateless MigrateHandshake
// backend, including that a request served immediately before the freeze is not
// lost across the move (every id answered exactly once).
func TestMoveHappyPath_Handshake(t *testing.T) {
	store := NewMemStore()
	dstSpawns := &spawnCounter{}
	source, addrA, stopA := startMoveServer(t, store, echoFactory(nil), MigrateHandshake)
	dest, addrB, stopB := startMoveServer(t, store, echoFactory(dstSpawns), MigrateHandshake)
	defer stopA()
	defer stopB()

	d := &switchDialer{addr: addrA}
	local, ch, cancel := wireClient(t, d)
	defer cancel()
	defer local.Close()
	write := func(s string) { io.WriteString(local.inW, s+"\n") }

	// Clean handshake capture: keep init / initialized / request in separate
	// frames (the established migration-test pattern for handshake mode).
	write(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
	waitResp(t, ch, 1)
	time.Sleep(50 * time.Millisecond)
	write(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	time.Sleep(50 * time.Millisecond)
	// A request served immediately before the move; its response must survive.
	write(`{"jsonrpc":"2.0","id":2,"method":"ping"}`)
	waitResp(t, ch, 2)

	id := firstSessionID(source)
	if id == "" {
		t.Fatal("no source session")
	}
	g := sessionGen(source, id)
	d.failoverTo(deadAddress(t))
	runMove(t, source, dest, id)

	assertOwner(t, store, id, dest.instance, g+1)
	assertFenced(t, store, id, source.instance, g)
	if source.Count() != 0 || dest.Count() != 1 {
		t.Fatalf("post-move counts source=%d dest=%d, want 0/1", source.Count(), dest.Count())
	}

	d.failoverTo(addrB)
	write(`{"jsonrpc":"2.0","id":3,"method":"after-move"}`)
	waitResp(t, ch, 3)
	if dstSpawns.count() != 1 {
		t.Fatalf("dest spawned %d handshake backends, want exactly 1 (warm)", dstSpawns.count())
	}
}

// runMove drives one prepare->ready->commit move over an in-process net.Pipe,
// using the real orchestrator (source) and control handler (dest). It fails the
// test on any move error.
func runMove(t *testing.T, source, dest *Server, id string) {
	t.Helper()
	srcConn, dstConn := net.Pipe()
	grant := onceGrant()
	mvErr := make(chan error, 1)
	go func() {
		mvErr <- dest.ServeMoveControl(dstConn, func(string) (bool, error) { return grant() })
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := source.MoveSessionTo(ctx, id, srcConn, moveDestKey); err != nil {
		t.Fatalf("MoveSessionTo: %v", err)
	}
	if err := <-mvErr; err != nil {
		t.Fatalf("ServeMoveControl: %v", err)
	}
}

// ============================ abort matrix ============================

// TestMoveAbort_AtPrepare: aborting while the destination is only warm (no lease)
// leaves the source the sole owner and its warm backend discarded.
func TestMoveAbort_AtPrepare(t *testing.T) {
	store := NewMemStore()
	source, addrA, stopA := startMoveServer(t, store, statefulFactory(nil), MigrateBackend)
	dest, _, stopB := startMoveServer(t, store, statefulFactory(nil), MigrateBackend)
	defer stopA()
	defer stopB()
	_ = addrA

	d := &switchDialer{addr: addrA}
	id, ch, local, cancel := establishBackendSession(t, source, d)
	defer cancel()
	defer local.Close()
	g := sessionGen(source, id)

	if err := dest.PrepareMove(loadPS(t, store, id), moveCreatorMeta); err != nil {
		t.Fatalf("PrepareMove: %v", err)
	}
	if dest.warmingCount() != 1 || dest.Count() != 0 {
		t.Fatalf("after prepare: warming=%d live=%d, want 1/0", dest.warmingCount(), dest.Count())
	}
	assertOwner(t, store, id, source.instance, g)

	dest.AbortMove(id)
	if dest.warmingCount() != 0 {
		t.Fatalf("after abort: warming=%d, want 0", dest.warmingCount())
	}
	assertOwner(t, store, id, source.instance, g)

	// Source still serves (nothing ever moved).
	write := func(s string) { io.WriteString(local.inW, s+"\n") }
	write(`{"jsonrpc":"2.0","id":9,"method":"incr"}`)
	if c := waitResp(t, ch, 9); c != 2 {
		t.Fatalf("source incr after abort = %d, want 2", c)
	}
}

// TestMoveAbort_PreCommit: aborting after the source froze (final checkpoint @G,
// lease retained) leaves the source resumable; the client resumes on A.
func TestMoveAbort_PreCommit(t *testing.T) {
	store := NewMemStore()
	source, addrA, stopA := startMoveServer(t, store, statefulFactory(nil), MigrateBackend)
	dest, _, stopB := startMoveServer(t, store, statefulFactory(nil), MigrateBackend)
	defer stopA()
	defer stopB()

	d := &switchDialer{addr: addrA}
	id, ch, local, cancel := establishBackendSession(t, source, d)
	defer cancel()
	defer local.Close()
	g := sessionGen(source, id)

	if err := dest.PrepareMove(loadPS(t, store, id), moveCreatorMeta); err != nil {
		t.Fatalf("PrepareMove: %v", err)
	}
	if err := source.FreezeForMove(id); err != nil {
		t.Fatalf("FreezeForMove: %v", err)
	}
	// Freeze retains the lease at G (quiesce != release).
	assertOwner(t, store, id, source.instance, g)
	if ok, _ := store.SaveIfOwned(PersistedSession{ID: id}, source.instance, g); !ok {
		t.Fatal("source must still own its lease after freeze (not fenced)")
	}

	// Abort both sides.
	dest.AbortMove(id)
	source.ThawForMove(id)
	if dest.warmingCount() != 0 {
		t.Fatalf("dest warming=%d after abort, want 0", dest.warmingCount())
	}
	assertOwner(t, store, id, source.instance, g)

	// The client (detached by freeze) reattaches to A and is served again.
	write := func(s string) { io.WriteString(local.inW, s+"\n") }
	write(`{"jsonrpc":"2.0","id":9,"method":"incr"}`)
	if c := waitResp(t, ch, 9); c != 2 {
		t.Fatalf("source incr after thaw = %d, want 2", c)
	}
}

// TestMoveAbort_ControlConnDrop: a control-connection drop before COMMITTED is an
// implicit abort (ServeMoveControl's defer), discarding the warm state.
func TestMoveAbort_ControlConnDrop(t *testing.T) {
	store := NewMemStore()
	source, addrA, stopA := startMoveServer(t, store, statefulFactory(nil), MigrateBackend)
	dest, _, stopB := startMoveServer(t, store, statefulFactory(nil), MigrateBackend)
	defer stopA()
	defer stopB()

	d := &switchDialer{addr: addrA}
	id, _, local, cancel := establishBackendSession(t, source, d)
	defer cancel()
	defer local.Close()
	g := sessionGen(source, id)

	srcConn, dstConn := net.Pipe()
	mvErr := make(chan error, 1)
	go func() { mvErr <- dest.ServeMoveControl(dstConn, denyAll) }()

	w := bufio.NewWriter(srcConn)
	r := bufio.NewReaderSize(srcConn, maxMoveFrameBytes+64)
	ps := loadPS(t, store, id)
	if err := writeMoveFrame(w, moveFrame{Type: moveKindPrepare, SessionID: id, Gen: g, Mode: int(MigrateBackend), CreatorKey: ps.CreatorKey}); err != nil {
		t.Fatalf("write prepare: %v", err)
	}
	ready, err := readMoveFrame(r)
	if err != nil || ready.Type != moveKindReady || !ready.OK {
		t.Fatalf("expected READY, got %+v err=%v", ready, err)
	}
	if dest.warmingCount() != 1 {
		t.Fatalf("dest warming=%d after prepare, want 1", dest.warmingCount())
	}

	// Drop the control connection: the destination must abort the warm state.
	srcConn.Close()
	if err := <-mvErr; err == nil {
		t.Fatal("ServeMoveControl should return the control-conn read error")
	}
	if dest.warmingCount() != 0 {
		t.Fatalf("dest warming=%d after control drop, want 0 (implicit abort)", dest.warmingCount())
	}
	assertOwner(t, store, id, source.instance, g)
}

// ============================ crash-recovery matrix ============================

// Each subtest injects a "crash" at a distinct point of the move (by abandoning
// the relevant side's remaining steps) and asserts the store has EXACTLY one
// resumable owner, recoverable by a driven reattach. Deterministic under
// -count=20: no sleeps, all ordering via awaited responses / synchronous calls.

// Row: crash at prepare (dest warming, no lease) -> SOURCE resumable.
func TestMoveCrash_AtPrepare(t *testing.T) {
	store := NewMemStore()
	source, addrA, stopA := startMoveServer(t, store, statefulFactory(nil), MigrateBackend)
	dest, _, stopB := startMoveServer(t, store, statefulFactory(nil), MigrateBackend)
	defer stopA()
	defer stopB()

	d := &switchDialer{addr: addrA}
	id, ch, local, cancel := establishBackendSession(t, source, d)
	defer cancel()
	defer local.Close()
	g := sessionGen(source, id)

	if err := dest.PrepareMove(loadPS(t, store, id), moveCreatorMeta); err != nil {
		t.Fatalf("PrepareMove: %v", err)
	}
	// "Crash" the destination: its warm entry is in-memory only and simply
	// vanishes. Nothing durable was written.
	assertOwner(t, store, id, source.instance, g)
	if ok, _ := store.SaveIfOwned(PersistedSession{ID: id, CreatorKey: moveCreatorMeta.PeerKey}, source.instance, g); !ok {
		t.Fatal("source must remain able to write @G after a prepare-time dest crash")
	}
	// Source is the sole resumable owner and keeps serving.
	write := func(s string) { io.WriteString(local.inW, s+"\n") }
	write(`{"jsonrpc":"2.0","id":9,"method":"incr"}`)
	if c := waitResp(t, ch, 9); c != 2 {
		t.Fatalf("source incr after dest prepare-crash = %d, want 2", c)
	}
}

// Row: crash after ready (dest warm + confirmed, still no lease) -> SOURCE. A
// fresh destination process starts with an empty warming map (in-memory), so the
// aborted warm leaves no trace and the source is untouched.
func TestMoveCrash_AfterReady(t *testing.T) {
	store := NewMemStore()
	source, addrA, stopA := startMoveServer(t, store, statefulFactory(nil), MigrateBackend)
	dest, _, stopB := startMoveServer(t, store, statefulFactory(nil), MigrateBackend)
	defer stopA()
	defer stopB()

	d := &switchDialer{addr: addrA}
	id, ch, local, cancel := establishBackendSession(t, source, d)
	defer cancel()
	defer local.Close()
	g := sessionGen(source, id)

	if err := dest.PrepareMove(loadPS(t, store, id), moveCreatorMeta); err != nil {
		t.Fatalf("PrepareMove: %v", err)
	}
	// READY was implicitly returned (PrepareMove succeeded). Crash dest now.
	assertOwner(t, store, id, source.instance, g)

	// A restarted destination process (fresh warming map) knows nothing durable.
	dest2, _, stopB2 := startMoveServer(t, store, statefulFactory(nil), MigrateBackend)
	defer stopB2()
	if dest2.warmingCount() != 0 {
		t.Fatalf("restarted dest warming=%d, want 0", dest2.warmingCount())
	}
	assertOwner(t, store, id, source.instance, g)

	write := func(s string) { io.WriteString(local.inW, s+"\n") }
	write(`{"jsonrpc":"2.0","id":9,"method":"incr"}`)
	if c := waitResp(t, ch, 9); c != 2 {
		t.Fatalf("source incr after ready-crash = %d, want 2", c)
	}
}

// Row: crash before the commit CAS (source froze + final checkpoint @G, no CAS)
// -> SOURCE. The on-disk @G payload is a clean resumable checkpoint that a fresh
// gateway takes over via the creator-reattach path (TakeoverLease @G).
func TestMoveCrash_PreCommit(t *testing.T) {
	store := NewMemStore()
	source, addrA, stopA := startMoveServer(t, store, statefulFactory(nil), MigrateBackend)
	dest, _, stopB := startMoveServer(t, store, statefulFactory(nil), MigrateBackend)
	defer stopB()

	d := &switchDialer{addr: addrA}
	id, ch, local, cancel := establishBackendSession(t, source, d)
	defer cancel()
	defer local.Close()
	g := sessionGen(source, id)

	// Park the client so the freeze's detach cannot immediately re-bind it to the
	// still-alive source before we model the source crash.
	d.failoverTo(deadAddress(t))
	if err := dest.PrepareMove(loadPS(t, store, id), moveCreatorMeta); err != nil {
		t.Fatalf("PrepareMove: %v", err)
	}
	if err := source.FreezeForMove(id); err != nil {
		t.Fatalf("FreezeForMove: %v", err)
	}
	// Crash before COMMIT: the lease never moved (quiesce != release).
	assertOwner(t, store, id, source.instance, g)
	stopA() // the source gateway dies; its in-memory freeze is lost, @G payload persists

	// Recovery: a fresh gateway rehydrates the clean @G checkpoint via the client
	// reattach path (creator TakeoverLease @G -> G+1).
	rec, addrRec, stopRec := startMoveServer(t, store, statefulFactory(nil), MigrateBackend)
	defer stopRec()
	d.failoverTo(addrRec)
	write := func(s string) { io.WriteString(local.inW, s+"\n") }
	write(`{"jsonrpc":"2.0","id":9,"method":"incr"}`)
	if c := waitResp(t, ch, 9); c != 2 {
		t.Fatalf("incr after pre-commit crash recovery = %d, want 2", c)
	}
	// The recovery gateway took over at G+1; the source is fenced.
	assertOwner(t, store, id, rec.instance, g+1)
	assertFenced(t, store, id, source.instance, g)
}

// Row: mid-commit (the swap) -> EXACTLY one. TakeoverLease is ONE CAS with no
// in-between: after commit the store shows dest@G+1 and the source is fenced.
func TestMoveCrash_MidCommit(t *testing.T) {
	store := NewMemStore()
	source, addrA, stopA := startMoveServer(t, store, statefulFactory(nil), MigrateBackend)
	dest, _, stopB := startMoveServer(t, store, statefulFactory(nil), MigrateBackend)
	defer stopA()
	defer stopB()

	d := &switchDialer{addr: addrA}
	id, _, local, cancel := establishBackendSession(t, source, d)
	defer cancel()
	defer local.Close()
	g := sessionGen(source, id)
	d.failoverTo(deadAddress(t))

	if err := dest.PrepareMove(loadPS(t, store, id), moveCreatorMeta); err != nil {
		t.Fatalf("PrepareMove: %v", err)
	}
	if err := source.FreezeForMove(id); err != nil {
		t.Fatalf("FreezeForMove: %v", err)
	}
	ok, err := dest.CommitMove(id, func() (bool, error) { return true, nil })
	if err != nil || !ok {
		t.Fatalf("CommitMove: ok=%v err=%v", ok, err)
	}
	// The single CAS committed: dest owns @G+1, source fenced. No two-owner state
	// is observable because the swap is one store operation.
	assertOwner(t, store, id, dest.instance, g+1)
	assertFenced(t, store, id, source.instance, g)
}

// Row: crash after the CAS, before promote/checkpoint -> DEST. The store already
// shows owner=dest@G+1 carrying the source's final @G payload, recoverable by a
// creator reattach TakeoverLease(G+1). Modeled by performing only the bare CAS.
func TestMoveCrash_AfterCASBeforePromote(t *testing.T) {
	store := NewMemStore()
	source, addrA, stopA := startMoveServer(t, store, statefulFactory(nil), MigrateBackend)
	dest, _, stopB := startMoveServer(t, store, statefulFactory(nil), MigrateBackend)
	defer stopA()
	defer stopB()

	d := &switchDialer{addr: addrA}
	id, ch, local, cancel := establishBackendSession(t, source, d)
	defer cancel()
	defer local.Close()
	g := sessionGen(source, id)
	d.failoverTo(deadAddress(t))

	// Prepare + freeze, then perform ONLY the ownership CAS (as if the destination
	// crashed the instant after it, before registerResumed's promote/checkpoint).
	if err := dest.PrepareMove(loadPS(t, store, id), moveCreatorMeta); err != nil {
		t.Fatalf("PrepareMove: %v", err)
	}
	if err := source.FreezeForMove(id); err != nil {
		t.Fatalf("FreezeForMove: %v", err)
	}
	lease, ok, err := store.TakeoverLease(id, dest.instance, g, 2*time.Minute, time.Now())
	if err != nil || !ok {
		t.Fatalf("bare CAS: ok=%v err=%v", ok, err)
	}
	if lease.Generation != g+1 {
		t.Fatalf("CAS generation = %d, want %d", lease.Generation, g+1)
	}
	// Store: owner=dest@G+1 with the source's resumable payload; source fenced.
	assertOwner(t, store, id, dest.instance, g+1)
	assertFenced(t, store, id, source.instance, g)
	ps := loadPS(t, store, id)
	if ps.CreatorKey != moveCreatorMeta.PeerKey {
		t.Fatalf("post-CAS payload lost creator identity: %q", ps.CreatorKey)
	}

	// Recovery: a fresh gateway rehydrates owner=dest@G+1 via creator reattach
	// (TakeoverLease(G+1) -> G+2). Exactly one resumable owner survived.
	rec, addrRec, stopRec := startMoveServer(t, store, statefulFactory(nil), MigrateBackend)
	defer stopRec()
	d.failoverTo(addrRec)
	write := func(s string) { io.WriteString(local.inW, s+"\n") }
	write(`{"jsonrpc":"2.0","id":9,"method":"incr"}`)
	if c := waitResp(t, ch, 9); c != 2 {
		t.Fatalf("incr after after-CAS crash recovery = %d, want 2", c)
	}
	assertOwner(t, store, id, rec.instance, g+2)
}

// Row: crash after commit (dest owns @G+1 and is warm) -> DEST, and if that dest
// then crashes, its @G+1 checkpoint recovers via normal crash-failover.
func TestMoveCrash_PostCommit(t *testing.T) {
	store := NewMemStore()
	source, addrA, stopA := startMoveServer(t, store, statefulFactory(nil), MigrateBackend)
	dest, _, stopB := startMoveServer(t, store, statefulFactory(nil), MigrateBackend)
	defer stopA()
	defer stopB()

	d := &switchDialer{addr: addrA}
	id, ch, local, cancel := establishBackendSession(t, source, d)
	defer cancel()
	defer local.Close()
	g := sessionGen(source, id)
	d.failoverTo(deadAddress(t))
	runMove(t, source, dest, id)
	assertOwner(t, store, id, dest.instance, g+1)

	// Now crash the destination that owns the moved session and fail over to a
	// third gateway: the @G+1 checkpoint written at promote recovers it.
	stopB()
	rec, addrRec, stopRec := startMoveServer(t, store, statefulFactory(nil), MigrateBackend)
	defer stopRec()
	d.failoverTo(addrRec)
	write := func(s string) { io.WriteString(local.inW, s+"\n") }
	write(`{"jsonrpc":"2.0","id":3,"method":"incr"}`)
	if c := waitResp(t, ch, 3); c != 2 {
		t.Fatalf("incr after post-commit dest crash recovery = %d, want 2", c)
	}
	assertOwner(t, store, id, rec.instance, g+2)
	assertFenced(t, store, id, dest.instance, g+1)
}

// Row: destination crash mid-prepare (dies while warming, before READY) ->
// SOURCE. A failed/partial prepare writes nothing durable; a restarted dest is
// clean and the source is untouched.
func TestMoveCrash_DestMidPrepare(t *testing.T) {
	store := NewMemStore()
	source, addrA, stopA := startMoveServer(t, store, statefulFactory(nil), MigrateBackend)
	dest, _, stopB := startMoveServer(t, store, statefulFactory(nil), MigrateBackend)
	defer stopA()
	defer stopB()

	d := &switchDialer{addr: addrA}
	id, ch, local, cancel := establishBackendSession(t, source, d)
	defer cancel()
	defer local.Close()
	g := sessionGen(source, id)

	// Crash inside prepare, right after the warm backend is spawned but before the
	// warming entry would be used, via the onWarmReady hook.
	dest.moveHooks.onWarmReady = func(string) {
		// The destination process dies here. Nothing durable was written; the
		// in-memory warm entry is abandoned.
		panic("dest-mid-prepare-crash")
	}
	func() {
		defer func() { _ = recover() }() // absorb the simulated crash
		_ = dest.PrepareMove(loadPS(t, store, id), moveCreatorMeta)
	}()
	dest.moveHooks.onWarmReady = nil

	assertOwner(t, store, id, source.instance, g)
	if ok, _ := store.SaveIfOwned(PersistedSession{ID: id, CreatorKey: moveCreatorMeta.PeerKey}, source.instance, g); !ok {
		t.Fatal("source must remain writable @G after a mid-prepare dest crash")
	}
	write := func(s string) { io.WriteString(local.inW, s+"\n") }
	write(`{"jsonrpc":"2.0","id":9,"method":"incr"}`)
	if c := waitResp(t, ch, 9); c != 2 {
		t.Fatalf("source incr after mid-prepare crash = %d, want 2", c)
	}
	// A real dest crash abandons the in-memory warm backend; discard it here so
	// -count runs do not accumulate its goroutine (assertions already ran).
	dest.AbortMove(id)
}

// ============================ idempotence & refusals ============================

// TestMoveIdempotentCommit: a second commit after success is a no-op success.
func TestMoveIdempotentCommit(t *testing.T) {
	store := NewMemStore()
	source, addrA, stopA := startMoveServer(t, store, statefulFactory(nil), MigrateBackend)
	dest, _, stopB := startMoveServer(t, store, statefulFactory(nil), MigrateBackend)
	defer stopA()
	defer stopB()

	d := &switchDialer{addr: addrA}
	id, _, local, cancel := establishBackendSession(t, source, d)
	defer cancel()
	defer local.Close()
	g := sessionGen(source, id)
	d.failoverTo(deadAddress(t))

	if err := dest.PrepareMove(loadPS(t, store, id), moveCreatorMeta); err != nil {
		t.Fatalf("PrepareMove: %v", err)
	}
	if err := source.FreezeForMove(id); err != nil {
		t.Fatalf("FreezeForMove: %v", err)
	}
	grant := onceGrant()
	if ok, err := dest.CommitMove(id, grant); err != nil || !ok {
		t.Fatalf("first commit: ok=%v err=%v", ok, err)
	}
	// Second commit: warm gone, session live -> idempotent success, no second swap.
	if ok, err := dest.CommitMove(id, grant); err != nil || !ok {
		t.Fatalf("second (idempotent) commit: ok=%v err=%v", ok, err)
	}
	assertOwner(t, store, id, dest.instance, g+1)
	if dest.Count() != 1 {
		t.Fatalf("dest holds %d sessions after idempotent commit, want 1", dest.Count())
	}
}

// TestMoveRefusesUnauthorized: a commit whose authorization gate denies (or is
// nil) is refused and the warm state discarded; the source keeps ownership.
func TestMoveRefusesUnauthorized(t *testing.T) {
	store := NewMemStore()
	source, addrA, stopA := startMoveServer(t, store, statefulFactory(nil), MigrateBackend)
	dest, _, stopB := startMoveServer(t, store, statefulFactory(nil), MigrateBackend)
	defer stopA()
	defer stopB()

	d := &switchDialer{addr: addrA}
	id, _, local, cancel := establishBackendSession(t, source, d)
	defer cancel()
	defer local.Close()
	g := sessionGen(source, id)
	d.failoverTo(deadAddress(t))

	if err := dest.PrepareMove(loadPS(t, store, id), moveCreatorMeta); err != nil {
		t.Fatalf("PrepareMove: %v", err)
	}
	if err := source.FreezeForMove(id); err != nil {
		t.Fatalf("FreezeForMove: %v", err)
	}
	if ok, err := dest.CommitMove(id, func() (bool, error) { return false, nil }); ok || err != errMoveUnauthorized {
		t.Fatalf("denied commit: ok=%v err=%v, want false/errMoveUnauthorized", ok, err)
	}
	if dest.warmingCount() != 0 {
		t.Fatalf("warming=%d after refused commit, want 0 (discarded)", dest.warmingCount())
	}
	assertOwner(t, store, id, source.instance, g)

	// A nil authorization gate is also deny-by-default.
	if err := dest.PrepareMove(loadPS(t, store, id), moveCreatorMeta); err != nil {
		t.Fatalf("re-PrepareMove: %v", err)
	}
	if ok, err := dest.CommitMove(id, nil); ok || err != errMoveUnauthorized {
		t.Fatalf("nil-authorize commit: ok=%v err=%v, want false/errMoveUnauthorized", ok, err)
	}
	assertOwner(t, store, id, source.instance, g)
}

// TestMoveRefusesMode: MigrateFull (and, by the same gate, no-checkpoint stateful
// backends) cannot be moved in v1 — prepare refuses.
func TestMoveRefusesMode(t *testing.T) {
	store := NewMemStore()
	dest := NewServer(statefulFactory(nil), 2*time.Minute, nil).WithStore(store, MigrateFull)
	ps := PersistedSession{ID: "00112233445566778899aabbccddeeff", CreatorKey: moveCreatorMeta.PeerKey, Generation: 3}
	if err := dest.PrepareMove(ps, moveCreatorMeta); err != errMoveModeUnsupported {
		t.Fatalf("PrepareMove(MigrateFull) err=%v, want errMoveModeUnsupported", err)
	}
}

// TestMoveRefusesDegraded: a session that never held a fencing lease (generation
// 0) is unfenceable, so a move is refused (it could split-brain).
func TestMoveRefusesDegraded(t *testing.T) {
	store := NewMemStore()
	dest := NewServer(statefulFactory(nil), 2*time.Minute, nil).WithStore(store, MigrateBackend)
	ps := PersistedSession{ID: "00112233445566778899aabbccddeeff", CreatorKey: moveCreatorMeta.PeerKey, Generation: 0}
	if err := dest.PrepareMove(ps, moveCreatorMeta); err != errMoveDegraded {
		t.Fatalf("PrepareMove(gen 0) err=%v, want errMoveDegraded", err)
	}
}

// ============================ concurrent-commit safety ============================

// TestMoveConcurrentCommit_NoDataLoss proves that a second, duplicate CommitMove
// for the same warm session (an operator retry, or a double-fired gateway trigger)
// can never erase the just-committed session. The second commit is injected at the
// most dangerous instant — after the first commit's CAS has won (store=dest@G+1)
// but before it has promoted the warm backend — via the onAfterCAS hook. Because
// CommitMove atomically CLAIMS the warm entry, the second commit finds nothing to
// promote and cannot close the backend the first commit is about to serve; without
// the claim it would (its authorize-loser discard) close that backend, whose pump
// failure would DeleteIfOwner the fresh record and strand the session with zero
// owners. Deterministic, no sleeps.
func TestMoveConcurrentCommit_NoDataLoss(t *testing.T) {
	store := NewMemStore()
	source, addrA, stopA := startMoveServer(t, store, statefulFactory(nil), MigrateBackend)
	dest, addrB, stopB := startMoveServer(t, store, statefulFactory(nil), MigrateBackend)
	defer stopA()
	defer stopB()

	d := &switchDialer{addr: addrA}
	id, ch, local, cancel := establishBackendSession(t, source, d)
	defer cancel()
	defer local.Close()
	g := sessionGen(source, id)
	d.failoverTo(deadAddress(t))

	if err := dest.PrepareMove(loadPS(t, store, id), moveCreatorMeta); err != nil {
		t.Fatalf("PrepareMove: %v", err)
	}
	if err := source.FreezeForMove(id); err != nil {
		t.Fatalf("FreezeForMove: %v", err)
	}

	// One shared single-use grant: exactly one commit can authorize (the real
	// production configuration, which is what makes the loser take the discard
	// path in the unfixed code).
	grant := onceGrant()
	var secondRan bool
	var secondErr error
	dest.moveHooks.onAfterCAS = func(string) {
		dest.moveHooks.onAfterCAS = nil // fire once; injected commit must not re-enter here
		// The first commit has won the CAS but not yet promoted. Inject the
		// duplicate commit right here (same goroutine — synchronous, deterministic).
		_, secondErr = dest.CommitMove(id, grant)
		secondRan = true
	}

	ok, err := dest.CommitMove(id, grant)
	if err != nil || !ok {
		t.Fatalf("winning commit: ok=%v err=%v", ok, err)
	}
	if !secondRan {
		t.Fatal("duplicate commit was not injected (onAfterCAS did not fire)")
	}
	// The duplicate commit must be a safe no-op: it found the entry already claimed
	// (errMoveNotWarming) or, had the promote already landed, idempotent success —
	// never a second swap, never a discard of the winner's backend.
	if secondErr != nil && secondErr != errMoveNotWarming {
		t.Fatalf("duplicate commit err=%v, want nil or errMoveNotWarming", secondErr)
	}

	// Exactly one owner survived: dest@G+1, source fenced, session NOT erased.
	assertOwner(t, store, id, dest.instance, g+1)
	assertFenced(t, store, id, source.instance, g)
	if dest.Count() != 1 {
		t.Fatalf("dest holds %d sessions after duplicate commit, want 1 (not erased)", dest.Count())
	}
	if dest.warmingCount() != 0 {
		t.Fatalf("dest warming=%d after commit, want 0", dest.warmingCount())
	}

	// And the moved session is live on the promoted warm backend: the client
	// reattaches to B and its state is continuous (count 1 -> 2).
	d.failoverTo(addrB)
	write := func(s string) { io.WriteString(local.inW, s+"\n") }
	write(`{"jsonrpc":"2.0","id":3,"method":"incr"}`)
	if c := waitResp(t, ch, 3); c != 2 {
		t.Fatalf("incr after duplicate-commit move = %d, want 2", c)
	}
}

// TestMoveCommitAfterReattach_NoLeak proves the warm-window reattach race is safe:
// if the creator reattaches to the destination while it is only warm, the reattach
// rehydrates a live session (its own CAS, G->G+1); a subsequent CommitMove for the
// same session is then an idempotent no-op that discards the orphaned warm backend
// and does NOT consume the single-use grant (so a genuine later authorization is
// still possible), and it never performs a second swap.
func TestMoveCommitAfterReattach_NoLeak(t *testing.T) {
	store := NewMemStore()
	source, addrA, stopA := startMoveServer(t, store, statefulFactory(nil), MigrateBackend)
	dest, _, stopB := startMoveServer(t, store, statefulFactory(nil), MigrateBackend)
	defer stopA()
	defer stopB()

	d := &switchDialer{addr: addrA}
	id, _, local, cancel := establishBackendSession(t, source, d)
	defer cancel()
	defer local.Close()
	g := sessionGen(source, id)

	if err := dest.PrepareMove(loadPS(t, store, id), moveCreatorMeta); err != nil {
		t.Fatalf("PrepareMove: %v", err)
	}
	if dest.warmingCount() != 1 {
		t.Fatalf("warming=%d after prepare, want 1", dest.warmingCount())
	}

	// The creator reattaches to the destination DURING the warm window: attach
	// takes the store path and rehydrates a separate live session at G+1.
	sid, _ := parseSessionID(id)
	defer dest.remove(sid) // tear down the rehydrated live session (goroutine hygiene)
	sess, resumed, err := dest.attach(sid, moveCreatorMeta)
	if err != nil || !resumed || sess == nil {
		t.Fatalf("warm-window reattach: resumed=%v err=%v", resumed, err)
	}
	if dest.Count() != 1 {
		t.Fatalf("dest live=%d after warm-window reattach, want 1", dest.Count())
	}
	assertOwner(t, store, id, dest.instance, g+1)

	// A single-use grant that records whether it was consumed.
	consumed := 0
	grant := func() (bool, error) { consumed++; return true, nil }

	// CommitMove finds the session already live here: idempotent success, orphaned
	// warm backend discarded, grant NOT consumed, no second swap.
	ok, err := dest.CommitMove(id, grant)
	if err != nil || !ok {
		t.Fatalf("idempotent commit after reattach: ok=%v err=%v", ok, err)
	}
	if consumed != 0 {
		t.Fatalf("grant consumed %d times, want 0 (session already live; no authorization needed)", consumed)
	}
	if dest.warmingCount() != 0 {
		t.Fatalf("warming=%d after commit, want 0 (orphan discarded)", dest.warmingCount())
	}
	if dest.Count() != 1 {
		t.Fatalf("dest live=%d after commit, want 1 (no second session)", dest.Count())
	}
	assertOwner(t, store, id, dest.instance, g+1) // still G+1: no second ownership swap
}
