package storetest

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"testing"
	"time"

	"github.com/xrey167/meshmcp/session"
)

// RunSessionLiveMove proves the v1-of-v2 live-session MOVE end to end against any
// LeaseStore backend: a session served by gateway 1 is deliberately relocated to
// gateway 2 via prepare -> ready -> commit (the source keeps serving until the
// single commit CAS), the client reattaches to gateway 2 on the pre-warmed
// backend, and gateway 1 is fenced at the store level. It is the public-API twin
// of RunSessionMigration (which proves the reactive crash-failover path); a new
// store backend runs both to prove it supports the reactive AND the deliberate
// ownership transfer. Requires a store that also implements session.LeaseStore
// (the CAS the commit swap rides on); a non-lease store is skipped.
func RunSessionLiveMove(t *testing.T, open func(t *testing.T) session.SessionStore) {
	store := open(t)
	ls, ok := store.(session.LeaseStore)
	if !ok {
		t.Skip("store has no CAS lease support; live move requires it")
	}
	factory := func(session.Meta) (session.Backend, error) { return newEchoBackend(), nil }
	// The creator identity both gateways see (identity binding needs a key).
	meta := session.Meta{PeerFQDN: "creator.mesh", PeerKey: "wg-creator-key", PeerAddr: "100.64.0.9:41641"}
	gw1, addr1, stop1 := startMoveServerPublic(t, "gw1", store, factory, meta)
	gw2, addr2, stop2 := startMoveServerPublic(t, "gw2", store, factory, meta)
	defer stop1()
	defer stop2()

	d := &failoverDialer{addr: addr1}
	local := newPipeEnd()
	client := session.NewClient(d.dial, func(format string, a ...any) { t.Logf("client: "+format, a...) })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = client.Run(ctx, local) }()

	got := make(chan int, 16)
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
	write := func(s string) { io.WriteString(local.inW, s+"\n") }
	waitFor := func(id int) {
		t.Helper()
		deadline := time.After(10 * time.Second)
		for {
			select {
			case g := <-got:
				if g == id {
					return
				}
			case <-deadline:
				t.Fatalf("timed out waiting for response id %d", id)
			}
		}
	}

	// Establish a session on gateway 1 (handshake kept in separate frames).
	write(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
	waitFor(1)
	time.Sleep(50 * time.Millisecond)
	write(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	time.Sleep(50 * time.Millisecond)
	write(`{"jsonrpc":"2.0","id":2,"method":"ping"}`)
	waitFor(2)
	time.Sleep(200 * time.Millisecond) // let gateway 1 checkpoint on the ack

	infos := gw1.Sessions()
	if len(infos) != 1 {
		t.Fatalf("gateway 1 should have exactly one session, has %d", len(infos))
	}
	id := infos[0].ID

	// Capture the store-observable owner/generation before the move.
	pre, ok, err := store.Load(id)
	if err != nil || !ok {
		t.Fatalf("load pre-move: ok=%v err=%v", ok, err)
	}
	preOwner, preGen := pre.Owner, pre.Generation

	// Park the client so it cannot re-serve on gateway 1 during the move; the
	// operator redirects it to gateway 2 only after commit.
	d.failoverTo(deadAddr(t))

	// Move gateway 1 -> gateway 2 over an in-process, identity-agnostic control
	// channel (production pins it to the destination key via exactPeerDial).
	srcConn, dstConn := net.Pipe()
	grant := onceGrant()
	mvErr := make(chan error, 1)
	go func() { mvErr <- gw2.ServeMoveControl(dstConn, func(string) (bool, error) { return grant() }) }()
	mctx, mcancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer mcancel()
	if err := gw1.MoveSessionTo(mctx, id, srcConn, "wg-destination-key"); err != nil {
		t.Fatalf("MoveSessionTo: %v", err)
	}
	if err := <-mvErr; err != nil {
		t.Fatalf("ServeMoveControl: %v", err)
	}

	// Store-observable ownership swap: a new owner at the next generation.
	post, ok, err := store.Load(id)
	if err != nil || !ok {
		t.Fatalf("load post-move: ok=%v err=%v", ok, err)
	}
	if post.Owner == preOwner || post.Generation != preGen+1 {
		t.Fatalf("ownership did not swap: pre owner=%q gen=%d, post owner=%q gen=%d",
			preOwner, preGen, post.Owner, post.Generation)
	}
	// Gateway 1 is fenced: its old lease can no longer write.
	if ok, _ := ls.SaveIfOwned(session.PersistedSession{ID: id}, preOwner, preGen); ok {
		t.Fatal("source gateway must be fenced after the move commit")
	}
	if gw1.Count() != 0 {
		t.Fatalf("source gateway still holds %d sessions after yielding", gw1.Count())
	}

	// The client reattaches to gateway 2 and is served by the pre-warmed backend.
	d.failoverTo(addr2)
	write(`{"jsonrpc":"2.0","id":3,"method":"after-move"}`)
	waitFor(3)

	local.Close()
}

// startMoveServerPublic is startServer's variant that returns the *Server so the
// caller can drive the move-control API (MoveSessionTo / ServeMoveControl). The
// accept loop uses a meta the caller sets via SetHandleMeta so both gateways see
// the same creator identity.
func startMoveServerPublic(t *testing.T, name string, store session.SessionStore, factory session.BackendFactory, meta session.Meta) (*session.Server, string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	logf := func(format string, a ...any) { t.Logf(name+": "+format, a...) }
	srv := session.NewServer(factory, 2*time.Minute, logf).WithStore(store, session.MigrateHandshake)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go srv.Handle(c, meta)
		}
	}()
	return srv, ln.Addr().String(), func() { ln.Close() }
}

// deadAddr returns an address with nothing listening, so a parked client's dials
// fail fast instead of re-serving on a gateway mid-move.
func deadAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

// onceGrant is a single-use authorization gate standing in for
// GrantStore.ConsumeOnceMatching at the store-conformance layer.
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
