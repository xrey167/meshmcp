package storetest

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/xrey167/meshmcp/session"
)

// RunSessionMigration proves the end-to-end failover contract against any
// SessionStore backend: a session served by gateway 1 survives that gateway
// "crashing" — the client reattaches to gateway 2, which rehydrates the
// session from the shared store, takes over the ownership lease, and keeps
// serving it. This is the public-API twin of the in-package
// TestSessionMigratesAcrossGateways (session/migration_test.go), extracted so
// external store backends (pgstore, future etcd/redis) can prove the same
// server-level flow the in-memory test proves, not just the store-level CAS
// contract.
func RunSessionMigration(t *testing.T, open func(t *testing.T) session.SessionStore) {
	store := open(t)
	factory := func(session.Meta) (session.Backend, error) { return newEchoBackend(), nil }
	addr1, stop1 := startServer(t, "gw1", store, factory)
	addr2, stop2 := startServer(t, "gw2", store, factory)
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

	// Handshake + a request on gateway 1. Small pauses keep each message a
	// separate transport frame so the captured handshake is init+initialized
	// only (not the later ping).
	write(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
	waitFor(1)
	time.Sleep(50 * time.Millisecond)
	write(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	time.Sleep(50 * time.Millisecond)
	write(`{"jsonrpc":"2.0","id":2,"method":"ping"}`)
	waitFor(2)

	// Let gateway 1 checkpoint, then "crash" it and fail over to gateway 2,
	// which must rehydrate from the store and take over the lease.
	time.Sleep(200 * time.Millisecond)
	stop1()
	d.failoverTo(addr2)

	write(`{"jsonrpc":"2.0","id":3,"method":"after-failover"}`)
	waitFor(3)

	local.Close()
}

// echoBackend is a stateless MCP-ish backend: it replies to initialize once
// and echoes every other id-bearing request — the "stateless backend"
// contract that makes handshake-replay migration safe.
type echoBackend struct {
	inR  *io.PipeReader
	inW  *io.PipeWriter
	outR *io.PipeReader
	outW *io.PipeWriter
}

func newEchoBackend() *echoBackend {
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	b := &echoBackend{inR, inW, outR, outW}
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
				continue // notification
			}
			if m.Method == "initialize" {
				fmt.Fprintf(outW, `{"jsonrpc":"2.0","id":%d,"result":{"init":true}}`+"\n", *m.ID)
			} else {
				fmt.Fprintf(outW, `{"jsonrpc":"2.0","id":%d,"result":{"echo":%q}}`+"\n", *m.ID, m.Method)
			}
		}
		outW.Close()
	}()
	return b
}

func (b *echoBackend) Read(p []byte) (int, error)  { return b.outR.Read(p) }
func (b *echoBackend) Write(p []byte) (int, error) { return b.inW.Write(p) }
func (b *echoBackend) Close() error                { b.inW.Close(); b.outW.Close(); return nil }

// failoverDialer dials the currently-active gateway and can sever the live
// connection to force the client to reconnect (to the new gateway).
type failoverDialer struct {
	mu   sync.Mutex
	addr string
	live net.Conn
}

func (d *failoverDialer) dial(ctx context.Context) (net.Conn, error) {
	d.mu.Lock()
	addr := d.addr
	d.mu.Unlock()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	d.mu.Lock()
	d.live = c
	d.mu.Unlock()
	return c, nil
}

func (d *failoverDialer) failoverTo(addr string) {
	d.mu.Lock()
	d.addr = addr
	c := d.live
	d.mu.Unlock()
	if c != nil {
		c.Close() // sever the connection to the dead gateway
	}
}

func startServer(t *testing.T, name string, store session.SessionStore, factory session.BackendFactory) (string, func()) {
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
			go srv.Handle(c, session.Meta{PeerFQDN: "storetest"})
		}
	}()
	return ln.Addr().String(), func() { ln.Close() }
}

// pipeEnd is the client-local io.ReadWriteCloser end of the session.
type pipeEnd struct {
	in   *io.PipeReader // Run reads from here (our writes)
	inW  *io.PipeWriter
	out  *io.PipeWriter // Run writes here (our reads)
	outR *io.PipeReader
}

func newPipeEnd() *pipeEnd {
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	return &pipeEnd{in: inR, inW: inW, out: outW, outR: outR}
}

func (l *pipeEnd) Read(p []byte) (int, error)  { return l.in.Read(p) }
func (l *pipeEnd) Write(p []byte) (int, error) { return l.out.Write(p) }
func (l *pipeEnd) Close() error                { l.inW.Close(); l.out.Close(); return nil }
