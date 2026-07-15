package session

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
)

// migBackend is a stateless MCP-ish backend: it replies to initialize once
// and echoes every other id-bearing request. This is the "stateless
// backend" contract that makes session migration safe.
type migBackend struct {
	inR  *io.PipeReader
	inW  *io.PipeWriter
	outR *io.PipeReader
	outW *io.PipeWriter
}

func newMigBackend() *migBackend {
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	b := &migBackend{inR, inW, outR, outW}
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

func (b *migBackend) Read(p []byte) (int, error)  { return b.outR.Read(p) }
func (b *migBackend) Write(p []byte) (int, error) { return b.inW.Write(p) }
func (b *migBackend) Close() error                { b.inW.Close(); b.outW.Close(); return nil }

// switchDialer dials the currently-active gateway and can sever the live
// connection to force the client to reconnect (to the new gateway).
type switchDialer struct {
	mu   sync.Mutex
	addr string
	live net.Conn
}

func (d *switchDialer) dial(ctx context.Context) (net.Conn, error) {
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

func (d *switchDialer) failoverTo(addr string) {
	d.mu.Lock()
	d.addr = addr
	c := d.live
	d.mu.Unlock()
	if c != nil {
		c.Close() // sever the connection to the dead gateway
	}
}

func startSessionServer(t *testing.T, store SessionStore, factory BackendFactory, mode MigrationMode) (string, func()) {
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
	return ln.Addr().String(), func() { ln.Close() }
}

// TestSessionMigratesAcrossGateways runs a session on gateway 1, "crashes"
// it, and reattaches to gateway 2 — which rehydrates the session from the
// shared store and continues serving it.
func TestSessionMigratesAcrossGateways(t *testing.T) {
	store := NewMemStore()
	migFactory := func(Meta) (Backend, error) { return newMigBackend(), nil }
	addr1, stop1 := startSessionServer(t, store, migFactory, MigrateHandshake)
	addr2, stop2 := startSessionServer(t, store, migFactory, MigrateHandshake)
	defer stop2()

	d := &switchDialer{addr: addr1}
	local := newLocalEnd()
	client := NewClient(d.dial, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = client.Run(ctx, local) }()

	// Collect id-keyed responses from the client's local output.
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

	// Let gateway 1 checkpoint (on the ack of id 2), then "crash" it and fail
	// over to gateway 2.
	time.Sleep(200 * time.Millisecond)
	stop1()
	d.failoverTo(addr2)

	// A new request must be served by gateway 2 after it rehydrates the
	// session from the store.
	write(`{"jsonrpc":"2.0","id":3,"method":"after-failover"}`)
	waitFor(3)

	local.Close()
}
