package session

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"testing"
	"time"
)

// The backend's own "EventStore": per-session state keyed by session id,
// which a freshly spawned backend on another gateway restores from.
var (
	stMu       sync.Mutex
	stCounters = map[string]int{}
)

func incrCounter(id string) int {
	stMu.Lock()
	defer stMu.Unlock()
	stCounters[id]++
	return stCounters[id]
}

// statefulBackend has per-session state (a counter) that it persists to and
// restores from its own store, keyed by MESHMCP_SESSION_ID. It requires no
// handshake replay to resume — it reconstructs itself from the id.
type statefulBackend struct {
	inR  *io.PipeReader
	inW  *io.PipeWriter
	outR *io.PipeReader
	outW *io.PipeWriter
}

func newStatefulBackend(id string) *statefulBackend {
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	b := &statefulBackend{inR, inW, outR, outW}
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
				fmt.Fprintf(outW, `{"jsonrpc":"2.0","id":%d,"result":{"count":%d}}`+"\n", *m.ID, incrCounter(id))
			}
		}
		outW.Close()
	}()
	return b
}

func (b *statefulBackend) Read(p []byte) (int, error)  { return b.outR.Read(p) }
func (b *statefulBackend) Write(p []byte) (int, error) { return b.inW.Write(p) }
func (b *statefulBackend) Close() error                { b.inW.Close(); b.outW.Close(); return nil }

// TestBackendManagedMigration verifies MigrateBackend mode: a stateful
// backend survives a gateway crash by restoring its own per-session state
// from MESHMCP_SESSION_ID — no handshake/log replay by meshmcp.
func TestBackendManagedMigration(t *testing.T) {
	store := NewMemStore()
	factory := func(meta Meta) (Backend, error) { return newStatefulBackend(meta.SessionID), nil }
	addr1, stop1 := startSessionServer(t, store, factory, MigrateBackend)
	addr2, stop2 := startSessionServer(t, store, factory, MigrateBackend)
	defer stop2()

	d := &switchDialer{addr: addr1}
	local := newLocalEnd()
	client := NewClient(d.dial, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = client.Run(ctx, local) }()

	counts := make(chan struct{ id, count int }, 16)
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
				counts <- struct{ id, count int }{*r.ID, r.Result.Count}
			}
		}
	}()
	write := func(s string) { io.WriteString(local.inW, s+"\n") }
	waitCount := func(id int) int {
		deadline := time.After(10 * time.Second)
		for {
			select {
			case c := <-counts:
				if c.id == id {
					return c.count
				}
			case <-deadline:
				t.Fatalf("timed out waiting for id %d", id)
			}
		}
	}

	write(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
	waitCount(1)
	time.Sleep(50 * time.Millisecond)
	write(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	time.Sleep(50 * time.Millisecond)
	write(`{"jsonrpc":"2.0","id":2,"method":"incr"}`)
	if got := waitCount(2); got != 1 {
		t.Fatalf("first incr = %d, want 1", got)
	}
	write(`{"jsonrpc":"2.0","id":3,"method":"incr"}`)
	if got := waitCount(3); got != 2 {
		t.Fatalf("second incr = %d, want 2", got)
	}

	// Crash gateway 1 and fail over to gateway 2.
	time.Sleep(200 * time.Millisecond)
	stop1()
	d.failoverTo(addr2)

	// The fresh backend on gateway 2 restored its counter (2) from the
	// session id, so the next incr is 3 — state survived without replay.
	write(`{"jsonrpc":"2.0","id":4,"method":"incr"}`)
	if got := waitCount(4); got != 3 {
		t.Fatalf("incr after failover = %d, want 3 (stateful backend restored)", got)
	}

	local.Close()
}
