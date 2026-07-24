package policy

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"sync"
	"testing"
	"time"
)

// echoBackend is an in-process MCP-ish server: for each request line with
// an id it replies with a result that names the tool (for tools/call) or
// {"ok":true}. It records every line it actually receives so the test can
// prove denied calls never reach it.
type echoBackend struct {
	toBackend  *io.PipeReader
	toBackendW *io.PipeWriter
	toCaller   *io.PipeReader
	toCallerW  *io.PipeWriter
	got        []string
}

func newEchoBackend() *echoBackend {
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	b := &echoBackend{toBackend: inR, toBackendW: inW, toCaller: outR, toCallerW: outW}
	go func() {
		sc := bufio.NewScanner(inR)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" {
				continue
			}
			b.got = append(b.got, line)
			var m rpcPeek
			_ = json.Unmarshal([]byte(line), &m)
			if len(m.ID) == 0 {
				continue // notification
			}
			if m.Method == "tools/call" {
				b.toCallerW.Write([]byte(`{"jsonrpc":"2.0","id":` + string(m.ID) + `,"result":{"tool":"` + m.Params.Name + `"}}` + "\n"))
			} else {
				b.toCallerW.Write([]byte(`{"jsonrpc":"2.0","id":` + string(m.ID) + `,"result":{"ok":true}}` + "\n"))
			}
		}
		b.toCallerW.Close()
	}()
	return b
}

func (b *echoBackend) Read(p []byte) (int, error)  { return b.toCaller.Read(p) }
func (b *echoBackend) Write(p []byte) (int, error) { return b.toBackendW.Write(p) }
func (b *echoBackend) Close() error                { b.toBackendW.Close(); b.toCallerW.Close(); return nil }

func TestFilterGovernsMethodsAndNotifications(t *testing.T) {
	backend := newEchoBackend()
	pol := &Policy{
		DefaultAllow: false,
		Rules: []Rule{
			{Peers: []string{"*"}, Methods: []string{"tasks/cancel"}, Allow: false},
			{Peers: []string{"*"}, Methods: []string{"notifications/roots/*"}, Allow: false},
		},
	}
	var auditBuf bytes.Buffer
	f := NewFilter(backend, Caller{Backend: "kg", Peer: "p.netbird.cloud"}, pol,
		NewAuditLog(&auditBuf, func() string { return "T" }), nil)

	replies := make(chan string, 8)
	go func() {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			replies <- sc.Text()
		}
		close(replies)
	}()
	write := func(s string) {
		if _, err := f.Write([]byte(s + "\n")); err != nil {
			t.Fatalf("write: %v", err)
		}
	}

	// Ordered: a forwarded notification, a dropped notification, a denied
	// request, then an ungoverned request whose reply we wait on. Because
	// the backend reads sequentially, seeing id=21's reply proves all
	// earlier lines were processed.
	write(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	write(`{"jsonrpc":"2.0","method":"notifications/roots/list_changed"}`)
	write(`{"jsonrpc":"2.0","id":20,"method":"tasks/cancel","params":{"taskId":"t1"}}`)
	write(`{"jsonrpc":"2.0","id":21,"method":"tasks/get","params":{"taskId":"t1"}}`)

	got := map[string]string{}
	timeout := time.After(5 * time.Second)
	for len(got) < 2 {
		select {
		case line := <-replies:
			var r struct {
				ID    json.Number     `json:"id"`
				Error json.RawMessage `json:"error"`
			}
			_ = json.Unmarshal([]byte(line), &r)
			got[r.ID.String()] = line
		case <-timeout:
			t.Fatalf("timed out; got %v", got)
		}
	}

	if !strings.Contains(got["20"], "denied by mesh policy") {
		t.Fatalf("tasks/cancel should be denied, got %q", got["20"])
	}
	if strings.Contains(got["21"], "denied") {
		t.Fatalf("tasks/get should be allowed, got %q", got["21"])
	}

	// Backend must have received only the forwarded lines.
	joined := strings.Join(backend.got, "\n")
	if !strings.Contains(joined, "notifications/initialized") {
		t.Fatalf("initialized should reach backend: %v", backend.got)
	}
	if !strings.Contains(joined, "tasks/get") {
		t.Fatalf("tasks/get should reach backend: %v", backend.got)
	}
	if strings.Contains(joined, "roots/list_changed") {
		t.Fatalf("denied notification leaked to backend: %v", backend.got)
	}
	if strings.Contains(joined, "tasks/cancel") {
		t.Fatalf("denied method leaked to backend: %v", backend.got)
	}

	audit := auditBuf.String()
	if !strings.Contains(audit, `"method":"tasks/cancel"`) || !strings.Contains(audit, `"rpc_id":"20","decision":"deny"`) {
		t.Fatalf("missing tasks/cancel deny audit:\n%s", audit)
	}
	if !strings.Contains(audit, `"method":"notifications/roots/list_changed","decision":"deny"`) {
		t.Fatalf("missing notification deny audit:\n%s", audit)
	}
}

func TestFilterEnforcesAndAudits(t *testing.T) {
	backend := newEchoBackend()
	pol := &Policy{
		DefaultAllow: false,
		Rules: []Rule{
			{Peers: []string{"*"}, Tools: []string{"read_*", "search_*"}, Allow: true},
		},
	}
	var auditBuf bytes.Buffer
	audit := NewAuditLog(&auditBuf, func() string { return "T" })

	f := NewFilter(backend, Caller{Backend: "kg", Peer: "laptop.netbird.cloud", PeerKey: "KEY"}, pol, audit, nil)

	replies := make(chan string, 8)
	go func() {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			replies <- sc.Text()
		}
		close(replies)
	}()

	write := func(s string) {
		if _, err := f.Write([]byte(s + "\n")); err != nil {
			t.Fatalf("write %q: %v", s, err)
		}
	}
	write(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
	write(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	write(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","arguments":{}}}`)
	write(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"delete_all","arguments":{}}}`)

	got := map[string]string{} // id -> raw reply
	timeout := time.After(5 * time.Second)
	for len(got) < 3 {
		select {
		case line := <-replies:
			var r struct {
				ID     json.Number     `json:"id"`
				Result json.RawMessage `json:"result"`
				Error  json.RawMessage `json:"error"`
			}
			if err := json.Unmarshal([]byte(line), &r); err != nil {
				t.Fatalf("bad reply %q: %v", line, err)
			}
			got[r.ID.String()] = line
		case <-timeout:
			t.Fatalf("timed out; got %d replies: %v", len(got), got)
		}
	}

	// id 1 (initialize) and id 2 (read_file) are backend results.
	if !strings.Contains(got["2"], `"tool":"read_file"`) {
		t.Fatalf("read_file should reach backend, got %q", got["2"])
	}
	// id 3 (delete_all) must be a policy denial, not a backend result.
	if !strings.Contains(got["3"], "denied by mesh policy") {
		t.Fatalf("delete_all should be denied, got %q", got["3"])
	}

	// The backend must never have seen the denied call.
	for _, line := range backend.got {
		if strings.Contains(line, "delete_all") {
			t.Fatalf("denied tool leaked to backend: %q", line)
		}
	}

	// Audit: exactly one allow (read_file) and one deny (delete_all).
	auditStr := auditBuf.String()
	if n := strings.Count(auditStr, `"decision":"allow"`); n != 1 {
		t.Fatalf("expected 1 allow audit record, got %d in:\n%s", n, auditStr)
	}
	if n := strings.Count(auditStr, `"decision":"deny"`); n != 1 {
		t.Fatalf("expected 1 deny audit record, got %d in:\n%s", n, auditStr)
	}
	if !strings.Contains(auditStr, `"tool":"delete_all"`) || !strings.Contains(auditStr, `"peer":"laptop.netbird.cloud"`) {
		t.Fatalf("audit missing expected fields:\n%s", auditStr)
	}
	t.Logf("enforcement + audit verified; audit log:\n%s", auditStr)
}

// captureHook records the AuditRecords the filter emits to the event hook.
type captureHook struct {
	mu   sync.Mutex
	recs []AuditRecord
}

func (c *captureHook) Emit(rec AuditRecord) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.recs = append(c.recs, rec)
}

func (c *captureHook) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.recs)
}

func (c *captureHook) snapshot() []AuditRecord {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]AuditRecord(nil), c.recs...)
}

// TestFilterEventHook verifies the filter forwards every policy decision to an
// attached EventHook, mirroring the audit record (this is the gateway->bus
// bridge the hooks feature relies on).
func TestFilterEventHook(t *testing.T) {
	backend := newEchoBackend()
	pol := &Policy{
		DefaultAllow: false,
		Rules:        []Rule{{Peers: []string{"*"}, Tools: []string{"read_*"}, Allow: true}},
	}
	hook := &captureHook{}
	f := NewFilter(backend, Caller{Backend: "kg", Peer: "p.netbird.cloud"}, pol, nil, nil)
	f.SetEventHook(hook)

	go func() {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
		}
	}()
	f.Write([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete_all"}}` + "\n"))
	f.Write([]byte(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_x"}}` + "\n"))

	deadline := time.After(5 * time.Second)
	for hook.count() < 2 {
		select {
		case <-deadline:
			t.Fatalf("hook received %d records, want 2", hook.count())
		case <-time.After(5 * time.Millisecond):
		}
	}
	var allow, deny int
	for _, r := range hook.snapshot() {
		switch r.Decision {
		case "allow":
			allow++
			if r.Tool != "read_x" {
				t.Fatalf("allow hook for wrong tool: %q", r.Tool)
			}
		case "deny":
			deny++
			if r.Tool != "delete_all" {
				t.Fatalf("deny hook for wrong tool: %q", r.Tool)
			}
		}
	}
	if allow != 1 || deny != 1 {
		t.Fatalf("hook decisions: allow=%d deny=%d, want 1/1", allow, deny)
	}
}

// TestFilterRateLimitRetryAfter proves S56: a rate-limited tool call's JSON-RPC
// error carries a machine-readable retry_after in error.data.
func TestFilterRateLimitRetryAfter(t *testing.T) {
	backend := newEchoBackend()
	pol := &Policy{DefaultAllow: false, Rules: []Rule{
		{Peers: []string{"*"}, Tools: []string{"read_*"}, Allow: true, Rate: &RateLimit{Max: 1, Per: "1m"}},
	}}
	now := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	eng := NewEngine(pol, func() time.Time { return now }, nil)
	f := NewFilterEngine(backend, Caller{Backend: "kg", Peer: "laptop.mesh", PeerKey: "KEY"}, eng, nil, nil)

	replies := make(chan string, 8)
	go func() {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			replies <- sc.Text()
		}
		close(replies)
	}()
	write := func(s string) {
		if _, err := f.Write([]byte(s + "\n")); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	// First read_file is allowed (backend echoes it); the second is rate-limited.
	write(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{}}}`)
	write(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","arguments":{}}}`)

	got := map[string]string{}
	timeout := time.After(5 * time.Second)
	for len(got) < 2 {
		select {
		case line := <-replies:
			var r struct {
				ID json.Number `json:"id"`
			}
			if json.Unmarshal([]byte(line), &r) == nil {
				got[r.ID.String()] = line
			}
		case <-timeout:
			t.Fatalf("timed out; got %v", got)
		}
	}
	if !strings.Contains(got["2"], "rate limit exceeded") {
		t.Fatalf("second call should be rate-limited, got %q", got["2"])
	}
	if !strings.Contains(got["2"], `"retry_after"`) {
		t.Fatalf("rate-limit denial should carry retry_after in error.data, got %q", got["2"])
	}
}
