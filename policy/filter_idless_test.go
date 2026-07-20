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

// recBackend is a synchronous recording backend: Write records the exact
// line the filter forwarded (under lock, before Write returns) so a test can
// deterministically assert whether a call reached the backend, without racing
// an async reader goroutine. It still auto-replies to id-bearing requests (on
// a detached goroutine, so recording never blocks on the read side) so callers
// waiting on a result unblock.
type recBackend struct {
	mu        sync.Mutex
	got       []string
	toCaller  *io.PipeReader
	toCallerW *io.PipeWriter
}

func newRecBackend() *recBackend {
	r, w := io.Pipe()
	return &recBackend{toCaller: r, toCallerW: w}
}

func (b *recBackend) Write(p []byte) (int, error) {
	line := strings.TrimSpace(string(p))
	if line != "" {
		b.mu.Lock()
		b.got = append(b.got, line)
		b.mu.Unlock()
	}
	var m rpcPeek
	if json.Unmarshal([]byte(line), &m) == nil && len(m.ID) != 0 {
		reply := `{"jsonrpc":"2.0","id":` + string(m.ID) + `,"result":{"ok":true}}` + "\n"
		if m.Method == "tools/call" {
			reply = `{"jsonrpc":"2.0","id":` + string(m.ID) + `,"result":{"tool":"` + m.Params.Name + `"}}` + "\n"
		}
		go func() { _, _ = b.toCallerW.Write([]byte(reply)) }()
	}
	return len(p), nil
}

func (b *recBackend) Read(p []byte) (int, error) { return b.toCaller.Read(p) }
func (b *recBackend) Close() error               { b.toCallerW.Close(); return nil }

func (b *recBackend) recorded() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return strings.Join(b.got, "\n")
}

// idlessFixture wires a filter with a deny-by-default policy that allows only
// read_* tools, drains the filter's read side into a replies channel, and
// returns everything a test needs.
type idlessFixture struct {
	f       *Filter
	backend *recBackend
	audit   *bytes.Buffer
	replies chan string
}

func newIDlessFixture(t *testing.T) *idlessFixture {
	t.Helper()
	backend := newRecBackend()
	pol := &Policy{
		DefaultAllow: false,
		Rules: []Rule{
			{Peers: []string{"*"}, Tools: []string{"read_*"}, Allow: true},
			{Peers: []string{"*"}, Methods: []string{"tasks/cancel"}, Allow: false},
		},
	}
	auditBuf := &bytes.Buffer{}
	f := NewFilter(backend, Caller{Backend: "kg", Peer: "peer.netbird.cloud", PeerKey: "KEY"}, pol,
		NewAuditLog(auditBuf, func() string { return "T" }), nil)
	replies := make(chan string, 16)
	go func() {
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 64*1024), 8<<20)
		for sc.Scan() {
			if line := strings.TrimSpace(sc.Text()); line != "" {
				replies <- line
			}
		}
		close(replies)
	}()
	return &idlessFixture{f: f, backend: backend, audit: auditBuf, replies: replies}
}

func (fx *idlessFixture) write(t *testing.T, s string) error {
	t.Helper()
	_, err := fx.f.Write([]byte(s + "\n"))
	return err
}

// waitReply blocks for the next denial/result line, failing on timeout.
func (fx *idlessFixture) waitReply(t *testing.T) string {
	t.Helper()
	select {
	case r, ok := <-fx.replies:
		if !ok {
			t.Fatalf("filter read side closed before a reply arrived")
		}
		return r
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for a filter reply")
		return ""
	}
}

// TestFilterIDlessToolCallDenied is the core regression: an ID-less tools/call
// for a denied tool must never reach the backend. On the vulnerable code it is
// classified as a notification, decided by method policy (which does not govern
// tools/call), and forwarded — bypassing tool authorization entirely.
func TestFilterIDlessToolCallDenied(t *testing.T) {
	fx := newIDlessFixture(t)
	if err := fx.write(t, `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"delete_all","arguments":{}}}`); err != nil {
		t.Fatalf("write: %v", err)
	}
	// Forwarding is synchronous inside Write, so recorded() is settled here.
	if got := fx.backend.recorded(); strings.Contains(got, "delete_all") {
		t.Fatalf("ID-less denied tools/call leaked to backend: %q", got)
	}
	if a := fx.audit.String(); !strings.Contains(a, `"tool":"delete_all"`) || !strings.Contains(a, `"decision":"deny"`) {
		t.Fatalf("expected a deny audit record for delete_all, got:\n%s", a)
	}
}

// TestFilterIDlessToolCallAllowedRejected: even a policy-*allowed* tool, sent
// without an id, is rejected as a protocol-invalid MCP request and never
// forwarded. A tools/call is a JSON-RPC request and MUST carry an id.
func TestFilterIDlessToolCallAllowedRejected(t *testing.T) {
	fx := newIDlessFixture(t)
	if err := fx.write(t, `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"read_file","arguments":{}}}`); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got := fx.backend.recorded(); strings.Contains(got, "read_file") {
		t.Fatalf("ID-less tools/call (even for an allowed tool) must not reach backend: %q", got)
	}
}

// TestFilterExplicitNullIDToolCall: id:null is not a valid request id; the
// tools/call must be rejected and never forwarded.
func TestFilterExplicitNullIDToolCall(t *testing.T) {
	fx := newIDlessFixture(t)
	if err := fx.write(t, `{"jsonrpc":"2.0","id":null,"method":"tools/call","params":{"name":"delete_all"}}`); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got := fx.backend.recorded(); strings.Contains(got, "delete_all") {
		t.Fatalf("null-id tools/call leaked to backend: %q", got)
	}
}

// TestFilterEmptyStringIDToolCall: an empty string is a valid JSON-RPC id, so
// the call goes through full tool policy. A denied tool is denied (not
// forwarded); an allowed tool is forwarded.
func TestFilterEmptyStringIDToolCall(t *testing.T) {
	fx := newIDlessFixture(t)
	if err := fx.write(t, `{"jsonrpc":"2.0","id":"","method":"tools/call","params":{"name":"delete_all"}}`); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got := fx.backend.recorded(); strings.Contains(got, "delete_all") {
		t.Fatalf("denied empty-string-id tools/call leaked to backend: %q", got)
	}
	if err := fx.write(t, `{"jsonrpc":"2.0","id":"","method":"tools/call","params":{"name":"read_file"}}`); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got := fx.backend.recorded(); !strings.Contains(got, "read_file") {
		t.Fatalf("allowed empty-string-id tools/call should reach backend: %q", got)
	}
}

// TestFilterNumericAndStringIDToolCall: ordinary numeric and string ids route
// through tool policy in the usual way.
func TestFilterNumericAndStringIDToolCall(t *testing.T) {
	fx := newIDlessFixture(t)
	if err := fx.write(t, `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"read_file"}}`); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := fx.write(t, `{"jsonrpc":"2.0","id":"abc","method":"tools/call","params":{"name":"delete_all"}}`); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := fx.backend.recorded()
	if !strings.Contains(got, "read_file") {
		t.Fatalf("allowed numeric-id call should reach backend: %q", got)
	}
	if strings.Contains(got, "delete_all") {
		t.Fatalf("denied string-id call leaked to backend: %q", got)
	}
}

// TestFilterMalformedParams: a tools/call whose params/name are structurally
// wrong must be rejected, not forwarded.
func TestFilterMalformedParams(t *testing.T) {
	cases := []string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":123}}`,     // name is a number
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":"oops"}`,           // params is a string
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"arguments":{}}}`, // missing name
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":""}}`,      // empty name
	}
	for _, c := range cases {
		fx := newIDlessFixture(t)
		if err := fx.write(t, c); err != nil {
			t.Fatalf("write %q: %v", c, err)
		}
		if got := fx.backend.recorded(); strings.Contains(got, "tools/call") {
			t.Fatalf("malformed tools/call leaked to backend: input=%q backend=%q", c, got)
		}
	}
}

// TestFilterDuplicateSecurityKeys: duplicate method / id / params.name keys are
// a parser-differential smuggling vector (Go json keeps the last, a backend may
// keep the first). They must be rejected, never forwarded.
func TestFilterDuplicateSecurityKeys(t *testing.T) {
	// Each case places the DANGEROUS value first, so Go's last-key-wins parse
	// picks the benign interpretation and would forward the raw bytes (which a
	// backend that keeps the first key reads as the dangerous call).
	cases := []string{
		// Go sees method=tools/list (ungoverned, forwarded); backend may see tools/call.
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","method":"tools/list","params":{"name":"read_file"}}`,
		// Go sees name=read_file (allowed, forwarded); backend may see delete_all.
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete_all","name":"read_file"}}`,
		// Duplicate id: which request does a reply correlate to? Ambiguous; reject.
		`{"jsonrpc":"2.0","id":1,"id":2,"method":"tools/call","params":{"name":"read_file"}}`,
	}
	for _, c := range cases {
		fx := newIDlessFixture(t)
		if err := fx.write(t, c); err != nil {
			t.Fatalf("write %q: %v", c, err)
		}
		if got := fx.backend.recorded(); got != "" {
			t.Fatalf("duplicate-key message leaked to backend: input=%q backend=%q", c, got)
		}
	}
}

// TestFilterBatchRejected: a top-level JSON-RPC batch cannot be authorized
// per-entry by the line filter and must be refused.
func TestFilterBatchRejected(t *testing.T) {
	fx := newIDlessFixture(t)
	if err := fx.write(t, `[{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete_all"}}]`); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got := fx.backend.recorded(); strings.Contains(got, "delete_all") {
		t.Fatalf("batch smuggled a tools/call to backend: %q", got)
	}
	r := fx.waitReply(t)
	if !strings.Contains(r, "batch") {
		t.Fatalf("expected a batch-rejection reply, got %q", r)
	}
}

// TestFilterOversizedLine: a peer that streams past the line cap without a
// newline tears the connection down instead of growing the buffer unbounded.
func TestFilterOversizedLine(t *testing.T) {
	fx := newIDlessFixture(t)
	big := bytes.Repeat([]byte(" "), maxLineBytes+1)
	if _, err := fx.f.Write(big); err != errLineTooLong {
		t.Fatalf("oversized line should return errLineTooLong, got %v", err)
	}
}

// TestFilterOrdinaryNotificationStillPasses: a genuine notification (no id, not
// a security-sensitive method) still flows to the backend after the dispatch
// reordering, so protocol-critical notifications are never lost.
func TestFilterOrdinaryNotificationStillPasses(t *testing.T) {
	fx := newIDlessFixture(t)
	if err := fx.write(t, `{"jsonrpc":"2.0","method":"notifications/initialized"}`); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got := fx.backend.recorded(); !strings.Contains(got, "notifications/initialized") {
		t.Fatalf("ordinary notification should reach backend: %q", got)
	}
}

// FuzzFilterClassification asserts the invariant across arbitrary single-line
// inputs: under a deny-all tool policy, NO input may cause any bytes that a
// lenient JSON parser reads as a tools/call to be forwarded to the backend.
func FuzzFilterClassification(f *testing.F) {
	seeds := []string{
		`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"x"}}`,
		`{"jsonrpc":"2.0","id":null,"method":"tools/call","params":{"name":"x"}}`,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x"}}`,
		`{"jsonrpc":"2.0","method":"tools/call","method":"tools/list","params":{"name":"x"}}`,
		`[{"jsonrpc":"2.0","method":"tools/call","params":{"name":"x"}}]`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`not json at all`,
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, line string) {
		if strings.ContainsRune(line, '\n') {
			return // single-line only; the filter frames on newlines
		}
		backend := newRecBackend()
		pol := &Policy{DefaultAllow: false} // deny every tool
		flt := NewFilter(backend, Caller{Backend: "b", Peer: "p"}, pol,
			NewAuditLog(io.Discard, func() string { return "T" }), nil)
		go func() {
			sc := bufio.NewScanner(flt)
			sc.Buffer(make([]byte, 64*1024), 32<<20)
			for sc.Scan() {
			}
		}()
		_, _ = flt.Write([]byte(line + "\n"))
		// Any forwarded line that a lenient parser reads as a tools/call is a
		// bypass: with a deny-all policy, no tools/call may ever reach backend.
		for _, got := range strings.Split(backend.recorded(), "\n") {
			if got == "" {
				continue
			}
			var m struct {
				Method string `json:"method"`
			}
			if json.Unmarshal([]byte(got), &m) == nil && m.Method == "tools/call" {
				t.Fatalf("deny-all policy forwarded a tools/call to backend\ninput=  %q\nforward=%q", line, got)
			}
		}
	})
}
