package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/xrey167/meshmcp/policy"
)

// TestStdioHTTPConformance is the Phase-7 cross-transport conformance test: the
// SAME semantic request and identity must receive the SAME decision (allow vs.
// deny/reject, and reach-backend vs. not) over the stdio filter and the
// Streamable-HTTP enforcer. Both route through the shared policy.ClassifyRPC +
// engine, so a request hardened on one transport cannot be softer on the other.
func TestStdioHTTPConformance(t *testing.T) {
	pol := &policy.Policy{
		DefaultAllow: false,
		Rules: []policy.Rule{
			{Peers: []string{"*"}, Tools: []string{"read_*"}, Allow: true},
			{Peers: []string{"*"}, Methods: []string{"tasks/cancel"}, Allow: false},
		},
	}
	const peer, key = "p.mesh", "PEERKEY"

	cases := []struct {
		name    string
		line    string
		allowed bool // true = the call reaches the backend (allowed); false = rejected/denied
	}{
		{"allowed tool", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{}}}`, true},
		{"denied tool", `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"delete_all"}}`, false},
		{"id-less tools/call", `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"read_file"}}`, false},
		{"null-id tools/call", `{"jsonrpc":"2.0","id":null,"method":"tools/call","params":{"name":"read_file"}}`, false},
		{"empty name", `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":""}}`, false},
		{"duplicate method key", `{"jsonrpc":"2.0","id":4,"method":"tools/call","method":"tools/list","params":{"name":"read_file"}}`, false},
		{"batch", `[{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"read_file"}}]`, false},
		{"governed method denied", `{"jsonrpc":"2.0","id":6,"method":"tasks/cancel","params":{}}`, false},
		{"ungoverned method", `{"jsonrpc":"2.0","id":7,"method":"tools/list","params":{}}`, true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			stdio := stdioReaches(t, pol, peer, key, c.line)
			httpd := httpReaches(t, pol, peer, key, c.line)
			if stdio != httpd {
				t.Fatalf("DRIFT: stdio reached-backend=%v but HTTP reached-backend=%v for %q", stdio, httpd, c.line)
			}
			if stdio != c.allowed {
				t.Fatalf("both transports agreed (reached=%v) but expected allowed=%v for %q", stdio, c.allowed, c.line)
			}
		})
	}
}

// stdioReaches runs one line through the stdio Filter and reports whether it
// reached the backend.
func stdioReaches(t *testing.T, pol *policy.Policy, peer, key, line string) bool {
	t.Helper()
	backend := newConfBackend()
	f := policy.NewFilter(backend, policy.Caller{Backend: "b", Peer: peer, PeerKey: key}, pol,
		policy.NewAuditLog(io.Discard, func() string { return "T" }), nil)
	go func() {
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 64*1024), 1<<20)
		for sc.Scan() {
		}
	}()
	if _, err := f.Write([]byte(line + "\n")); err != nil {
		return false // e.g. oversized line torn down
	}
	// Forwarding is synchronous within Write.
	return backend.received()
}

// httpReaches runs one body through the HTTP enforcer and reports whether it
// would be proxied to the backend (ok == true).
func httpReaches(t *testing.T, pol *policy.Policy, peer, key, body string) bool {
	t.Helper()
	b := &Backend{Name: "b", Policy: pol}
	enf := newHTTPEnforcer(b, policy.NewAuditLog(io.Discard, func() string { return "T" }))
	req, err := http.NewRequest(http.MethodPost, "http://x/mcp", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	ok, _, _ := enf.decide(peer, key, req)
	return ok
}

// confBackend records whether any line reached it (synchronously on Write).
type confBackend struct {
	toCaller  *io.PipeReader
	toCallerW *io.PipeWriter
	got       bool
}

func newConfBackend() *confBackend {
	r, w := io.Pipe()
	return &confBackend{toCaller: r, toCallerW: w}
}

func (b *confBackend) Write(p []byte) (int, error) {
	if len(bytes.TrimSpace(p)) > 0 {
		b.got = true
	}
	var m struct {
		ID     json.RawMessage `json:"id"`
		Method string          `json:"method"`
	}
	if json.Unmarshal(bytes.TrimSpace(p), &m) == nil && len(m.ID) != 0 {
		reply := `{"jsonrpc":"2.0","id":` + string(m.ID) + `,"result":{}}` + "\n"
		go func() { _, _ = b.toCallerW.Write([]byte(reply)) }()
	}
	return len(p), nil
}
func (b *confBackend) Read(p []byte) (int, error) { return b.toCaller.Read(p) }
func (b *confBackend) Close() error               { b.toCallerW.Close(); return nil }
func (b *confBackend) received() bool             { return b.got }
