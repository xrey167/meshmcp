package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xrey167/meshmcp/policy"
	"github.com/xrey167/meshmcp/secrets"
)

// HTTP parity slice v1 (task 9): per-session taint labels, secret injection +
// response redaction, and capability upgrades on Streamable-HTTP and remote
// backends, at parity with the stdio filter. These tests drive the REAL
// serveHTTP handler (httpBackendHandler) in front of an httptest backend, with
// identity injected the same way remoteHandler tests do.

const capMetaKeyWire = "com.meshmcp/capability" // the wire _meta key (pinned)

// parityBackend is an httptest MCP backend that records every body it receives
// and answers via a configurable responder.
type parityBackend struct {
	mu      sync.Mutex
	bodies  [][]byte
	respond func(w http.ResponseWriter, r *http.Request, body []byte)
}

func (pb *parityBackend) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	pb.mu.Lock()
	pb.bodies = append(pb.bodies, append([]byte(nil), body...))
	respond := pb.respond
	pb.mu.Unlock()
	if respond != nil {
		respond(w, r, body)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
}

func (pb *parityBackend) hits() int {
	pb.mu.Lock()
	defer pb.mu.Unlock()
	return len(pb.bodies)
}

func (pb *parityBackend) lastBody() []byte {
	pb.mu.Lock()
	defer pb.mu.Unlock()
	if len(pb.bodies) == 0 {
		return nil
	}
	return pb.bodies[len(pb.bodies)-1]
}

// startParityGateway wires the real HTTP-backend handler (ACL → enforcer →
// identity stamp → reverse proxy with response redaction) in front of pb.
// Identity is read from X-Test-Peer(-Key) request headers via the injectable
// identify seam, so two-peer tests need no mesh.
func startParityGateway(t *testing.T, b *Backend, pb *parityBackend) (*httptest.Server, *httpEnforcer) {
	t.Helper()
	bs := httptest.NewServer(pb)
	t.Cleanup(bs.Close)
	u, err := url.Parse(bs.URL)
	if err != nil {
		t.Fatal(err)
	}
	b.HTTP = bs.URL
	b.httpURL = u
	enf, err := newHTTPEnforcer(b, policy.NewAuditLog(io.Discard, func() string { return "T" }))
	if err != nil {
		t.Fatal(err)
	}
	identify := func(r *http.Request) (string, string) {
		return r.Header.Get("X-Test-Peer-Key"), r.Header.Get("X-Test-Peer")
	}
	gw := httptest.NewServer(httpBackendHandler(b, enf, identify))
	t.Cleanup(gw.Close)
	return gw, enf
}

func toolCallBody(id int, tool, args string) string {
	if args == "" {
		args = "{}"
	}
	return fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":%q,"arguments":%s}}`, id, tool, args)
}

// postMCP sends one JSON-RPC body as the given peer/session and returns the
// response.
func postMCP(t *testing.T, gw *httptest.Server, peer, key, sid, body string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, gw.URL+"/mcp", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Test-Peer", peer)
	req.Header.Set("X-Test-Peer-Key", key)
	if sid != "" {
		req.Header.Set(mcpSessionHeader, sid)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(rb)
}

func labelPolicy() *policy.Policy {
	return &policy.Policy{DefaultAllow: false, Rules: []policy.Rule{
		{Peers: []string{"*"}, Tools: []string{"fetch_web"}, Allow: true, EmitLabels: []string{"pii"}},
		{Peers: []string{"*"}, Tools: []string{"egress"}, Allow: true, BlockLabels: []string{"pii"}},
		{Peers: []string{"*"}, Tools: []string{"read_*"}, Allow: true},
	}}
}

// TestHTTPTaintLabelsPerSession: an emit_labels call taints exactly its own
// (peer, session); a block_labels tool is then denied in that session but
// allowed in a fresh one (per-session isolation, stdio parity).
func TestHTTPTaintLabelsPerSession(t *testing.T) {
	pb := &parityBackend{}
	gw, _ := startParityGateway(t, &Backend{Name: "b", Policy: labelPolicy()}, pb)

	// Untainted session: egress allowed.
	if _, body := postMCP(t, gw, "alice", "KA", "S1", toolCallBody(1, "egress", "")); !strings.Contains(body, `"result"`) {
		t.Fatalf("egress before any taint must be allowed, got: %s", body)
	}
	// Taint S1, then egress in S1 is blocked.
	if _, body := postMCP(t, gw, "alice", "KA", "S1", toolCallBody(2, "fetch_web", "")); !strings.Contains(body, `"result"`) {
		t.Fatalf("fetch_web should be allowed, got: %s", body)
	}
	if _, body := postMCP(t, gw, "alice", "KA", "S1", toolCallBody(3, "egress", "")); !strings.Contains(body, "carries label") || !strings.Contains(body, "pii") {
		t.Fatalf("egress after taint in the same session must be label-blocked, got: %s", body)
	}
	// A fresh session is label-clean.
	if _, body := postMCP(t, gw, "alice", "KA", "S2", toolCallBody(4, "egress", "")); !strings.Contains(body, `"result"`) {
		t.Fatalf("egress in a fresh session must be allowed, got: %s", body)
	}
	if pb.hits() != 3 {
		t.Fatalf("backend must see exactly the 3 allowed calls, saw %d", pb.hits())
	}
}

// TestHTTPLabelPolicyRequiresSessionHeader: with label rules in force, a
// tools/call without a valid Mcp-Session-Id is DENIED (never silently
// un-labeled), while methods, notifications, and GET are unaffected.
func TestHTTPLabelPolicyRequiresSessionHeader(t *testing.T) {
	pb := &parityBackend{}
	gw, _ := startParityGateway(t, &Backend{Name: "b", Policy: labelPolicy()}, pb)

	// Missing header → denied, and the denial names the header.
	if _, body := postMCP(t, gw, "alice", "KA", "", toolCallBody(1, "read_file", "")); !strings.Contains(body, mcpSessionHeader) {
		t.Fatalf("session-less tools/call must be denied naming %s, got: %s", mcpSessionHeader, body)
	}
	// Malformed ids → denied. (A control character cannot even be transmitted
	// as a header value, so the wire-testable invalid forms are a space and an
	// over-long id.)
	for _, sid := range []string{"has space", strings.Repeat("x", httpSessionMaxIDLen+1)} {
		if _, body := postMCP(t, gw, "alice", "KA", sid, toolCallBody(2, "read_file", "")); !strings.Contains(body, mcpSessionHeader) {
			t.Fatalf("invalid session id %q must be denied, got: %s", sid, body)
		}
	}
	if pb.hits() != 0 {
		t.Fatalf("no denied call may reach the backend, saw %d", pb.hits())
	}
	// With a header the same call proceeds.
	if _, body := postMCP(t, gw, "alice", "KA", "S1", toolCallBody(3, "read_file", "")); !strings.Contains(body, `"result"`) {
		t.Fatalf("tools/call with a session id must proceed, got: %s", body)
	}
	// Ungoverned method without a session header still passes through.
	if _, body := postMCP(t, gw, "alice", "KA", "", `{"jsonrpc":"2.0","id":9,"method":"tools/list"}`); !strings.Contains(body, `"result"`) {
		t.Fatalf("tools/list must not require a session header, got: %s", body)
	}
	// GET (SSE attach) without a session header is proxied untouched.
	req, _ := http.NewRequest(http.MethodGet, gw.URL+"/mcp", nil)
	req.Header.Set("X-Test-Peer", "alice")
	req.Header.Set("X-Test-Peer-Key", "KA")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET must be proxied, got %d", resp.StatusCode)
	}
}

// secretsBackend returns a Backend with a policy + env-backed secret grants.
func secretsBackend(t *testing.T, name string, grants []string, blockLabels []string, pol *policy.Policy) *Backend {
	t.Helper()
	t.Setenv("MESHPARITY_API_KEY", paritySecret)
	if pol == nil {
		pol = &policy.Policy{DefaultAllow: false, Rules: []policy.Rule{
			{Peers: []string{"*"}, Tools: []string{"*"}, Allow: true},
		}}
	}
	return &Backend{Name: name, Policy: pol, Secrets: &SecretsConfig{
		EnvPrefix: "MESHPARITY_",
		Grants: []secrets.Grant{{
			Peers:       []string{"*"},
			Secrets:     grants,
			BlockLabels: blockLabels,
		}},
	}}
}

const paritySecret = `sk-parity-12"34-secret`

// jsonEscaped is the JSON string-escaped form of the raw secret (what a JSON
// echo carries on the wire).
func jsonEscaped(v string) string {
	b, _ := json.Marshal(v)
	return string(b[1 : len(b)-1])
}

// TestHTTPSecretInjectionAndJSONRedaction: the request the backend receives
// carries the resolved value (marker gone, Content-Length correct); a backend
// echoing the value (raw and JSON-escaped) gets both scrubbed.
func TestHTTPSecretInjectionAndJSONRedaction(t *testing.T) {
	pb := &parityBackend{}
	pb.respond = func(w http.ResponseWriter, r *http.Request, body []byte) {
		w.Header().Set("Content-Type", "application/json")
		// Echo the escaped form inside valid JSON AND the raw bytes after it —
		// the redactor is byte-level and must catch both.
		_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":1,"result":{"echo":"%s"}}%s`, jsonEscaped(paritySecret), paritySecret)
	}
	gw, _ := startParityGateway(t, secretsBackend(t, "b", []string{"API_KEY"}, nil, nil), pb)

	_, body := postMCP(t, gw, "alice", "KA", "", toolCallBody(1, "charge", `{"token":"{{secret:API_KEY}}"}`))
	if strings.Contains(body, paritySecret) || strings.Contains(body, jsonEscaped(paritySecret)) {
		t.Fatalf("response must not contain the injected secret in any form: %s", body)
	}
	if got := strings.Count(body, "[redacted-secret]"); got != 2 {
		t.Fatalf("expected 2 redaction placeholders (escaped + raw echo), got %d in: %s", got, body)
	}
	got := pb.lastBody()
	if !bytes.Contains(got, []byte(jsonEscaped(paritySecret))) {
		t.Fatalf("backend must receive the resolved secret value, got: %s", got)
	}
	if bytes.Contains(got, []byte("{{secret:")) {
		t.Fatalf("backend must not see the secret marker: %s", got)
	}
}

// TestHTTPSecretSSERedactionAcrossChunks: an SSE response is scrubbed even when
// the backend splits the secret across two flushed chunks mid-value, framing
// stays byte-identical, and the stream stays LIVE (the first event reaches the
// client while the backend is still holding the second).
func TestHTTPSecretSSERedactionAcrossChunks(t *testing.T) {
	esc := jsonEscaped(paritySecret)
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseFn := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(releaseFn) // never leave the backend handler blocked on a failed test
	pb := &parityBackend{}
	pb.respond = func(w http.ResponseWriter, r *http.Request, body []byte) {
		fl := w.(http.Flusher)
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "event: message\n")
		fl.Flush()
		// Split the secret mid-value across two flushes within one data line.
		_, _ = io.WriteString(w, `data: {"result":"`+esc[:7])
		fl.Flush()
		_, _ = io.WriteString(w, esc[7:]+`"}`+"\n\n")
		fl.Flush()
		<-release // liveness: event 2 is not even written until the client saw event 1
		_, _ = io.WriteString(w, "data: done\n\n")
		fl.Flush()
	}
	gw, _ := startParityGateway(t, secretsBackend(t, "b", []string{"API_KEY"}, nil, nil), pb)

	req, _ := http.NewRequest(http.MethodPost, gw.URL+"/mcp",
		strings.NewReader(toolCallBody(1, "stream", `{"token":"{{secret:API_KEY}}"}`)))
	req.Header.Set("X-Test-Peer", "alice")
	req.Header.Set("X-Test-Peer-Key", "KA")
	client := &http.Client{Timeout: 30 * time.Second} // watchdog: a buffered (non-live) stream deadlocks here
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "text/event-stream") {
		t.Fatalf("expected SSE response, got %q", ct)
	}
	br := bufio.NewReader(resp.Body)
	readEvent := func() []string {
		var lines []string
		for {
			l, err := br.ReadString('\n')
			if err != nil {
				t.Fatalf("stream ended early (lines so far %q): %v", lines, err)
			}
			if l == "\n" {
				return lines
			}
			lines = append(lines, strings.TrimRight(l, "\n"))
		}
	}
	ev1 := readEvent()
	if len(ev1) != 2 || ev1[0] != "event: message" {
		t.Fatalf("event framing must be preserved, got %q", ev1)
	}
	if want := `data: {"result":"[redacted-secret]"}`; ev1[1] != want {
		t.Fatalf("chunk-split secret must be redacted within its line:\n got %q\nwant %q", ev1[1], want)
	}
	releaseFn() // we saw event 1 before the backend wrote event 2: the stream is live
	if ev2 := readEvent(); len(ev2) != 1 || ev2[0] != "data: done" {
		t.Fatalf("second event mangled: %q", ev2)
	}
}

// TestHTTPSecretDenials: an ungranted secret and a label-blocked grant both
// deny BEFORE the backend is contacted; a clean session still injects.
func TestHTTPSecretDenials(t *testing.T) {
	pol := &policy.Policy{DefaultAllow: false, Rules: []policy.Rule{
		{Peers: []string{"*"}, Tools: []string{"fetch_web"}, Allow: true, TaintSource: true},
		{Peers: []string{"*"}, Tools: []string{"*"}, Allow: true},
	}}
	pb := &parityBackend{}
	b := secretsBackend(t, "b", []string{"API_KEY"}, []string{"tainted"}, pol)
	gw, _ := startParityGateway(t, b, pb)

	// Ungranted name → denied, backend never hit.
	if _, body := postMCP(t, gw, "alice", "KA", "S1", toolCallBody(1, "charge", `{"k":"{{secret:OTHER}}"}`)); !strings.Contains(body, "not granted") {
		t.Fatalf("ungranted secret must deny, got: %s", body)
	}
	if pb.hits() != 0 {
		t.Fatal("denied injection must not reach the backend")
	}
	// Clean session → injected.
	if _, body := postMCP(t, gw, "alice", "KA", "S1", toolCallBody(2, "charge", `{"k":"{{secret:API_KEY}}"}`)); !strings.Contains(body, `"result"`) {
		t.Fatalf("granted secret in a clean session must inject, got: %s", body)
	}
	// Taint the session; the label-blocked grant now refuses.
	if _, body := postMCP(t, gw, "alice", "KA", "S1", toolCallBody(3, "fetch_web", "")); !strings.Contains(body, `"result"`) {
		t.Fatalf("taint source call failed: %s", body)
	}
	if _, body := postMCP(t, gw, "alice", "KA", "S1", toolCallBody(4, "charge", `{"k":"{{secret:API_KEY}}"}`)); !strings.Contains(body, "carries label") || !strings.Contains(body, "tainted") {
		t.Fatalf("tainted session must block the grant, got: %s", body)
	}
	// A fresh session injects again.
	if _, body := postMCP(t, gw, "alice", "KA", "S2", toolCallBody(5, "charge", `{"k":"{{secret:API_KEY}}"}`)); !strings.Contains(body, `"result"`) {
		t.Fatalf("fresh session must inject, got: %s", body)
	}
}

// TestHTTPSecretInjectionRequiresPeerKey: response redactors are keyed by the
// transport-proven peer key, so an injection for a peer the transport could
// not key (peerKey == "", FQDN-only admission) is refused before the backend —
// every key-less peer would otherwise share one ""-keyed redactor, the
// cross-peer match oracle per-peer scoping exists to prevent. Non-secret calls
// from the same peer still proceed.
func TestHTTPSecretInjectionRequiresPeerKey(t *testing.T) {
	pb := &parityBackend{}
	gw, enf := startParityGateway(t, secretsBackend(t, "b", []string{"API_KEY"}, nil, nil), pb)

	// A key-less peer's non-secret call proceeds (nothing to scope).
	if _, body := postMCP(t, gw, "ghost", "", "", toolCallBody(1, "read_file", "")); !strings.Contains(body, `"result"`) {
		t.Fatalf("non-secret call from a key-less peer must proceed, got: %s", body)
	}
	// Its secret injection is refused before the backend is contacted.
	if _, body := postMCP(t, gw, "ghost", "", "", toolCallBody(2, "charge", `{"k":"{{secret:API_KEY}}"}`)); !strings.Contains(body, "transport-proven peer identity") {
		t.Fatalf("key-less injection must be refused, got: %s", body)
	}
	if pb.hits() != 1 {
		t.Fatalf("the refused injection must not reach the backend (hits=%d)", pb.hits())
	}
	// No shared ""-keyed redactor may ever come into existence.
	if enf.sessions.lookupRedactor("") != nil {
		t.Fatal("a \"\"-keyed redactor must never be created")
	}
	// A keyed peer on the same backend still injects normally.
	if _, body := postMCP(t, gw, "alice", "KA", "", toolCallBody(3, "charge", `{"k":"{{secret:API_KEY}}"}`)); !strings.Contains(body, `"result"`) {
		t.Fatalf("keyed peer must still inject, got: %s", body)
	}
}

// mintCapability issues a capability for (key, backend, tool glob) signed by
// signer, valid for an hour.
func mintCapability(t *testing.T, signer *policy.Signer, key, backend string, tools ...string) string {
	t.Helper()
	tok, err := signer.IssueCapability(policy.CapabilityClaims{
		Subject: key, Audience: backend, Tools: tools, Issuer: "test",
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
	}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func withMeta(body, token string) string {
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		panic(err)
	}
	var params map[string]json.RawMessage
	_ = json.Unmarshal(m["params"], &params)
	if params == nil {
		params = map[string]json.RawMessage{}
	}
	meta, _ := json.Marshal(map[string]string{capMetaKeyWire: token})
	params["_meta"] = meta
	pb, _ := json.Marshal(params)
	m["params"] = pb
	ob, _ := json.Marshal(m)
	return string(ob)
}

// TestHTTPCapabilityUpgradeAndStrip: a valid capability upgrades a
// default-deny over HTTP, the token never reaches the backend (tools/call AND
// method bodies), an explicit deny is not overridden, and required:true
// refuses token-less calls.
func TestHTTPCapabilityUpgradeAndStrip(t *testing.T) {
	signer, err := policy.GenerateSigner()
	if err != nil {
		t.Fatal(err)
	}
	pol := &policy.Policy{DefaultAllow: false, Rules: []policy.Rule{
		{Peers: []string{"*"}, Tools: []string{"banned"}, Allow: false},
	}}
	pb := &parityBackend{}
	b := &Backend{Name: "b", Policy: pol,
		Capabilities: &CapabilitiesConfig{Required: false, TrustedPublicKeys: []string{signer.PubKeyHex()}}}
	gw, _ := startParityGateway(t, b, pb)

	// Token-less default-deny call → denied.
	if _, body := postMCP(t, gw, "alice", "KA", "", toolCallBody(1, "read_file", "")); !strings.Contains(body, "blocked") {
		t.Fatalf("token-less call must stay default-denied, got: %s", body)
	}
	// Valid token upgrades — and the backend body must carry no token.
	tok := mintCapability(t, signer, "KA", "b", "read_*")
	if _, body := postMCP(t, gw, "alice", "KA", "", withMeta(toolCallBody(2, "read_file", ""), tok)); !strings.Contains(body, `"result"`) {
		t.Fatalf("valid capability must upgrade the default deny, got: %s", body)
	}
	if got := pb.lastBody(); bytes.Contains(got, []byte(tok)) || bytes.Contains(got, []byte("_meta")) {
		t.Fatalf("capability token must be stripped before the backend: %s", got)
	}
	// A capability never overrides an explicit deny rule.
	tok2 := mintCapability(t, signer, "KA", "b", "banned")
	if _, body := postMCP(t, gw, "alice", "KA", "", withMeta(toolCallBody(3, "banned", ""), tok2)); !strings.Contains(body, "blocked") {
		t.Fatalf("explicit deny must survive a valid capability, got: %s", body)
	}
	// Wrong-subject token fails closed.
	if _, body := postMCP(t, gw, "alice", "KOTHER", "", withMeta(toolCallBody(4, "read_file", ""), tok)); !strings.Contains(body, "invalid capability") {
		t.Fatalf("subject-mismatched token must deny, got: %s", body)
	}
	// A token riding a METHOD body is stripped from what the backend receives.
	before := pb.hits()
	if _, body := postMCP(t, gw, "alice", "KA", "", withMeta(`{"jsonrpc":"2.0","id":9,"method":"tools/list","params":{}}`, tok)); !strings.Contains(body, `"result"`) {
		t.Fatalf("tools/list should pass through, got: %s", body)
	}
	if pb.hits() != before+1 {
		t.Fatal("tools/list must reach the backend")
	}
	if got := pb.lastBody(); bytes.Contains(got, []byte(tok)) {
		t.Fatalf("token on a method line must be stripped: %s", got)
	}

	// required:true refuses token-less calls even for a rule-allowed tool.
	pb2 := &parityBackend{}
	b2 := &Backend{Name: "b2", Policy: &policy.Policy{DefaultAllow: false, Rules: []policy.Rule{
		{Peers: []string{"*"}, Tools: []string{"read_*"}, Allow: true}}},
		Capabilities: &CapabilitiesConfig{Required: true, TrustedPublicKeys: []string{signer.PubKeyHex()}}}
	gw2, _ := startParityGateway(t, b2, pb2)
	if _, body := postMCP(t, gw2, "alice", "KA", "", toolCallBody(1, "read_file", "")); !strings.Contains(body, "capability required") {
		t.Fatalf("required:true must refuse token-less calls, got: %s", body)
	}
	if pb2.hits() != 0 {
		t.Fatal("refused call must not reach the backend")
	}
}

// auditTempDir returns a temp dir for an audit_log file the resolved sink will
// hold open for the test process's lifetime (exactly like the production
// gateway, which never closes it). Removal is best-effort: Windows cannot
// delete the still-open file, which would fail t.TempDir's checked cleanup.
func auditTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "meshmcp-audit")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// TestResolveBackendAuditCapabilitiesOnly: a capabilities-only backend's
// authorization decisions must land in a ledger — the gateway-wide shared
// ledger when configured, else the backend's own audit_log — never silently
// nowhere (a capability upgrade of a default-deny is an authorization like any
// policy decision).
func TestResolveBackendAuditCapabilitiesOnly(t *testing.T) {
	signer, err := policy.GenerateSigner()
	if err != nil {
		t.Fatal(err)
	}
	caps := &CapabilitiesConfig{Required: true, TrustedPublicKeys: []string{signer.PubKeyHex()}}
	shared := policy.NewAuditLog(io.Discard, func() string { return "T" })

	// Capabilities-only + shared ledger → the shared ledger itself, not owned.
	if a, own, err := resolveBackendAudit(&Backend{Name: "c", Capabilities: caps}, shared); err != nil || a != shared || own {
		t.Fatalf("capabilities-only backend must use the shared ledger, got (%p, own=%v, err=%v)", a, own, err)
	}
	// Policy-bearing + shared ledger → the shared ledger (unchanged behavior).
	if a, own, err := resolveBackendAudit(&Backend{Name: "p", Policy: &policy.Policy{}}, shared); err != nil || a != shared || own {
		t.Fatalf("policy backend must use the shared ledger, got (%p, own=%v, err=%v)", a, own, err)
	}
	// Capabilities-only + per-backend audit_log, no shared ledger → an owned
	// sink whose records land in the configured file.
	logPath := filepath.Join(auditTempDir(t), "audit.jsonl")
	a, own, err := resolveBackendAudit(&Backend{Name: "c", Capabilities: caps, AuditLog: logPath}, nil)
	if err != nil || a == nil || !own {
		t.Fatalf("capabilities-only backend with audit_log must get its own sink, got (%p, own=%v, err=%v)", a, own, err)
	}
	if err := a.Append(policy.AuditRecord{Backend: "c", Method: "tools/call", Tool: "read_file", Decision: "allow"}); err != nil {
		t.Fatal(err)
	}
	a.Flush()
	data, err := os.ReadFile(logPath)
	if err != nil || !bytes.Contains(data, []byte(`"tool":"read_file"`)) {
		t.Fatalf("decision must land in the configured audit_log, got %q (err=%v)", data, err)
	}
	// Neither policy nor capabilities → no decisions, no sink (any transport).
	for _, b := range []*Backend{{Name: "h", HTTP: "http://x"}, {Name: "s", Stdio: []string{"cmd"}}} {
		if a, own, err := resolveBackendAudit(b, shared); err != nil || a != nil || own {
			t.Fatalf("backend %q without policy/capabilities must get no sink, got (%p, own=%v, err=%v)", b.Name, a, own, err)
		}
	}
}

// TestHTTPCapabilityOnlyDecisionsAudited: with the audit sink resolved the way
// cmdServe resolves it, a capabilities-only HTTP backend records BOTH the
// token-less deny and the capability-upgraded allow in its ledger (previously
// the resolved sink was nil and such authorizations left no record at all).
func TestHTTPCapabilityOnlyDecisionsAudited(t *testing.T) {
	signer, err := policy.GenerateSigner()
	if err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(auditTempDir(t), "audit.jsonl")
	b := &Backend{Name: "b", AuditLog: logPath,
		Capabilities: &CapabilitiesConfig{Required: true, TrustedPublicKeys: []string{signer.PubKeyHex()}}}
	audit, own, err := resolveBackendAudit(b, nil)
	if err != nil || audit == nil || !own {
		t.Fatalf("audit resolution failed: (%p, own=%v, err=%v)", audit, own, err)
	}

	pb := &parityBackend{}
	bs := httptest.NewServer(pb)
	t.Cleanup(bs.Close)
	u, err := url.Parse(bs.URL)
	if err != nil {
		t.Fatal(err)
	}
	b.HTTP, b.httpURL = bs.URL, u
	enf, err := newHTTPEnforcer(b, audit)
	if err != nil {
		t.Fatal(err)
	}
	gw := httptest.NewServer(httpBackendHandler(b, enf, func(r *http.Request) (string, string) {
		return r.Header.Get("X-Test-Peer-Key"), r.Header.Get("X-Test-Peer")
	}))
	t.Cleanup(gw.Close)

	// Token-less call → denied (capability required) and recorded.
	if _, body := postMCP(t, gw, "alice", "KA", "", toolCallBody(1, "read_file", "")); !strings.Contains(body, "capability required") {
		t.Fatalf("token-less call must be refused, got: %s", body)
	}
	// Capability-upgraded call → allowed, proxied, and recorded.
	tok := mintCapability(t, signer, "KA", "b", "read_*")
	if _, body := postMCP(t, gw, "alice", "KA", "", withMeta(toolCallBody(2, "read_file", ""), tok)); !strings.Contains(body, `"result"`) {
		t.Fatalf("capability call must be allowed, got: %s", body)
	}
	if pb.hits() != 1 {
		t.Fatalf("backend must see exactly the allowed call, saw %d", pb.hits())
	}
	audit.Flush()
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(data, []byte(`"decision":"deny"`)) || !bytes.Contains(data, []byte(`"decision":"allow"`)) {
		t.Fatalf("both the deny and the capability-upgraded allow must be in the ledger, got: %s", data)
	}
	if got := bytes.Count(data, []byte(`"tool":"read_file"`)); got != 2 {
		t.Fatalf("expected 2 audited tools/call decisions, got %d in: %s", got, data)
	}
}

// mintSingleUse issues a SingleUse capability bound to key/backend for the given
// tool glob — mintCapability's one-shot sibling.
func mintSingleUse(t *testing.T, signer *policy.Signer, key, backend, tool string) string {
	t.Helper()
	tok, err := signer.IssueCapability(policy.CapabilityClaims{
		Subject: key, Audience: backend, Tools: []string{tool}, Issuer: "test",
		SingleUse: true, ExpiresAt: time.Now().Add(time.Hour).Unix(),
	}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// TestHTTPSingleUseCapabilityParity pins the HTTP enforcer's deferred single-use
// consumption at parity with the stdio filter (FoldCapability returns claims;
// the caller consumes only after its final allow): a one-shot grant authorizes
// exactly once, a replay is refused, and a co-sign hold does NOT burn it (the
// approved-tool retry still has it). Without the deferred Consume the HTTP path
// would either never consume (replay slips through) or burn on the hold.
func TestHTTPSingleUseCapabilityParity(t *testing.T) {
	signer, err := policy.GenerateSigner()
	if err != nil {
		t.Fatal(err)
	}

	t.Run("consumed once, replay denied", func(t *testing.T) {
		b := &Backend{Name: "b", Capabilities: &CapabilitiesConfig{
			Required: true, TrustedPublicKeys: []string{signer.PubKeyHex()}}}
		pb := &parityBackend{}
		gw, _ := startParityGateway(t, b, pb)
		tok := mintSingleUse(t, signer, "KA", "b", "read_*")

		if _, body := postMCP(t, gw, "alice", "KA", "", withMeta(toolCallBody(1, "read_file", ""), tok)); !strings.Contains(body, `"result"`) {
			t.Fatalf("first use of a single-use grant must be allowed, got: %s", body)
		}
		if pb.hits() != 1 {
			t.Fatalf("the allowed call must reach the backend exactly once, saw %d", pb.hits())
		}
		if _, body := postMCP(t, gw, "alice", "KA", "", withMeta(toolCallBody(2, "read_file", ""), tok)); !strings.Contains(body, "already been used") {
			t.Fatalf("a single-use replay over HTTP must be refused, got: %s", body)
		}
		if pb.hits() != 1 {
			t.Fatalf("the replay must not reach the backend, saw %d", pb.hits())
		}
	})

	t.Run("co-sign hold does not burn the grant", func(t *testing.T) {
		b := &Backend{Name: "b", Policy: &policy.Policy{DefaultAllow: false, Rules: []policy.Rule{
			{Peers: []string{"*"}, Tools: []string{"read_secret"}, Allow: true, RequireCosign: true},
		}}, Capabilities: &CapabilitiesConfig{TrustedPublicKeys: []string{signer.PubKeyHex()}}}
		pb := &parityBackend{}
		gw, _ := startParityGateway(t, b, pb)
		tok := mintSingleUse(t, signer, "KA", "b", "read_*")

		// A require_cosign call holds — the grant is verified but NOT consumed.
		if _, body := postMCP(t, gw, "alice", "KA", "", withMeta(toolCallBody(1, "read_secret", ""), tok)); !strings.Contains(body, "co-sign") {
			t.Fatalf("expected a co-sign hold, got: %s", body)
		}
		if pb.hits() != 0 {
			t.Fatalf("a held call must not reach the backend, saw %d", pb.hits())
		}
		// The grant survived: a default-deny tool it also covers is upgraded to
		// allow, consuming the grant only now.
		if _, body := postMCP(t, gw, "alice", "KA", "", withMeta(toolCallBody(2, "read_file", ""), tok)); !strings.Contains(body, `"result"`) {
			t.Fatalf("a co-sign hold must not burn the single-use grant, got: %s", body)
		}
		if pb.hits() != 1 {
			t.Fatalf("the surviving grant's call must reach the backend, saw %d", pb.hits())
		}
		// …and it is consumed after that allow: the replay is refused.
		if _, body := postMCP(t, gw, "alice", "KA", "", withMeta(toolCallBody(3, "read_file", ""), tok)); !strings.Contains(body, "already been used") {
			t.Fatalf("the grant must be consumed after its final allow, got: %s", body)
		}
	})
}

// TestHTTPSessionStoreBounds: the label table denies (never evicts) at the
// per-peer cap, expires idle entries on the injectable clock, and DELETE drops
// an entry.
func TestHTTPSessionStoreBounds(t *testing.T) {
	now := time.Unix(1700000000, 0)
	st := newHTTPSessionStore(func() time.Time { return now })
	st.perPeer = 2

	if ok, _ := st.ensure("KA", "S1"); !ok {
		t.Fatal("S1 create failed")
	}
	st.addLabels("KA", "S1", []string{"pii"})
	if ok, _ := st.ensure("KA", "S2"); !ok {
		t.Fatal("S2 create failed")
	}
	// Cap reached: a THIRD distinct session is denied…
	if ok, reason := st.ensure("KA", "S3"); ok || !strings.Contains(reason, "capacity") {
		t.Fatalf("expected a capacity denial for S3, got ok=%v reason=%q", ok, reason)
	}
	// …and existing sessions keep enforcing their labels (nothing was evicted).
	if labels := st.snapshot("KA", "S1"); !labels["pii"] {
		t.Fatalf("S1 labels lost after the cap denial: %v", labels)
	}
	// Another peer is unaffected by KA's cap.
	if ok, _ := st.ensure("KB", "S1"); !ok {
		t.Fatal("another peer must have its own cap")
	}
	// Idle expiry on the injectable clock (documented residual ≈ stdio
	// disconnect): after the TTL the labels are gone and capacity is freed.
	now = now.Add(st.idleTTL + time.Hour)
	if ok, _ := st.ensure("KA", "S4"); !ok {
		t.Fatal("idle expiry must free capacity for S4")
	}
	if labels := st.snapshot("KA", "S1"); labels != nil {
		t.Fatalf("expired session labels must be gone, got %v", labels)
	}
	// DELETE teardown drops an entry immediately.
	st.addLabels("KA", "S4", []string{"pii"})
	st.drop("KA", "S4")
	if labels := st.snapshot("KA", "S4"); labels != nil {
		t.Fatalf("dropped session labels must be gone, got %v", labels)
	}
}

// TestHTTPSessionDeleteEndToEnd: a spec DELETE with the session header clears
// the session's taint through the real handler.
func TestHTTPSessionDeleteEndToEnd(t *testing.T) {
	pb := &parityBackend{}
	gw, _ := startParityGateway(t, &Backend{Name: "b", Policy: labelPolicy()}, pb)

	postMCP(t, gw, "alice", "KA", "S1", toolCallBody(1, "fetch_web", ""))
	if _, body := postMCP(t, gw, "alice", "KA", "S1", toolCallBody(2, "egress", "")); !strings.Contains(body, `carries label`) {
		t.Fatalf("expected a label block before DELETE, got: %s", body)
	}
	req, _ := http.NewRequest(http.MethodDelete, gw.URL+"/mcp", nil)
	req.Header.Set("X-Test-Peer", "alice")
	req.Header.Set("X-Test-Peer-Key", "KA")
	req.Header.Set(mcpSessionHeader, "S1")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	// The session was torn down: S1 is a fresh, label-clean session now.
	if _, body := postMCP(t, gw, "alice", "KA", "S1", toolCallBody(3, "egress", "")); !strings.Contains(body, `"result"`) {
		t.Fatalf("egress after DELETE teardown must be allowed, got: %s", body)
	}
}

// TestHTTPPeerIsolation: one peer can neither poison another's session labels
// (same session-id string) nor cause its responses to become a redaction
// oracle for another peer's injected credential.
func TestHTTPPeerIsolation(t *testing.T) {
	pol := &policy.Policy{DefaultAllow: false, Rules: []policy.Rule{
		{Peers: []string{"*"}, Tools: []string{"fetch_web"}, Allow: true, EmitLabels: []string{"pii"}},
		{Peers: []string{"*"}, Tools: []string{"egress"}, Allow: true, BlockLabels: []string{"pii"}},
		{Peers: []string{"*"}, Tools: []string{"*"}, Allow: true},
	}}
	pb := &parityBackend{}
	b := secretsBackend(t, "b", []string{"API_KEY"}, nil, pol)
	gw, _ := startParityGateway(t, b, pb)

	// Peer A taints session id "SHARED"; peer B using the SAME id string is
	// unaffected (the label key includes the transport-proven peer key).
	postMCP(t, gw, "alice", "KA", "SHARED", toolCallBody(1, "fetch_web", ""))
	if _, body := postMCP(t, gw, "bob", "KB", "SHARED", toolCallBody(2, "egress", "")); !strings.Contains(body, `"result"`) {
		t.Fatalf("peer B must not inherit peer A's taint, got: %s", body)
	}
	if _, body := postMCP(t, gw, "alice", "KA", "SHARED", toolCallBody(3, "egress", "")); !strings.Contains(body, `carries label`) {
		t.Fatalf("peer A must still be tainted, got: %s", body)
	}

	// Peer A injects a secret. A response to PEER B echoing A's value is NOT
	// redacted — redaction scoped per peer, so B cannot probe candidate strings
	// and use the placeholder as an oracle for A's credential.
	postMCP(t, gw, "alice", "KA", "SHARED", toolCallBody(4, "charge", `{"k":"{{secret:API_KEY}}"}`))
	pb.mu.Lock()
	pb.respond = func(w http.ResponseWriter, r *http.Request, body []byte) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":1,"result":{"probe":"%s"}}`, jsonEscaped(paritySecret))
	}
	pb.mu.Unlock()
	if _, body := postMCP(t, gw, "bob", "KB", "SHARED", toolCallBody(5, "read_file", "")); strings.Contains(body, "[redacted-secret]") {
		t.Fatalf("peer B's responses must not reveal (by redaction) that the probe matched peer A's secret: %s", body)
	}
	// The same echo to PEER A is scrubbed.
	if _, body := postMCP(t, gw, "alice", "KA", "SHARED", toolCallBody(6, "read_file", "")); !strings.Contains(body, "[redacted-secret]") {
		t.Fatalf("peer A's echoed secret must be scrubbed, got: %s", body)
	}
}

// TestHTTPCompressedResponseRefusedWithActiveRedactor: once a secret is in
// play, a response the gateway cannot scan (an encoding the transport did not
// decode) is refused with 502 — never forwarded unscanned.
func TestHTTPCompressedResponseRefusedWithActiveRedactor(t *testing.T) {
	pb := &parityBackend{}
	pb.respond = func(w http.ResponseWriter, r *http.Request, body []byte) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", "br")
		_, _ = w.Write([]byte("opaque-compressed-bytes"))
	}
	gw, _ := startParityGateway(t, secretsBackend(t, "b", []string{"API_KEY"}, nil, nil), pb)

	status, body := postMCP(t, gw, "alice", "KA", "", toolCallBody(1, "charge", `{"k":"{{secret:API_KEY}}"}`))
	if status != http.StatusBadGateway {
		t.Fatalf("unscannable response must be refused with 502, got %d: %s", status, body)
	}
	if strings.Contains(body, "opaque-compressed-bytes") {
		t.Fatalf("refused response bytes must not be forwarded: %s", body)
	}
}

// TestHTTPPendingCosignBindingAndApproval: a held HTTP co-sign records
// args_hash + policy_hash (the request-bound binding stdio records), and a
// signed approval minted for exactly that binding releases ONE retry.
func TestHTTPPendingCosignBindingAndApproval(t *testing.T) {
	dir := t.TempDir()
	signer, err := policy.GenerateSigner()
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(t.TempDir(), "approval.key")
	if err := signer.SaveSigner(keyPath); err != nil {
		t.Fatal(err)
	}
	pol := &policy.Policy{DefaultAllow: false, Rules: []policy.Rule{
		{Peers: []string{"*"}, Tools: []string{"charge"}, Allow: true, RequireCosign: true},
	}}
	pb := &parityBackend{}
	b := &Backend{Name: "pay", Policy: pol, CosignStore: dir, CosignTTLSeconds: 300, ApprovalSigningKey: keyPath}
	gw, enf := startParityGateway(t, b, pb)

	args := `{"amount":42}`
	if _, body := postMCP(t, gw, "alice", "KA", "", toolCallBody(1, "charge", args)); !strings.Contains(body, "co-sign") {
		t.Fatalf("expected a co-sign hold, got: %s", body)
	}
	pending := &policy.FilePending{Dir: dir, TTL: 300 * time.Second}
	held, err := pending.List()
	if err != nil || len(held) != 1 {
		t.Fatalf("expected 1 pending record, got %d (%v)", len(held), err)
	}
	if held[0].ArgsHash == "" || held[0].PolicyHash == "" {
		t.Fatalf("HTTP pending record must carry the request binding, got %+v", held[0])
	}
	if held[0].PolicyHash != enf.eng.PolicyHash() {
		t.Fatal("pending policy_hash must match the engine's live policy hash")
	}
	// Approve exactly this binding and retry: released once, then held again.
	store := policy.NewFileApprovalStore(dir, 300*time.Second, signer)
	if _, err := store.Grant(held[0].ApprovalRequest(), "approver", held[0].PolicyHash, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, body := postMCP(t, gw, "alice", "KA", "", toolCallBody(2, "charge", args)); !strings.Contains(body, `"result"`) {
		t.Fatalf("approved retry must be released, got: %s", body)
	}
	if pb.hits() != 1 {
		t.Fatalf("exactly one call may reach the backend, saw %d", pb.hits())
	}
	// Different arguments do not match the approval; the same arguments are
	// single-use.
	if _, body := postMCP(t, gw, "alice", "KA", "", toolCallBody(3, "charge", args)); !strings.Contains(body, "co-sign") {
		t.Fatalf("a consumed approval must not release a second call, got: %s", body)
	}
}

// TestCapabilityFoldConformanceStdioHTTP pins the shared FoldCapability: the
// stdio filter and the HTTP enforcer agree on every (policy, token) outcome.
func TestCapabilityFoldConformanceStdioHTTP(t *testing.T) {
	signer, err := policy.GenerateSigner()
	if err != nil {
		t.Fatal(err)
	}
	const peer, key = "p.mesh", "PEERKEY"
	pol := &policy.Policy{DefaultAllow: false, Rules: []policy.Rule{
		{Peers: []string{"*"}, Tools: []string{"banned"}, Allow: false},
		{Peers: []string{"*"}, Tools: []string{"listed_*"}, Allow: true},
	}}
	valid := mintCapability(t, signer, key, "b", "read_*")
	banned := mintCapability(t, signer, key, "b", "banned")

	cases := []struct {
		name     string
		required bool
		line     string
		allowed  bool
	}{
		{"tokenless default-deny", false, toolCallBody(1, "read_file", ""), false},
		{"valid token upgrades", false, withMeta(toolCallBody(2, "read_file", ""), valid), true},
		{"token cannot override explicit deny", false, withMeta(toolCallBody(3, "banned", ""), banned), false},
		{"token for another tool glob", false, withMeta(toolCallBody(4, "write_file", ""), valid), false},
		{"required tokenless denies even rule-allowed", true, toolCallBody(5, "listed_thing", ""), false},
		{"required with valid token", true, withMeta(toolCallBody(6, "read_file", ""), valid), true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			stdio := stdioCapReaches(t, pol, signer.PubKeyHex(), c.required, peer, key, c.line)
			httpd := httpCapReaches(t, pol, signer.PubKeyHex(), c.required, peer, key, c.line)
			if stdio != httpd {
				t.Fatalf("DRIFT: stdio reached=%v http reached=%v for %q", stdio, httpd, c.line)
			}
			if stdio != c.allowed {
				t.Fatalf("both transports agreed (reached=%v) but expected %v", stdio, c.allowed)
			}
		})
	}
}

func stdioCapReaches(t *testing.T, pol *policy.Policy, pubHex string, required bool, peer, key, line string) bool {
	t.Helper()
	backend := newConfBackend()
	f := policy.NewFilter(backend, policy.Caller{Backend: "b", Peer: peer, PeerKey: key}, pol,
		policy.NewAuditLog(io.Discard, func() string { return "T" }), nil)
	v, err := policy.NewCapabilityVerifier([]string{pubHex}, nil)
	if err != nil {
		t.Fatal(err)
	}
	f.SetCapabilityVerifier(v, required)
	go func() {
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 64*1024), 1<<20)
		for sc.Scan() {
		}
	}()
	if _, err := f.Write([]byte(line + "\n")); err != nil {
		return false
	}
	return backend.received()
}

func httpCapReaches(t *testing.T, pol *policy.Policy, pubHex string, required bool, peer, key, body string) bool {
	t.Helper()
	b := &Backend{Name: "b", Policy: pol,
		Capabilities: &CapabilitiesConfig{Required: required, TrustedPublicKeys: []string{pubHex}}}
	enf, err := newHTTPEnforcer(b, policy.NewAuditLog(io.Discard, func() string { return "T" }))
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, "http://x/mcp", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	ok, _, _ := enf.decide(peer, key, req)
	return ok
}

// TestRemoteBackendSecretParity: the SAME enforcer gives a "remote" backend
// request-side injection and response-side redaction — the rewritten body
// reaches the upstream, and the buffered response is scrubbed (with an
// unscannable encoding refused).
func TestRemoteBackendSecretParity(t *testing.T) {
	esc := jsonEscaped(paritySecret)
	var compressed atomic.Bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if !bytes.Contains(body, []byte(esc)) {
			t.Errorf("upstream must receive the injected value, got: %s", body)
		}
		if bytes.Contains(body, []byte("{{secret:")) {
			t.Errorf("upstream must not see the marker: %s", body)
		}
		if compressed.Load() {
			w.Header().Set("Content-Encoding", "br")
			_, _ = w.Write([]byte("opaque"))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":1,"result":{"echo":"%s"}}`, esc)
	}))
	defer upstream.Close()
	u, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	rc := &remoteClient{name: "r", endpoint: u, clientID: "c", httpClient: upstream.Client(), now: time.Now}

	b := secretsBackend(t, "r", []string{"API_KEY"}, nil, nil)
	enf, err := newHTTPEnforcer(b, policy.NewAuditLog(io.Discard, func() string { return "T" }))
	if err != nil {
		t.Fatal(err)
	}
	identify := func(r *http.Request) (string, string) {
		return r.Header.Get("X-Test-Peer-Key"), r.Header.Get("X-Test-Peer")
	}
	gw := httptest.NewServer(remoteHandler("r", newACL(nil), enf, rc, identify))
	defer gw.Close()

	do := func(id int) (int, string, http.Header) {
		req, _ := http.NewRequest(http.MethodPost, gw.URL+"/mcp",
			strings.NewReader(toolCallBody(id, "charge", `{"token":"{{secret:API_KEY}}"}`)))
		req.Header.Set("X-Test-Peer", "alice")
		req.Header.Set("X-Test-Peer-Key", "KA")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		rb, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(rb), resp.Header
	}

	status, body, hdr := do(1)
	if status != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", status, body)
	}
	if strings.Contains(body, esc) || strings.Contains(body, paritySecret) {
		t.Fatalf("remote response must be scrubbed: %s", body)
	}
	if !strings.Contains(body, "[redacted-secret]") {
		t.Fatalf("expected a redaction placeholder, got: %s", body)
	}
	if cl := hdr.Get("Content-Length"); cl != fmt.Sprint(len(body)) {
		t.Fatalf("redacted Content-Length must match the body: header %s, body %d", cl, len(body))
	}
	// An encoding the gateway cannot scan is refused once a redactor is active.
	compressed.Store(true)
	status, body, _ = do(2)
	if status != http.StatusBadGateway || strings.Contains(body, "opaque") {
		t.Fatalf("unscannable remote response must be refused with 502, got %d: %s", status, body)
	}
}

// TestHTTPRedactorCapacityDenies: an injection that would exceed the per-peer
// redaction capacity is refused (a value that cannot be remembered cannot be
// scrubbed — fail closed, never fail open).
func TestHTTPRedactorCapacityDenies(t *testing.T) {
	t.Setenv("MESHPARITY_K1", "secret-value-one-1234")
	t.Setenv("MESHPARITY_K2", "secret-value-two-5678")
	pb := &parityBackend{}
	b := &Backend{Name: "b",
		Policy:  &policy.Policy{DefaultAllow: false, Rules: []policy.Rule{{Peers: []string{"*"}, Tools: []string{"*"}, Allow: true}}},
		Secrets: &SecretsConfig{EnvPrefix: "MESHPARITY_", Grants: []secrets.Grant{{Peers: []string{"*"}, Secrets: []string{"*"}}}}}
	gw, enf := startParityGateway(t, b, pb)
	enf.sessions.redCap = 1 // test hook: one remembered value per peer

	if _, body := postMCP(t, gw, "alice", "KA", "", toolCallBody(1, "charge", `{"k":"{{secret:K1}}"}`)); !strings.Contains(body, `"result"`) {
		t.Fatalf("first injection must fit the capacity, got: %s", body)
	}
	if _, body := postMCP(t, gw, "alice", "KA", "", toolCallBody(2, "charge", `{"k":"{{secret:K2}}"}`)); !strings.Contains(body, "secret-redaction capacity") {
		t.Fatalf("over-capacity injection must be refused, got: %s", body)
	}
	if pb.hits() != 1 {
		t.Fatalf("the refused injection must not reach the backend, saw %d hits", pb.hits())
	}
}
