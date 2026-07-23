package edge

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/xrey167/meshmcp/mcp"
	"github.com/xrey167/meshmcp/policy"
)

func mustSigner(t testing.TB) *policy.Signer {
	t.Helper()
	s, err := policy.GenerateSigner()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func policyAllowSearch() policy.Policy {
	return policy.Policy{Rules: []policy.Rule{{Peers: []string{"oauth:*"}, Tools: []string{"search_*"}, Allow: true}}}
}

func policyAllowAllTools() policy.Policy {
	return policy.Policy{Rules: []policy.Rule{{Peers: []string{"oauth:*"}, Tools: []string{"*"}, Allow: true}}}
}

// startBackend returns a DialBackend that connects each call to a fresh
// in-process mcp.Server exposing search_docs and forbidden_tool, over net.Pipe.
func startBackend(t testing.TB) DialBackend {
	t.Helper()
	build := func() *mcp.Server {
		srv := mcp.New("test-backend", "1.0")
		srv.AddTool(mcp.Tool{
			Name: "search_docs",
			Handler: func(ctx context.Context, args json.RawMessage) (mcp.ToolResult, error) {
				return mcp.ToolResult{Content: []mcp.Content{mcp.Text("found: " + string(args))}}, nil
			},
		})
		srv.AddTool(mcp.Tool{
			Name: "forbidden_tool",
			Handler: func(ctx context.Context, args json.RawMessage) (mcp.ToolResult, error) {
				return mcp.ToolResult{Content: []mcp.Content{mcp.Text("should never run")}}, nil
			},
		})
		return srv
	}
	return func(ctx context.Context) (net.Conn, error) {
		clientSide, serverSide := net.Pipe()
		srv := build()
		go func() {
			_ = srv.Serve(context.Background(), serverSide, serverSide)
			serverSide.Close()
		}()
		return clientSide, nil
	}
}

// newMCPServer builds an edge server wired to an in-process backend and an
// approved client with a live access token, returning the token and ids.
func newMCPServer(t *testing.T, mutate func(*Config)) (*Server, *httptest.Server, string, string) {
	t.Helper()
	dir := t.TempDir()
	cfg := validConfig()
	cfg.StateDir = dir
	cfg.AuditLog = dir + "/audit.jsonl"
	cfg.SigningKey = dir + "/key.json"
	cfg.Limits.RegisterPerIPPerMin = 10000
	cfg.Limits.PreauthPerIPPerMin = 10000
	cfg.Limits.PerClientRPS = 10000
	// Policy: allow search_*, deny everything else (default_allow false).
	cfg.Backend.Tools = []string{"search_*", "forbidden_tool"}
	cfg.Backend.Policy = policyAllowSearch()
	if mutate != nil {
		mutate(&cfg)
	}
	signer := mustSigner(t)
	srv, err := New(cfg, Options{
		Now:         func() time.Time { return time.Now() },
		Signer:      signer,
		AuditWriter: &discardWriter{},
		DialBackend: startBackend(t),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	clientID := approvedClient(t, srv, ts, testRedirect)
	verifier, challenge := pkcePair()
	code := runAuthorize(t, srv, ts, clientID, testRedirect, challenge, "s")
	_, tok := postToken(t, ts.URL, url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "client_id": {clientID},
		"redirect_uri": {testRedirect}, "code_verifier": {verifier},
	})
	return srv, ts, clientID, tok.AccessToken
}

// mcpPost sends a JSON-RPC request to /mcp with the bearer and optional session.
func mcpPostReq(t *testing.T, base, token, sessionID, body string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, base+pathMCP, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if sessionID != "" {
		req.Header.Set(headerSessionID, sessionID)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestMCPUnauthenticatedChallenge(t *testing.T) {
	_, ts, _, _ := newMCPServer(t, nil)
	resp := mcpPostReq(t, ts.URL, "", "", `{"jsonrpc":"2.0","id":1,"method":"initialize"}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no token → want 401, got %d", resp.StatusCode)
	}

	resp2 := mcpPostReq(t, ts.URL, "garbage-token", "", `{"jsonrpc":"2.0","id":1,"method":"initialize"}`)
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("bad token → want 401, got %d", resp2.StatusCode)
	}
}

func TestMCPInitializeAndToolCall(t *testing.T) {
	_, ts, _, token := newMCPServer(t, nil)

	// initialize opens a session.
	resp := mcpPostReq(t, ts.URL, token, "", `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
	sid := resp.Header.Get(headerSessionID)
	resp.Body.Close()
	if sid == "" {
		t.Fatal("initialize must issue an Mcp-Session-Id")
	}

	// tools/call for a permitted tool.
	resp = mcpPostReq(t, ts.URL, token, sid, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"search_docs","arguments":{"q":"hi"}}}`)
	body := decodeRPC(t, resp)
	resp.Body.Close()
	if body["error"] != nil {
		t.Fatalf("permitted tool call returned error: %v", body["error"])
	}
	if body["result"] == nil {
		t.Fatalf("permitted tool call missing result: %v", body)
	}
}

func TestMCPPolicyDeniesForbiddenTool(t *testing.T) {
	_, ts, _, token := newMCPServer(t, nil)
	resp := mcpPostReq(t, ts.URL, token, "", `{"jsonrpc":"2.0","id":1,"method":"initialize"}`)
	sid := resp.Header.Get(headerSessionID)
	resp.Body.Close()

	// forbidden_tool is within the capability but denied by policy (only search_*
	// is allowed) → the double-gate's policy leg blocks it.
	resp = mcpPostReq(t, ts.URL, token, sid, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"forbidden_tool","arguments":{}}}`)
	body := decodeRPC(t, resp)
	resp.Body.Close()
	if body["error"] == nil {
		t.Fatal("policy must deny forbidden_tool")
	}
}

func TestMCPCapabilityGateDeniesUncoveredTool(t *testing.T) {
	// A tool not in the capability's tool set is denied by the capability leg even
	// if policy would allow it.
	_, ts, _, token := newMCPServer(t, func(c *Config) {
		c.Backend.Tools = []string{"search_*"}   // capability covers only search_*
		c.Backend.Policy = policyAllowAllTools() // policy allows everything
	})
	resp := mcpPostReq(t, ts.URL, token, "", `{"jsonrpc":"2.0","id":1,"method":"initialize"}`)
	sid := resp.Header.Get(headerSessionID)
	resp.Body.Close()

	resp = mcpPostReq(t, ts.URL, token, sid, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"other_tool","arguments":{}}}`)
	body := decodeRPC(t, resp)
	resp.Body.Close()
	if body["error"] == nil {
		t.Fatal("capability gate must deny a tool outside the grant")
	}
}

func TestMCPSessionValidation(t *testing.T) {
	srv, ts, clientID, token := newMCPServer(t, nil)

	resp := mcpPostReq(t, ts.URL, token, "", `{"jsonrpc":"2.0","id":1,"method":"initialize"}`)
	sid := resp.Header.Get(headerSessionID)
	resp.Body.Close()

	// Unknown session → 404.
	r2 := mcpPostReq(t, ts.URL, token, "deadbeef", `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	r2.Body.Close()
	if r2.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown session → want 404, got %d", r2.StatusCode)
	}

	// A second client cannot use the first's session.
	other := approvedClient(t, srv, ts, testRedirect)
	verifier, challenge := pkcePair()
	code := runAuthorize(t, srv, ts, other, testRedirect, challenge, "s")
	_, otok := postToken(t, ts.URL, url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "client_id": {other},
		"redirect_uri": {testRedirect}, "code_verifier": {verifier},
	})
	r3 := mcpPostReq(t, ts.URL, otok.AccessToken, sid, `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	r3.Body.Close()
	if r3.StatusCode != http.StatusNotFound {
		t.Fatalf("cross-client session use → want 404, got %d", r3.StatusCode)
	}
	_ = clientID

	// DELETE ends the session.
	req, _ := http.NewRequest(http.MethodDelete, ts.URL+pathMCP, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set(headerSessionID, sid)
	dr, _ := http.DefaultClient.Do(req)
	dr.Body.Close()
	if dr.StatusCode != http.StatusNoContent {
		t.Fatalf("DELETE session → want 204, got %d", dr.StatusCode)
	}
	// The session is gone now.
	r4 := mcpPostReq(t, ts.URL, token, sid, `{"jsonrpc":"2.0","id":3,"method":"tools/list"}`)
	r4.Body.Close()
	if r4.StatusCode != http.StatusNotFound {
		t.Fatalf("deleted session → want 404, got %d", r4.StatusCode)
	}
}

func TestMCPStatelessMode(t *testing.T) {
	_, ts, _, token := newMCPServer(t, func(c *Config) {
		off := false
		c.OAuth.Sessions = &off
	})
	// No session headers are issued or required.
	resp := mcpPostReq(t, ts.URL, token, "", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search_docs","arguments":{}}}`)
	if sid := resp.Header.Get(headerSessionID); sid != "" {
		t.Fatalf("stateless mode must not issue a session id, got %q", sid)
	}
	body := decodeRPC(t, resp)
	resp.Body.Close()
	if body["result"] == nil {
		t.Fatalf("stateless tool call should succeed: %v", body)
	}
	// GET must be refused when sessions are disabled.
	req, _ := http.NewRequest(http.MethodGet, ts.URL+pathMCP, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	gr, _ := http.DefaultClient.Do(req)
	gr.Body.Close()
	if gr.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET with sessions disabled → want 405, got %d", gr.StatusCode)
	}
}

func TestMCPProtocolVersionValidation(t *testing.T) {
	_, ts, _, token := newMCPServer(t, nil)
	req, _ := http.NewRequest(http.MethodPost, ts.URL+pathMCP, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set(headerProtocolVersion, "1999-01-01")
	resp, _ := http.DefaultClient.Do(req)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("unsupported protocol version → want 400, got %d", resp.StatusCode)
	}
}

func decodeRPC(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		t.Fatalf("decode rpc: %v", err)
	}
	return m
}

type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }
