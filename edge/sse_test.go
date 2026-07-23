package edge

import (
	"bufio"
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
)

// backendWithNotifier returns a dialer whose backend, on the "emit" tool, sends
// a server notification back over the session — exercising the SSE relay.
func backendWithNotifier(t testing.TB) DialBackend {
	t.Helper()
	return func(ctx context.Context) (net.Conn, error) {
		clientSide, serverSide := net.Pipe()
		srv := mcp.New("notifier-backend", "1.0")
		srv.AddTool(mcp.Tool{
			Name: "search_docs",
			Handler: func(hctx context.Context, args json.RawMessage) (mcp.ToolResult, error) {
				if sess := mcp.SessionFrom(hctx); sess != nil {
					sess.Notify("notifications/message", map[string]any{"level": "info", "data": "hello-sse"})
				}
				return mcp.ToolResult{Content: []mcp.Content{mcp.Text("ok")}}, nil
			},
		})
		go func() {
			_ = srv.Serve(context.Background(), serverSide, serverSide)
			serverSide.Close()
		}()
		return clientSide, nil
	}
}

func TestMCPSSEStreamRelaysNotification(t *testing.T) {
	dir := t.TempDir()
	cfg := validConfig()
	cfg.StateDir = dir
	cfg.AuditLog = dir + "/audit.jsonl"
	cfg.SigningKey = dir + "/key.json"
	cfg.Limits.RegisterPerIPPerMin = 10000
	cfg.Limits.PreauthPerIPPerMin = 10000
	cfg.Limits.PerClientRPS = 10000
	cfg.Backend.Tools = []string{"search_*"}
	cfg.Backend.Policy = policyAllowSearch()
	srv, err := New(cfg, Options{
		Now:         time.Now,
		Signer:      mustSigner(t),
		AuditWriter: &discardWriter{},
		DialBackend: backendWithNotifier(t),
	})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	clientID := approvedClient(t, srv, ts, testRedirect)
	verifier, challenge := pkcePair()
	code := runAuthorize(t, srv, ts, clientID, testRedirect, challenge, "s")
	_, tok := postToken(t, ts.URL, url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "client_id": {clientID},
		"redirect_uri": {testRedirect}, "code_verifier": {verifier},
	})
	token := tok.AccessToken

	// initialize → session.
	resp := mcpPostReq(t, ts.URL, token, "", `{"jsonrpc":"2.0","id":1,"method":"initialize"}`)
	sid := resp.Header.Get(headerSessionID)
	resp.Body.Close()
	if sid == "" {
		t.Fatal("no session id")
	}

	// Open the SSE stream.
	greq, _ := http.NewRequest(http.MethodGet, ts.URL+pathMCP, nil)
	greq.Header.Set("Authorization", "Bearer "+token)
	greq.Header.Set(headerSessionID, sid)
	greq.Header.Set("Accept", "text/event-stream")
	gresp, err := http.DefaultClient.Do(greq)
	if err != nil {
		t.Fatal(err)
	}
	defer gresp.Body.Close()
	if ct := gresp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		t.Fatalf("SSE content-type = %q", ct)
	}

	// Trigger a tool call that makes the backend emit a notification.
	go func() {
		time.Sleep(50 * time.Millisecond)
		r := mcpPostReq(t, ts.URL, token, sid, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"search_docs","arguments":{}}}`)
		r.Body.Close()
	}()

	// Read SSE lines until we see the relayed notification (or time out).
	done := make(chan string, 1)
	go func() {
		sc := bufio.NewScanner(gresp.Body)
		for sc.Scan() {
			line := sc.Text()
			if strings.Contains(line, "hello-sse") {
				done <- line
				return
			}
		}
		done <- ""
	}()

	select {
	case line := <-done:
		if !strings.Contains(line, "hello-sse") {
			t.Fatalf("did not receive relayed notification, got %q", line)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for SSE notification")
	}
}

func TestMCPSSEExpiryCut(t *testing.T) {
	dir := t.TempDir()
	cfg := validConfig()
	cfg.StateDir = dir
	cfg.AuditLog = dir + "/audit.jsonl"
	cfg.SigningKey = dir + "/key.json"
	cfg.Limits.RegisterPerIPPerMin = 10000
	cfg.Limits.PreauthPerIPPerMin = 10000
	cfg.Limits.PerClientRPS = 10000
	cfg.Backend.Tools = []string{"search_*"}
	cfg.Backend.Policy = policyAllowSearch()
	// Very short access-token TTL so the SSE stream is cut quickly.
	cfg.OAuth.AccessTokenTTL = Duration(2 * time.Second)
	srv, err := New(cfg, Options{
		Now:         time.Now,
		Signer:      mustSigner(t),
		AuditWriter: &discardWriter{},
		DialBackend: startBackend(t),
	})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	clientID := approvedClient(t, srv, ts, testRedirect)
	verifier, challenge := pkcePair()
	code := runAuthorize(t, srv, ts, clientID, testRedirect, challenge, "s")
	_, tok := postToken(t, ts.URL, url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "client_id": {clientID},
		"redirect_uri": {testRedirect}, "code_verifier": {verifier},
	})
	token := tok.AccessToken

	resp := mcpPostReq(t, ts.URL, token, "", `{"jsonrpc":"2.0","id":1,"method":"initialize"}`)
	sid := resp.Header.Get(headerSessionID)
	resp.Body.Close()

	greq, _ := http.NewRequest(http.MethodGet, ts.URL+pathMCP, nil)
	greq.Header.Set("Authorization", "Bearer "+token)
	greq.Header.Set(headerSessionID, sid)
	gresp, err := http.DefaultClient.Do(greq)
	if err != nil {
		t.Fatal(err)
	}
	defer gresp.Body.Close()

	// The stream must close on its own within a few seconds (token expiry cut).
	done := make(chan bool, 1)
	go func() {
		sc := bufio.NewScanner(gresp.Body)
		for sc.Scan() {
		}
		done <- true
	}()
	select {
	case <-done:
	case <-time.After(6 * time.Second):
		t.Fatal("SSE stream was not cut after token expiry")
	}
}
