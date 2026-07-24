package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func httpEchoServer() *Server {
	s := New("http", "1.0")
	s.AddTool(Tool{
		Name: "echo",
		Handler: func(ctx context.Context, args json.RawMessage) (ToolResult, error) {
			return ToolResult{Content: []Content{Text(string(args))}}, nil
		},
	})
	return s
}

// TestHTTPBodyCap proves the HTTP transport bounds the request body: a normal
// message is served, but a body past the cap is rejected with 413 rather than
// being buffered whole into memory (a memory-exhaustion vector on any http:
// backend serving HTTPHandler).
func TestHTTPBodyCap(t *testing.T) {
	srv := httptest.NewServer(httpEchoServer().HTTPHandler())
	defer srv.Close()

	// A normal request is served.
	ok := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"hi":1}}}`
	resp, err := http.Post(srv.URL, "application/json", strings.NewReader(ok))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("normal request status = %d, want 200", resp.StatusCode)
	}
	resp.Body.Close()

	// A body past the cap is refused with 413 (not OK, not a hang/OOM).
	huge := fmt.Sprintf(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{"x":%q}}}`,
		strings.Repeat("A", maxHTTPBodyBytes+1024))
	resp2, err := http.Post(srv.URL, "application/json", strings.NewReader(huge))
	if err != nil {
		t.Fatalf("post huge: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body status = %d, want 413", resp2.StatusCode)
	}
}
