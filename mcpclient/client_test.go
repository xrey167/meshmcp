package mcpclient

import (
	"context"
	"encoding/json"
	"io"
	"testing"
	"time"

	"github.com/xrey167/meshmcp/mcp"
)

// rwPipe adapts a read half and a write half into one io.ReadWriteCloser.
type rwPipe struct {
	r *io.PipeReader
	w *io.PipeWriter
}

func (p rwPipe) Read(b []byte) (int, error)  { return p.r.Read(b) }
func (p rwPipe) Write(b []byte) (int, error) { return p.w.Write(b) }
func (p rwPipe) Close() error                { p.r.Close(); return p.w.Close() }

func TestClientAgainstServer(t *testing.T) {
	// Wire an mcp.Server to the client over crossed pipes.
	c2sR, c2sW := io.Pipe() // client -> server
	s2cR, s2cW := io.Pipe() // server -> client

	s := mcp.New("test", "1.0")
	s.AddTool(mcp.Tool{
		Name: "add",
		Handler: func(_ context.Context, args json.RawMessage) (mcp.ToolResult, error) {
			var a struct{ A, B float64 }
			_ = json.Unmarshal(args, &a)
			return mcp.ToolResult{Content: []mcp.Content{mcp.Text("sum")}}, nil
		},
	})
	go func() { _ = s.Serve(context.Background(), c2sR, s2cW); s2cW.Close() }()

	c := New(rwPipe{r: s2cR, w: c2sW}, nil)
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if _, err := c.Initialize(ctx, "tester"); err != nil {
		t.Fatalf("initialize: %v", err)
	}
	tools, err := c.ListTools(ctx)
	if err != nil {
		t.Fatalf("tools/list: %v", err)
	}
	if len(tools) != 1 || tools[0].Name != "add" {
		t.Fatalf("unexpected tools: %+v", tools)
	}
	res, err := c.CallTool(ctx, "add", map[string]any{"a": 2, "b": 3}, false)
	if err != nil {
		t.Fatalf("tools/call: %v", err)
	}
	if len(res) == 0 {
		t.Fatalf("empty result")
	}

	// Unknown tool surfaces as an RPC error.
	if _, err := c.CallTool(ctx, "nope", nil, false); err == nil {
		t.Fatalf("expected error for unknown tool")
	}
}
