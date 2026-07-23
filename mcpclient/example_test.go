package mcpclient_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"

	"github.com/xrey167/meshmcp/mcp"
	"github.com/xrey167/meshmcp/mcpclient"
)

// examplePipe adapts a read half and a write half into one io.ReadWriteCloser
// — the shape mcpclient.New consumes. In production this is a mesh connection
// (client.Dial over WireGuard); here it is an in-process pipe so the example
// runs anywhere.
type examplePipe struct {
	r *io.PipeReader
	w *io.PipeWriter
}

func (p examplePipe) Read(b []byte) (int, error)  { return p.r.Read(b) }
func (p examplePipe) Write(b []byte) (int, error) { return p.w.Write(b) }
func (p examplePipe) Close() error                { p.r.Close(); return p.w.Close() }

// Example shows the whole client lifecycle against an MCP server: connect,
// initialize, discover tools, and call one. Against a real gateway the only
// change is the transport — dial the backend's mesh address and hand the
// connection to New; everything after that line is identical.
func Example() {
	// An in-process MCP server standing in for a meshmcp backend.
	c2sR, c2sW := io.Pipe()
	s2cR, s2cW := io.Pipe()
	srv := mcp.New("demo-backend", "1.0")
	srv.AddTool(mcp.Tool{
		Name:        "add",
		Description: "add two numbers",
		Handler: func(_ context.Context, args json.RawMessage) (mcp.ToolResult, error) {
			var in struct{ A, B float64 }
			if err := json.Unmarshal(args, &in); err != nil {
				return mcp.ToolResult{}, err
			}
			return mcp.ToolResult{Content: []mcp.Content{mcp.Text(fmt.Sprintf("%g", in.A+in.B))}}, nil
		},
	})
	go func() { _ = srv.Serve(context.Background(), c2sR, s2cW); s2cW.Close() }()

	// The client: New starts the read loop; Initialize performs the MCP
	// handshake; then list and call tools.
	c := mcpclient.New(examplePipe{r: s2cR, w: c2sW}, nil)
	defer c.Close()
	ctx := context.Background()

	if _, err := c.Initialize(ctx, "example-client"); err != nil {
		log.Fatal(err)
	}
	tools, err := c.ListTools(ctx)
	if err != nil {
		log.Fatal(err)
	}
	for _, t := range tools {
		fmt.Printf("tool: %s — %s\n", t.Name, t.Description)
	}

	raw, err := c.CallTool(ctx, "add", map[string]any{"a": 2, "b": 40}, false)
	if err != nil {
		log.Fatal(err)
	}
	var result struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("add(2, 40) = %s\n", result.Content[0].Text)

	// Output:
	// tool: add — add two numbers
	// add(2, 40) = 42
}
