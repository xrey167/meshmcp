// mcphttp is a minimal HTTP (Streamable-HTTP-style) MCP server, used to
// exercise meshmcp's `http:` backend path. Its whoami tool returns the
// mesh identity the gateway stamped into the request headers, proving the
// reverse proxy + identity-header path end to end.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"

	"github.com/xrey167/meshmcp/mcp"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:3001", "listen address")
	flag.Parse()

	s := mcp.New("mcphttp", "0.1.0")
	s.AddTool(mcp.Tool{
		Name:        "whoami",
		Description: "Return the mesh identity the gateway stamped into the request headers.",
		Handler: func(ctx context.Context, _ json.RawMessage) (mcp.ToolResult, error) {
			h := mcp.HTTPHeadersFrom(ctx)
			peer, key := "", ""
			if h != nil {
				peer = h.Get("X-Meshmcp-Peer")
				key = h.Get("X-Meshmcp-Peer-Key")
			}
			return mcp.ToolResult{Content: []mcp.Content{
				mcp.Text(fmt.Sprintf("you are %s (key %s)", peer, key)),
			}}, nil
		},
	})
	s.AddTool(mcp.Tool{
		Name: "add",
		Handler: func(_ context.Context, args json.RawMessage) (mcp.ToolResult, error) {
			var a struct{ A, B float64 }
			_ = json.Unmarshal(args, &a)
			return mcp.ToolResult{Content: []mcp.Content{mcp.Text(fmt.Sprintf("%v", a.A+a.B))}}, nil
		},
	})

	fmt.Fprintf(os.Stderr, "mcphttp: listening on %s\n", *addr)
	if err := http.ListenAndServe(*addr, s.HTTPHandler()); err != nil {
		fmt.Fprintln(os.Stderr, "mcphttp:", err)
		os.Exit(1)
	}
}
