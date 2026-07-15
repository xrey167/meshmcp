// mcpecho is a minimal but real MCP stdio server used as a resumable
// backend for live end-to-end testing of meshmcp. It speaks newline-
// delimited JSON-RPC 2.0 and implements initialize, tools/list,
// tools/call (an "echo" tool), and ping.
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
)

type rpcReq struct {
	JSONRPC string           `json:"jsonrpc"`
	ID      *json.RawMessage `json:"id,omitempty"`
	Method  string           `json:"method"`
	Params  json.RawMessage  `json:"params,omitempty"`
}

func main() {
	fmt.Fprintf(os.Stderr, "mcpecho: started for peer %q\n", os.Getenv("MESHMCP_PEER"))

	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 1<<20), 1<<20)
	out := bufio.NewWriter(os.Stdout)

	for in.Scan() {
		line := bytes.TrimSpace(in.Bytes())
		if len(line) == 0 {
			continue
		}
		var req rpcReq
		if err := json.Unmarshal(line, &req); err != nil {
			continue
		}
		if req.ID == nil {
			continue // JSON-RPC notification: no reply
		}

		var result any
		switch req.Method {
		case "initialize":
			result = map[string]any{
				"protocolVersion": "2025-06-18",
				"capabilities":    map[string]any{"tools": map[string]any{}},
				"serverInfo":      map[string]any{"name": "mcpecho", "version": "0.1.0"},
			}
		case "tools/list":
			result = map[string]any{"tools": []any{map[string]any{
				"name":        "echo",
				"description": "echoes the provided text",
				"inputSchema": map[string]any{
					"type":       "object",
					"properties": map[string]any{"text": map[string]any{"type": "string"}},
				},
			}}}
		case "tools/call":
			result = map[string]any{"content": []any{map[string]any{
				"type": "text", "text": "echo: " + callText(req.Params),
			}}}
		case "ping":
			result = map[string]any{}
		default:
			writeResp(out, map[string]any{
				"jsonrpc": "2.0", "id": req.ID,
				"error": map[string]any{"code": -32601, "message": "method not found"},
			})
			continue
		}
		writeResp(out, map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": result})
	}
}

func callText(params json.RawMessage) string {
	var p struct {
		Name      string `json:"name"`
		Arguments struct {
			Text string `json:"text"`
		} `json:"arguments"`
	}
	_ = json.Unmarshal(params, &p)
	return p.Arguments.Text
}

func writeResp(out *bufio.Writer, v any) {
	b, _ := json.Marshal(v)
	out.Write(b)
	out.WriteByte('\n')
	out.Flush()
}
