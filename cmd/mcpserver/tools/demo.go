package tools

import (
	"context"
	"encoding/json"

	"meshmcp/mcp"
)

// registerDemo adds a few canned tools used by the mesh showcase agents so
// their allowed calls return a believable result. The interesting behavior in
// the demo happens at the gateway (policy, taint, secret injection, co-sign),
// not in these handlers — they just echo enough to look real.
func registerDemo(s *mcp.Server) {
	// fetch — a stand-in web fetcher. In the demo this tool is a taint_source,
	// so calling it marks the session tainted at the gateway.
	s.AddTool(mcp.Tool{
		Name:        "fetch",
		Description: "Fetch a URL and return its (stub) contents.",
		InputSchema: objSchema(map[string]any{"url": strProp("URL to fetch")}, "url"),
		Handler: func(_ context.Context, args json.RawMessage) (mcp.ToolResult, error) {
			var a struct {
				URL string `json:"url"`
			}
			_ = json.Unmarshal(args, &a)
			return textResult("fetched " + a.URL + " (stub: untrusted external content)"), nil
		},
	})

	// charge — a stand-in payments call. The gateway injects the API key via
	// {{secret:stripe_key}}; this handler never sees the raw value beyond what
	// it is handed.
	s.AddTool(mcp.Tool{
		Name:        "charge",
		Description: "Charge an amount via the (stub) payments API.",
		InputSchema: objSchema(map[string]any{
			"amount": numProp("amount in minor units"),
			"auth":   strProp("authorization header"),
		}, "amount"),
		Handler: func(_ context.Context, args json.RawMessage) (mcp.ToolResult, error) {
			var a struct {
				Amount float64 `json:"amount"`
			}
			_ = json.Unmarshal(args, &a)
			return textResult("charged " + formatNum(a.Amount) + " (stub: authenticated with an injected key)"), nil
		},
	})

	// read_customer — a stand-in records lookup. In the demo this tool emits the
	// "pii" data-flow label at the gateway.
	s.AddTool(mcp.Tool{
		Name:        "read_customer",
		Description: "Read a (stub) customer record.",
		InputSchema: objSchema(map[string]any{"id": numProp("customer id")}, "id"),
		Handler: func(_ context.Context, args json.RawMessage) (mcp.ToolResult, error) {
			var a struct {
				ID float64 `json:"id"`
			}
			_ = json.Unmarshal(args, &a)
			return textResult("customer #" + formatNum(a.ID) + ": Jane Doe, jane@example.com (stub PII)"), nil
		},
	})
}
