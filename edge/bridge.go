package edge

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/xrey167/meshmcp/mcpclient"
)

// DialBackend dials the one configured mesh backend, returning a raw connection
// speaking newline-framed JSON-RPC. Production injects a WireGuard mesh dial
// (client.Dial); the default is a plain TCP dial (same-host backends and tests).
type DialBackend func(ctx context.Context) (net.Conn, error)

// bridge is a live connection to the backend, wrapping mcpclient so request/
// response correlation and server-initiated notifications are handled. A bridge
// backs one session (or one stateless POST request).
type bridge struct {
	cli  *mcpclient.Client
	conn net.Conn

	mu       sync.Mutex
	onNotify func(method string, params json.RawMessage)
	closed   bool
}

// newBridge dials the backend and wraps it in an mcpclient. It does NOT perform
// the MCP initialize handshake itself — the hosted client's own initialize
// request is relayed through the bridge transparently, so the edge stays a pure
// proxy and never double-initializes the backend.
func newBridge(ctx context.Context, dial DialBackend) (*bridge, error) {
	conn, err := dial(ctx)
	if err != nil {
		return nil, fmt.Errorf("edge: dial backend: %w", err)
	}
	b := &bridge{conn: conn}
	b.cli = mcpclient.New(conn, func(method string, params json.RawMessage) {
		b.mu.Lock()
		fn := b.onNotify
		b.mu.Unlock()
		if fn != nil {
			fn(method, params)
		}
	})
	return b, nil
}

// setNotifyHandler installs (or clears) the sink for backend notifications,
// used to route them onto a session's SSE stream while one is open.
func (b *bridge) setNotifyHandler(fn func(method string, params json.RawMessage)) {
	b.mu.Lock()
	b.onNotify = fn
	b.mu.Unlock()
}

// forward relays one JSON-RPC request to the backend and returns a complete
// JSON-RPC response object carrying the ORIGINAL request id, so the proxy is
// transparent to the client. A backend RPC error becomes a JSON-RPC error
// response (not a transport error).
func (b *bridge) forward(ctx context.Context, method string, id json.RawMessage, params json.RawMessage) ([]byte, error) {
	var p any
	if len(params) > 0 {
		p = json.RawMessage(params)
	}
	result, err := b.cli.Call(ctx, method, p)
	if err != nil {
		if rpcErr, ok := err.(*mcpclient.RPCError); ok {
			return jsonRPCErrorResponse(id, rpcErr.Code, rpcErr.Message), nil
		}
		return nil, err
	}
	return jsonRPCResultResponse(id, result), nil
}

// notify relays a client notification (no response expected).
func (b *bridge) notify(method string, params json.RawMessage) error {
	var p any
	if len(params) > 0 {
		p = json.RawMessage(params)
	}
	return b.cli.Notify(method, p)
}

func (b *bridge) close() {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return
	}
	b.closed = true
	b.mu.Unlock()
	_ = b.cli.Close()
}

// defaultDial is the plain-TCP fallback dialer used when no mesh dialer is
// injected (tests, or an edge co-located with its backend).
func defaultDial(addr string) DialBackend {
	return func(ctx context.Context) (net.Conn, error) {
		d := net.Dialer{Timeout: 10 * time.Second}
		return d.DialContext(ctx, "tcp", addr)
	}
}

// jsonRPCResultResponse builds {"jsonrpc":"2.0","id":<id>,"result":<result>}.
func jsonRPCResultResponse(id json.RawMessage, result json.RawMessage) []byte {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	if len(result) == 0 {
		result = json.RawMessage("null")
	}
	out, _ := json.Marshal(map[string]json.RawMessage{
		"jsonrpc": json.RawMessage(`"2.0"`),
		"id":      id,
		"result":  result,
	})
	return out
}

// jsonRPCErrorResponse builds a JSON-RPC error response carrying the original id.
func jsonRPCErrorResponse(id json.RawMessage, code int, message string) []byte {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	errObj, _ := json.Marshal(map[string]any{"code": code, "message": message})
	out, _ := json.Marshal(map[string]json.RawMessage{
		"jsonrpc": json.RawMessage(`"2.0"`),
		"id":      id,
		"error":   errObj,
	})
	return out
}
