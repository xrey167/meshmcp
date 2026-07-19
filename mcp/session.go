package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"sync"
	"time"
)

// writeTimeout bounds a single client write. Without it, a client that stops
// reading (TCP zero-window) would block a Flush forever while holding the
// connection mutex, stalling the request loop and any notification fan-out. On
// transports that support deadlines (net.Conn) a stalled write fails and the
// connection is torn down; on pipes/stdio (no deadline support) this is a no-op.
const writeTimeout = 15 * time.Second

type writeDeadliner interface {
	SetWriteDeadline(time.Time) error
}

// outConn serializes all writes to the client stream (responses and
// server-initiated notifications from any goroutine) behind one mutex.
type outConn struct {
	mu sync.Mutex
	bw *bufio.Writer
	wd writeDeadliner // nil when the transport has no deadline support
}

func (c *outConn) send(v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.wd != nil {
		_ = c.wd.SetWriteDeadline(time.Now().Add(writeTimeout))
		defer func() { _ = c.wd.SetWriteDeadline(time.Time{}) }()
	}
	if _, err := c.bw.Write(b); err != nil {
		return err
	}
	if err := c.bw.WriteByte('\n'); err != nil {
		return err
	}
	return c.bw.Flush()
}

// Session is the per-connection handle a tool/resource/prompt handler uses
// to send notifications back to the client — progress updates, log
// messages, or any custom notification. It is safe for concurrent use, so
// a task goroutine can stream progress while the main loop serves other
// requests.
type Session struct {
	conn *outConn
}

// Notify sends a JSON-RPC notification (no id, no response expected).
func (s *Session) Notify(method string, params any) {
	if s == nil || s.conn == nil {
		return
	}
	_ = s.conn.send(notification{JSONRPC: "2.0", Method: method, Params: params})
}

// Progress emits a notifications/progress for a long-running operation.
// total <= 0 and message == "" are omitted.
func (s *Session) Progress(token any, progress, total float64, message string) {
	p := map[string]any{"progressToken": token, "progress": progress}
	if total > 0 {
		p["total"] = total
	}
	if message != "" {
		p["message"] = message
	}
	s.Notify("notifications/progress", p)
}

// Log emits a notifications/message (MCP structured logging).
func (s *Session) Log(level, data string) {
	s.Notify("notifications/message", map[string]any{"level": level, "data": data})
}

type notification struct {
	JSONRPC string `json:"jsonrpc"`
	Method  string `json:"method"`
	Params  any    `json:"params,omitempty"`
}

type sessionKey struct{}

// WithSession attaches a Session to a context for handlers to retrieve.
func WithSession(ctx context.Context, s *Session) context.Context {
	return context.WithValue(ctx, sessionKey{}, s)
}

// SessionFrom returns the Session attached to ctx, or nil.
func SessionFrom(ctx context.Context) *Session {
	s, _ := ctx.Value(sessionKey{}).(*Session)
	return s
}
