// Package mcpclient is a small MCP client over any io.ReadWriteCloser
// (typically a mesh net.Conn from embed.Client.Dial). It speaks
// newline-delimited JSON-RPC 2.0, correlates responses by id, and routes
// server-initiated notifications to a callback. It is the shared building
// block for the CLI client, the aggregating router, and the
// server-to-server orchestrator.
package mcpclient

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sync"
)

// RPCError is a JSON-RPC error object.
type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e *RPCError) Error() string { return fmt.Sprintf("mcp error %d: %s", e.Code, e.Message) }

// Tool / Resource / Prompt are the shapes returned by the list methods.
type Tool struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	InputSchema json.RawMessage `json:"inputSchema,omitempty"`
}

type Resource struct {
	URI         string `json:"uri"`
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
	MimeType    string `json:"mimeType,omitempty"`
}

type Prompt struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	Arguments   json.RawMessage `json:"arguments,omitempty"`
}

// Client is an MCP client bound to one transport.
type Client struct {
	rw io.ReadWriteCloser

	wmu sync.Mutex
	w   *bufio.Writer

	mu      sync.Mutex
	nextID  int
	pending map[int]chan rpcResp

	onNotify  func(method string, params json.RawMessage)
	closeOnce sync.Once
	closed    chan struct{}
	readErr   error

	// onRequest handles server-initiated requests (sampling/createMessage,
	// elicitation/create, roots/list). Guarded by mu because the read loop
	// reads it. Set via SetOnRequest before traffic that could trigger a
	// reverse request. If nil, such requests get "method not found".
	onRequest func(ctx context.Context, method string, params json.RawMessage) (json.RawMessage, *RPCError)

	// RequestMeta, if set, is merged into every request's params._meta.
	// The router uses it to carry the end-client's mesh identity through to
	// upstream servers (an "on behalf of" hint; the transport identity is
	// still the router, cryptographically).
	RequestMeta map[string]any
}

type rpcResp struct {
	result json.RawMessage
	err    *RPCError
}

// New starts a client on rw and begins reading. onNotify (may be nil)
// receives server-initiated notifications.
func New(rw io.ReadWriteCloser, onNotify func(method string, params json.RawMessage)) *Client {
	c := &Client{
		rw:       rw,
		w:        bufio.NewWriter(rw),
		pending:  map[int]chan rpcResp{},
		onNotify: onNotify,
		closed:   make(chan struct{}),
	}
	go c.readLoop()
	return c
}

func (c *Client) readLoop() {
	sc := bufio.NewScanner(c.rw)
	sc.Buffer(make([]byte, 1<<20), 8<<20)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var m struct {
			ID     *int            `json:"id"`
			Method string          `json:"method"`
			Params json.RawMessage `json:"params"`
			Result json.RawMessage `json:"result"`
			Error  *RPCError       `json:"error"`
		}
		if err := json.Unmarshal(line, &m); err != nil {
			continue
		}
		if m.ID == nil {
			// Notification.
			if c.onNotify != nil && m.Method != "" {
				c.onNotify(m.Method, m.Params)
			}
			continue
		}
		if m.Method != "" {
			// Server-initiated request (has both id and method).
			go c.serveInbound(*m.ID, m.Method, m.Params)
			continue
		}
		// Response to one of our requests.
		c.mu.Lock()
		ch := c.pending[*m.ID]
		delete(c.pending, *m.ID)
		c.mu.Unlock()
		if ch != nil {
			ch <- rpcResp{result: m.Result, err: m.Error}
		}
	}
	c.finish(sc.Err())
}

// SetOnRequest installs the handler for server-initiated requests. Call it
// before any traffic that could trigger one (e.g. before Initialize).
func (c *Client) SetOnRequest(fn func(ctx context.Context, method string, params json.RawMessage) (json.RawMessage, *RPCError)) {
	c.mu.Lock()
	c.onRequest = fn
	c.mu.Unlock()
}

// serveInbound answers a server-initiated request via the handler.
func (c *Client) serveInbound(id int, method string, params json.RawMessage) {
	c.mu.Lock()
	h := c.onRequest
	c.mu.Unlock()
	if h == nil {
		_ = c.write(map[string]any{"jsonrpc": "2.0", "id": id,
			"error": map[string]any{"code": -32601, "message": "method not found: " + method}})
		return
	}
	res, rpcErr := h(context.Background(), method, params)
	if rpcErr != nil {
		_ = c.write(map[string]any{"jsonrpc": "2.0", "id": id, "error": rpcErr})
		return
	}
	_ = c.write(map[string]any{"jsonrpc": "2.0", "id": id, "result": res})
}

func (c *Client) finish(err error) {
	c.closeOnce.Do(func() {
		c.mu.Lock()
		c.readErr = err
		for id, ch := range c.pending {
			close(ch)
			delete(c.pending, id)
		}
		c.mu.Unlock()
		close(c.closed)
	})
}

// Call sends a request and waits for the correlated response.
func (c *Client) Call(ctx context.Context, method string, params any) (json.RawMessage, error) {
	c.mu.Lock()
	c.nextID++
	id := c.nextID
	ch := make(chan rpcResp, 1)
	c.pending[id] = ch
	c.mu.Unlock()

	req := map[string]any{"jsonrpc": "2.0", "id": id, "method": method}
	if params != nil {
		req["params"] = c.withMeta(params)
	}
	if err := c.write(req); err != nil {
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
		return nil, err
	}

	select {
	case r, ok := <-ch:
		if !ok {
			if c.readErr != nil {
				return nil, c.readErr
			}
			return nil, io.EOF
		}
		if r.err != nil {
			return nil, r.err
		}
		return r.result, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.closed:
		return nil, io.ErrClosedPipe
	}
}

// Notify sends a notification (no response expected).
func (c *Client) Notify(method string, params any) error {
	req := map[string]any{"jsonrpc": "2.0", "method": method}
	if params != nil {
		req["params"] = params
	}
	return c.write(req)
}

// withMeta merges RequestMeta into a map-shaped params object as _meta,
// without mutating the caller's value. A caller-supplied _meta map is
// preserved, but RequestMeta wins on key conflicts: RequestMeta carries the
// router's origin identity stamp, which params must never override.
func (c *Client) withMeta(params any) any {
	if c.RequestMeta == nil {
		return params
	}
	pm, ok := params.(map[string]any)
	if !ok {
		return params
	}
	cp := make(map[string]any, len(pm)+1)
	for k, v := range pm {
		cp[k] = v
	}
	meta := make(map[string]any, len(c.RequestMeta)+1)
	if prior, ok := cp["_meta"].(map[string]any); ok {
		for k, v := range prior {
			meta[k] = v
		}
	}
	for k, v := range c.RequestMeta {
		meta[k] = v
	}
	cp["_meta"] = meta
	return cp
}

func (c *Client) write(v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if _, err := c.w.Write(b); err != nil {
		return err
	}
	if err := c.w.WriteByte('\n'); err != nil {
		return err
	}
	return c.w.Flush()
}

// Close closes the transport.
func (c *Client) Close() error { return c.rw.Close() }

// --- high-level MCP helpers ---

// Initialize performs the MCP handshake (initialize + initialized).
func (c *Client) Initialize(ctx context.Context, clientName string) (json.RawMessage, error) {
	res, err := c.Call(ctx, "initialize", map[string]any{
		"protocolVersion": "2025-06-18",
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": clientName, "version": "0.1.0"},
	})
	if err != nil {
		return nil, err
	}
	_ = c.Notify("notifications/initialized", nil)
	return res, nil
}

func (c *Client) ListTools(ctx context.Context) ([]Tool, error) {
	res, err := c.Call(ctx, "tools/list", nil)
	if err != nil {
		return nil, err
	}
	var out struct {
		Tools []Tool `json:"tools"`
	}
	return out.Tools, json.Unmarshal(res, &out)
}

// CallTool invokes a tool. Pass task=true to run it asynchronously.
func (c *Client) CallTool(ctx context.Context, name string, args any, task bool) (json.RawMessage, error) {
	params := map[string]any{"name": name, "arguments": args}
	if task {
		params["task"] = true
	}
	return c.Call(ctx, "tools/call", params)
}

func (c *Client) ListResources(ctx context.Context) ([]Resource, error) {
	res, err := c.Call(ctx, "resources/list", nil)
	if err != nil {
		return nil, err
	}
	var out struct {
		Resources []Resource `json:"resources"`
	}
	return out.Resources, json.Unmarshal(res, &out)
}

func (c *Client) ReadResource(ctx context.Context, uri string) (json.RawMessage, error) {
	return c.Call(ctx, "resources/read", map[string]any{"uri": uri})
}

func (c *Client) ListPrompts(ctx context.Context) ([]Prompt, error) {
	res, err := c.Call(ctx, "prompts/list", nil)
	if err != nil {
		return nil, err
	}
	var out struct {
		Prompts []Prompt `json:"prompts"`
	}
	return out.Prompts, json.Unmarshal(res, &out)
}

func (c *Client) GetPrompt(ctx context.Context, name string, args any) (json.RawMessage, error) {
	return c.Call(ctx, "prompts/get", map[string]any{"name": name, "arguments": args})
}
