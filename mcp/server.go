// Package mcp is a small, dependency-free MCP server framework speaking
// newline-delimited JSON-RPC 2.0 over stdio. It implements the standard
// capability set — tools (with executable handlers), resources, and
// prompts — to the 2025-06-18 MCP protocol, so any MCP client (including
// Claude) can drive a server built with it, and so it exercises meshmcp's
// policy and resumable-session layers with real MCP semantics.
package mcp

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
)

// ProtocolVersion is the MCP revision this server implements.
const ProtocolVersion = "2025-06-18"

// Content is a single content block in a tool result or prompt message.
// A block is one of: text ("text"), an inline image ("image") or audio
// ("audio") carrying base64 Data + MimeType, or an embedded binary resource
// ("resource") carrying a Resource with a base64 Blob. The concrete kind is
// selected by Type, matching the MCP 2025-06-18 content union.
type Content struct {
	Type string `json:"type"`
	// Text is set for a "text" block.
	Text string `json:"text,omitempty"`
	// Data is base64-encoded bytes for an "image" or "audio" block.
	Data string `json:"data,omitempty"`
	// MimeType classifies the Data of an "image"/"audio" block.
	MimeType string `json:"mimeType,omitempty"`
	// Resource carries the embedded contents of a "resource" block.
	Resource *ResourceContents `json:"resource,omitempty"`
}

// Text is a convenience constructor for a text content block.
func Text(s string) Content { return Content{Type: "text", Text: s} }

// Image is a convenience constructor for an inline image content block;
// data is the raw image bytes (base64-encoded on the wire).
func Image(mimeType string, data []byte) Content {
	return Content{Type: "image", Data: base64.StdEncoding.EncodeToString(data), MimeType: mimeType}
}

// Audio is a convenience constructor for an inline audio content block;
// data is the raw audio bytes (base64-encoded on the wire).
func Audio(mimeType string, data []byte) Content {
	return Content{Type: "audio", Data: base64.StdEncoding.EncodeToString(data), MimeType: mimeType}
}

// Blob is a convenience constructor for a content block carrying arbitrary
// binary data as an embedded resource; data is the raw bytes (base64 on wire).
func Blob(uri, mimeType string, data []byte) Content {
	rc := BlobResource(uri, mimeType, data)
	return Content{Type: "resource", Resource: &rc}
}

// ToolResult is what a tool handler returns.
type ToolResult struct {
	Content []Content `json:"content"`
	IsError bool      `json:"isError,omitempty"`
}

// Tool is an executable capability. Handler receives the raw JSON of the
// call's "arguments" object.
type Tool struct {
	Name        string
	Description string
	InputSchema map[string]any
	Handler     func(ctx context.Context, args json.RawMessage) (ToolResult, error)
}

// ResourceContents is the body returned by reading a resource. It carries
// either Text (a text resource) or Blob (base64-encoded binary), matching the
// MCP TextResourceContents / BlobResourceContents shapes.
type ResourceContents struct {
	URI      string `json:"uri"`
	MimeType string `json:"mimeType,omitempty"`
	Text     string `json:"text,omitempty"`
	Blob     string `json:"blob,omitempty"`
}

// BlobResource builds a binary ResourceContents from raw bytes (base64 on wire).
func BlobResource(uri, mimeType string, data []byte) ResourceContents {
	return ResourceContents{URI: uri, MimeType: mimeType, Blob: base64.StdEncoding.EncodeToString(data)}
}

// Resource is a readable resource identified by a URI.
type Resource struct {
	URI         string
	Name        string
	Description string
	MimeType    string
	Read        func(ctx context.Context) (ResourceContents, error)
}

// PromptArg describes one argument of a prompt.
type PromptArg struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Required    bool   `json:"required,omitempty"`
}

// PromptMessage is one message in a rendered prompt.
type PromptMessage struct {
	Role    string  `json:"role"`
	Content Content `json:"content"`
}

// PromptResult is what a prompt handler returns.
type PromptResult struct {
	Description string          `json:"description,omitempty"`
	Messages    []PromptMessage `json:"messages"`
}

// Prompt is a parameterized prompt template.
type Prompt struct {
	Name        string
	Description string
	Arguments   []PromptArg
	Get         func(ctx context.Context, args map[string]string) (PromptResult, error)
}

// Server holds registered capabilities and dispatches JSON-RPC requests.
type Server struct {
	name, version string

	mu        sync.RWMutex
	tools     map[string]Tool
	toolOrder []string
	resources map[string]Resource
	resOrder  []string
	prompts   map[string]Prompt
	promptOrd []string

	tasks *taskManager
	sess  *Session // the active connection's session (one Serve at a time)

	globalMW []ToolMiddleware
	toolMW   map[string][]ToolMiddleware

	reqMu   sync.Mutex
	reqSeq  int
	pending map[int]chan clientResp

	submu sync.Mutex
	subs  map[string]*subscription // active subscriptions/listen streams by id
}

type clientResp struct {
	result json.RawMessage
	err    *rpcError
}

// Request sends a server-initiated request to the connected client and waits
// for its response — the server->client direction (sampling/createMessage,
// elicitation/create, roots/list). A router uses this to relay an upstream's
// reverse request down to the end client.
func (s *Server) Request(ctx context.Context, method string, params any) (json.RawMessage, error) {
	s.mu.RLock()
	sess := s.sess
	s.mu.RUnlock()
	if sess == nil || sess.conn == nil {
		return nil, errors.New("mcp: no active session for server request")
	}
	s.reqMu.Lock()
	if s.pending == nil {
		s.pending = map[int]chan clientResp{}
	}
	s.reqSeq++
	id := s.reqSeq
	ch := make(chan clientResp, 1)
	s.pending[id] = ch
	s.reqMu.Unlock()

	req := map[string]any{"jsonrpc": "2.0", "id": id, "method": method}
	if params != nil {
		req["params"] = params
	}
	if err := sess.conn.send(req); err != nil {
		s.reqMu.Lock()
		delete(s.pending, id)
		s.reqMu.Unlock()
		return nil, err
	}
	select {
	case r := <-ch:
		if r.err != nil {
			return nil, r.err
		}
		return r.result, nil
	case <-ctx.Done():
		s.reqMu.Lock()
		delete(s.pending, id)
		s.reqMu.Unlock()
		return nil, ctx.Err()
	}
}

// routeResponse delivers a client's response to a pending server request.
func (s *Server) routeResponse(line []byte) {
	var r struct {
		ID     *int            `json:"id"`
		Result json.RawMessage `json:"result"`
		Error  *rpcError       `json:"error"`
	}
	if err := json.Unmarshal(line, &r); err != nil || r.ID == nil {
		return
	}
	s.reqMu.Lock()
	ch := s.pending[*r.ID]
	delete(s.pending, *r.ID)
	s.reqMu.Unlock()
	if ch != nil {
		ch <- clientResp{result: r.Result, err: r.Error}
	}
}

// Notify sends a server-initiated notification to the connected client from
// outside a handler (e.g. a proxy forwarding an upstream's notification). It
// is a no-op until a connection is being served.
func (s *Server) Notify(method string, params any) {
	s.mu.RLock()
	sess := s.sess
	s.mu.RUnlock()
	if sess != nil {
		sess.Notify(method, params)
	}
}

// New creates a server advertising the given name/version.
func New(name, version string) *Server {
	return &Server{
		name:      name,
		version:   version,
		tools:     map[string]Tool{},
		resources: map[string]Resource{},
		prompts:   map[string]Prompt{},
		tasks:     newTaskManager(),
	}
}

// AddTool registers a tool (last registration of a name wins).
func (s *Server) AddTool(t Tool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.tools[t.Name]; !ok {
		s.toolOrder = append(s.toolOrder, t.Name)
	}
	s.tools[t.Name] = t
}

// AddResource registers a resource.
func (s *Server) AddResource(r Resource) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.resources[r.URI]; !ok {
		s.resOrder = append(s.resOrder, r.URI)
	}
	s.resources[r.URI] = r
}

// AddPrompt registers a prompt.
func (s *Server) AddPrompt(p Prompt) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.prompts[p.Name]; !ok {
		s.promptOrd = append(s.promptOrd, p.Name)
	}
	s.prompts[p.Name] = p
}

// Serve reads JSON-RPC requests from r and writes responses to w until r
// hits EOF. Requests are handled sequentially (stdio is a single stream).
func (s *Server) Serve(ctx context.Context, r io.Reader, w io.Writer) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<20), 8<<20)
	conn := &outConn{bw: bufio.NewWriter(w)}
	if wd, ok := w.(writeDeadliner); ok {
		conn.wd = wd // bound writes on transports that support deadlines (net.Conn)
	}
	sess := &Session{conn: conn}
	s.mu.Lock()
	s.sess = sess
	s.mu.Unlock()
	sctx := WithSession(ctx, sess)
	defer s.closeAllSubscriptions() // terminate any open listen streams on disconnect

	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var req request
		if err := json.Unmarshal(line, &req); err != nil {
			_ = conn.send(response{JSONRPC: "2.0", ID: json.RawMessage("null"),
				Error: &rpcError{Code: codeParse, Message: "parse error"}})
			continue
		}
		// A request without an id is a notification: act on it, never reply.
		if len(req.ID) == 0 {
			s.handleNotification(req)
			continue
		}
		// An id with no method is a response to a server-initiated request.
		if req.Method == "" {
			s.routeResponse(line)
			continue
		}
		// Dispatch concurrently so the read loop stays responsive — a
		// handler may itself issue a server->client request (sampling,
		// elicitation) whose response must be read while it waits. Clients
		// correlate replies by id, so out-of-order completion is fine.
		go func(req request) {
			resp := s.dispatch(sctx, req, sess)
			if !resp.skip {
				_ = conn.send(resp)
			}
		}(req)
	}
	return sc.Err()
}

// handleNotification acts on client-initiated notifications. Unknown ones
// are ignored per JSON-RPC.
func (s *Server) handleNotification(req request) {
	switch req.Method {
	case "notifications/cancelled":
		// Standard cancellation. We map the cancelled request id onto a
		// task id, so cancelling a task's originating request cancels it.
		var p struct {
			RequestID json.RawMessage `json:"requestId"`
			TaskID    string          `json:"taskId"`
		}
		_ = json.Unmarshal(req.Params, &p)
		// A cancel may target an open subscriptions/listen stream (its id is the
		// subscription id); if so, close it with the terminal `complete` result.
		if s.closeSubscription(string(p.RequestID)) {
			return
		}
		id := p.TaskID
		if id == "" {
			// requestId may be a JSON string or number; trim quotes.
			id = strings.Trim(string(p.RequestID), `"`)
		}
		if t, ok := s.tasks.get(id); ok {
			t.cancel()
		}
	default:
		// notifications/initialized and anything else: no action.
	}
}

func (s *Server) dispatch(ctx context.Context, req request, sess *Session) response {
	ok := func(result any) response {
		return response{JSONRPC: "2.0", ID: req.ID, Result: result}
	}
	fail := func(code int, msg string) response {
		return response{JSONRPC: "2.0", ID: req.ID, Error: &rpcError{Code: code, Message: msg}}
	}

	switch req.Method {
	case "initialize":
		return ok(s.initializeResult())
	case "ping":
		return ok(map[string]any{})
	case "tools/list":
		return ok(s.listTools())
	case "tools/call":
		return s.callTool(ctx, req, sess, ok, fail)
	case "resources/list":
		return ok(s.listResources())
	case "resources/read":
		return s.readResource(ctx, req, ok, fail)
	case "prompts/list":
		return ok(s.listPrompts())
	case "prompts/get":
		return s.getPrompt(ctx, req, ok, fail)
	case "tasks/list":
		return ok(map[string]any{"tasks": s.tasks.list()})
	case "tasks/get":
		return s.taskGet(req, ok, fail)
	case "tasks/result":
		return s.taskResult(req, ok, fail)
	case "tasks/cancel":
		return s.taskCancel(req, ok, fail)
	case "tasks/steer":
		return s.taskSteer(req, ok, fail)
	case methodSubscriptionsListen:
		return s.handleListen(req, sess)
	default:
		return fail(codeMethodNotFound, "method not found: "+req.Method)
	}
}

func (s *Server) initializeResult() map[string]any {
	s.mu.RLock()
	defer s.mu.RUnlock()
	caps := map[string]any{}
	if len(s.tools) > 0 {
		caps["tools"] = map[string]any{"listChanged": false}
	}
	if len(s.resources) > 0 {
		caps["resources"] = map[string]any{"subscribe": false, "listChanged": false}
	}
	if len(s.prompts) > 0 {
		caps["prompts"] = map[string]any{"listChanged": false}
	}
	return map[string]any{
		"protocolVersion": ProtocolVersion,
		"capabilities":    caps,
		"serverInfo":      map[string]any{"name": s.name, "version": s.version},
	}
}

func (s *Server) listTools() map[string]any {
	s.mu.RLock()
	defer s.mu.RUnlock()
	list := make([]map[string]any, 0, len(s.toolOrder))
	for _, name := range s.toolOrder {
		t := s.tools[name]
		schema := t.InputSchema
		if schema == nil {
			schema = map[string]any{"type": "object"}
		}
		list = append(list, map[string]any{
			"name": t.Name, "description": t.Description, "inputSchema": schema,
		})
	}
	return map[string]any{"tools": list}
}

func (s *Server) callTool(ctx context.Context, req request, sess *Session, ok func(any) response, fail func(int, string) response) response {
	var p struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
		// Task requests the call run asynchronously as a task; the response
		// is a working task handle and the result is fetched via tasks/result.
		Task bool `json:"task"`
	}
	if err := json.Unmarshal(req.Params, &p); err != nil {
		return fail(codeInvalidParams, "invalid params: "+err.Error())
	}
	s.mu.RLock()
	t, found := s.tools[p.Name]
	s.mu.RUnlock()
	if !found {
		return fail(codeInvalidParams, "unknown tool: "+p.Name)
	}
	args := p.Arguments
	if len(args) == 0 {
		args = json.RawMessage("{}")
	}
	meta := rawMeta(req.Params)
	handler := s.effectiveHandler(t)
	if p.Task {
		// Tasks stream progress on the session channel; a stateless transport
		// (HTTP) has none, so reject rather than start a task nobody hears.
		if sess.conn == nil {
			return fail(codeInvalidParams, "tasks are not supported over this transport")
		}
		// start sends the working handle (with this request id) before
		// spawning the task, so progress never precedes it. The same compiled
		// middleware chain runs for the task.
		s.tasks.start(sess, req.ID, p.Name, handler, meta, args)
		return response{skip: true}
	}
	ctx = withToolCall(ctx, ToolCallInfo{Tool: p.Name, RequestID: req.ID, Meta: meta})
	res, err := handler(ctx, args)
	if err != nil {
		// Tool execution failures are reported as an error result, per MCP,
		// so the model can see and react to them.
		return ok(ToolResult{Content: []Content{Text(err.Error())}, IsError: true})
	}
	if res.Content == nil {
		res.Content = []Content{}
	}
	return ok(res)
}

func (s *Server) taskGet(req request, ok func(any) response, fail func(int, string) response) response {
	id, err := taskID(req.Params)
	if err != nil {
		return fail(codeInvalidParams, err.Error())
	}
	t, found := s.tasks.get(id)
	if !found {
		return fail(codeInvalidParams, "unknown task: "+id)
	}
	status, errMsg := t.snapshot()
	res := map[string]any{"taskId": id, "status": status}
	if errMsg != "" {
		res["error"] = errMsg
	}
	return ok(res)
}

func (s *Server) taskResult(req request, ok func(any) response, fail func(int, string) response) response {
	id, err := taskID(req.Params)
	if err != nil {
		return fail(codeInvalidParams, err.Error())
	}
	t, found := s.tasks.get(id)
	if !found {
		return fail(codeInvalidParams, "unknown task: "+id)
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	switch t.status {
	case StatusCompleted:
		result := t.result
		if result.Content == nil {
			result.Content = []Content{}
		}
		return ok(result)
	case StatusFailed:
		return ok(ToolResult{Content: []Content{Text(t.errMsg)}, IsError: true})
	case StatusCancelled:
		return fail(codeTaskState, "task cancelled: "+id)
	default:
		return fail(codeTaskState, "task not complete: "+id)
	}
}

func (s *Server) taskCancel(req request, ok func(any) response, fail func(int, string) response) response {
	id, err := taskID(req.Params)
	if err != nil {
		return fail(codeInvalidParams, err.Error())
	}
	t, found := s.tasks.get(id)
	if !found {
		return fail(codeInvalidParams, "unknown task: "+id)
	}
	t.cancel()
	return ok(map[string]any{"taskId": id, "status": StatusCancelled})
}

// taskSteer delivers mid-flight guidance to a working task (Air · Steer, P3).
// Symmetric with taskCancel: the interrupt stops a task, the steer augments it.
// It is a normal MCP method, so a policy `methods:` rule governs it exactly as
// it governs tasks/cancel. Delivery is cooperative — only a handler selecting on
// SteerChan(ctx) reacts; the payload is the caller's params.payload (or {}).
func (s *Server) taskSteer(req request, ok func(any) response, fail func(int, string) response) response {
	var p struct {
		TaskID  string          `json:"taskId"`
		Payload json.RawMessage `json:"payload"`
	}
	if err := json.Unmarshal(req.Params, &p); err != nil {
		return fail(codeInvalidParams, "invalid params: "+err.Error())
	}
	if p.TaskID == "" {
		return fail(codeInvalidParams, "taskId is required")
	}
	payload := p.Payload
	if len(payload) == 0 {
		payload = json.RawMessage(`{}`)
	}
	switch s.tasks.steer(p.TaskID, payload) {
	case steerDelivered:
		return ok(map[string]any{"taskId": p.TaskID, "status": StatusWorking, "steered": true})
	case steerBusy:
		return fail(codeTaskState, "task busy (steer buffer full): "+p.TaskID)
	case steerNotReady:
		return fail(codeTaskState, "task not steerable (not working): "+p.TaskID)
	default: // steerUnknown
		return fail(codeInvalidParams, "unknown task: "+p.TaskID)
	}
}

func taskID(params json.RawMessage) (string, error) {
	var p struct {
		TaskID string `json:"taskId"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return "", fmt.Errorf("invalid params: %w", err)
	}
	if p.TaskID == "" {
		return "", fmt.Errorf("taskId is required")
	}
	return p.TaskID, nil
}

func (s *Server) listResources() map[string]any {
	s.mu.RLock()
	defer s.mu.RUnlock()
	list := make([]map[string]any, 0, len(s.resOrder))
	for _, uri := range s.resOrder {
		r := s.resources[uri]
		item := map[string]any{"uri": r.URI, "name": r.Name}
		if r.Description != "" {
			item["description"] = r.Description
		}
		if r.MimeType != "" {
			item["mimeType"] = r.MimeType
		}
		list = append(list, item)
	}
	return map[string]any{"resources": list}
}

func (s *Server) readResource(ctx context.Context, req request, ok func(any) response, fail func(int, string) response) response {
	var p struct {
		URI string `json:"uri"`
	}
	if err := json.Unmarshal(req.Params, &p); err != nil {
		return fail(codeInvalidParams, "invalid params: "+err.Error())
	}
	s.mu.RLock()
	r, found := s.resources[p.URI]
	s.mu.RUnlock()
	if !found {
		return fail(codeInvalidParams, "unknown resource: "+p.URI)
	}
	c, err := r.Read(ctx)
	if err != nil {
		return fail(codeInternal, "read resource: "+err.Error())
	}
	if c.URI == "" {
		c.URI = r.URI
	}
	if c.MimeType == "" {
		c.MimeType = r.MimeType
	}
	return ok(map[string]any{"contents": []ResourceContents{c}})
}

func (s *Server) listPrompts() map[string]any {
	s.mu.RLock()
	defer s.mu.RUnlock()
	list := make([]map[string]any, 0, len(s.promptOrd))
	for _, name := range s.promptOrd {
		p := s.prompts[name]
		item := map[string]any{"name": p.Name}
		if p.Description != "" {
			item["description"] = p.Description
		}
		if len(p.Arguments) > 0 {
			item["arguments"] = p.Arguments
		}
		list = append(list, item)
	}
	return map[string]any{"prompts": list}
}

func (s *Server) getPrompt(ctx context.Context, req request, ok func(any) response, fail func(int, string) response) response {
	var p struct {
		Name      string            `json:"name"`
		Arguments map[string]string `json:"arguments"`
	}
	if err := json.Unmarshal(req.Params, &p); err != nil {
		return fail(codeInvalidParams, "invalid params: "+err.Error())
	}
	s.mu.RLock()
	pr, found := s.prompts[p.Name]
	s.mu.RUnlock()
	if !found {
		return fail(codeInvalidParams, "unknown prompt: "+p.Name)
	}
	for _, a := range pr.Arguments {
		if a.Required {
			if _, present := p.Arguments[a.Name]; !present {
				return fail(codeInvalidParams, fmt.Sprintf("prompt %q: missing required argument %q", p.Name, a.Name))
			}
		}
	}
	res, err := pr.Get(ctx, p.Arguments)
	if err != nil {
		return fail(codeInternal, "get prompt: "+err.Error())
	}
	return ok(res)
}

// --- JSON-RPC wire types ---

type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
	// skip (unexported, not serialized) tells the Serve loop the handler
	// already sent its own reply — used by task calls, which must send the
	// working handle before the task goroutine emits progress.
	skip bool
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e *rpcError) Error() string { return fmt.Sprintf("mcp error %d: %s", e.Code, e.Message) }

const (
	codeParse          = -32700
	codeMethodNotFound = -32601
	codeInvalidParams  = -32602
	codeInternal       = -32603
	codeTaskState      = -32002 // task not in a terminal/ready state
)
