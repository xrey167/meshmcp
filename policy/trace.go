package policy

import (
	"encoding/json"
	"io"
	"sync"
)

// TraceOptions configures how much of each message the tracer records.
type TraceOptions struct {
	// Payloads includes request params / response results / errors in each
	// record. Off by default: payloads can be large (file contents) and
	// sensitive. Metadata (method, tool, id, direction, decision) is always
	// recorded.
	Payloads bool
	// MaxBytes caps a recorded payload; larger bodies are replaced by a
	// {"truncated":true,"bytes":N} marker. Defaults to 2048.
	MaxBytes int
}

// TraceEvent is one line of the MCP trace log: a single JSON-RPC message
// observed at the gateway, in one direction, attributed to a mesh peer.
type TraceEvent struct {
	Time     string          `json:"time"`
	Backend  string          `json:"backend"`
	Peer     string          `json:"peer"`
	PeerKey  string          `json:"peer_key,omitempty"`
	PeerAddr string          `json:"peer_addr,omitempty"`
	Dir      string          `json:"dir"`  // "c2s" (client->server) | "s2c"
	Kind     string          `json:"kind"` // request | response | notification
	Method   string          `json:"method,omitempty"`
	Tool     string          `json:"tool,omitempty"`
	RPCID    string          `json:"rpc_id,omitempty"`
	IsError  bool            `json:"is_error,omitempty"`
	Decision string          `json:"decision,omitempty"` // policy verdict, if any
	Bytes    int             `json:"bytes"`
	Payload  json.RawMessage `json:"payload,omitempty"`
}

// Tracer writes a full trace of MCP traffic as newline-delimited JSON. One
// Tracer is shared by every backend on a gateway, so the file is a unified,
// identity-attributed record of every call across the mesh.
type Tracer struct {
	mu   sync.Mutex
	w    io.Writer
	now  func() string
	opts TraceOptions
}

// NewTracer writes trace events to w. now supplies timestamps.
func NewTracer(w io.Writer, now func() string, opts TraceOptions) *Tracer {
	if now == nil {
		now = func() string { return "" }
	}
	if opts.MaxBytes <= 0 {
		opts.MaxBytes = 2048
	}
	return &Tracer{w: w, now: now, opts: opts}
}

// record parses one JSON-RPC line and emits a trace event. dir is "c2s" or
// "s2c"; decision is the policy verdict for governed client->server messages
// ("" when none applied).
func (t *Tracer) record(caller Caller, dir string, line []byte, decision string) {
	if t == nil || t.w == nil {
		return
	}
	var m struct {
		ID     json.RawMessage `json:"id"`
		Method string          `json:"method"`
		Params json.RawMessage `json:"params"`
		Result json.RawMessage `json:"result"`
		Error  json.RawMessage `json:"error"`
	}
	_ = json.Unmarshal(line, &m)

	ev := TraceEvent{
		Backend:  caller.Backend,
		Peer:     caller.Peer,
		PeerKey:  caller.PeerKey,
		PeerAddr: caller.PeerAddr,
		Dir:      dir,
		Method:   m.Method,
		RPCID:    string(m.ID),
		Decision: decision,
		Bytes:    len(line),
		IsError:  len(m.Error) > 0,
	}
	switch {
	case m.Method != "" && len(m.ID) > 0:
		ev.Kind = "request"
	case m.Method != "":
		ev.Kind = "notification"
	default:
		ev.Kind = "response"
	}
	if m.Method == "tools/call" {
		var p struct {
			Name string `json:"name"`
		}
		_ = json.Unmarshal(m.Params, &p)
		ev.Tool = p.Name
	}
	if t.opts.Payloads {
		body := m.Params
		if ev.Kind == "response" {
			if len(m.Error) > 0 {
				body = m.Error
			} else {
				body = m.Result
			}
		}
		ev.Payload = t.capPayload(body)
	}

	ev.Time = t.now()
	b, err := json.Marshal(ev)
	if err != nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.w.Write(b)
	t.w.Write([]byte{'\n'})
}

func (t *Tracer) capPayload(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 {
		return nil
	}
	if len(raw) <= t.opts.MaxBytes {
		return raw
	}
	marker, _ := json.Marshal(map[string]any{"truncated": true, "bytes": len(raw)})
	return marker
}
