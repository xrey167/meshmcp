package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
)

// Caller identifies the mesh peer whose traffic a filter is enforcing.
type Caller struct {
	Backend  string
	Peer     string
	PeerKey  string
	PeerAddr string
}

// Filter wraps a backend MCP server's stdio and enforces a Policy on the
// JSON-RPC flowing through it. Writes (peer -> backend) are authorized;
// denied tools/call requests are answered with a JSON-RPC error and never
// reach the backend. Reads (backend -> peer) pass through, interleaved
// with any synthetic denial responses on whole-line boundaries.
type Filter struct {
	inner  io.ReadWriteCloser
	eng    *Engine
	audit  *AuditLog
	tracer *Tracer
	caller Caller

	tainted atomic.Bool // set once an untrusted (taint_source) call is made

	wbuf []byte // reassembly of the peer -> backend line stream

	outR *io.PipeReader
	outW *io.PipeWriter
	omu  sync.Mutex // serializes whole-line writes to outW

	closeOnce sync.Once
}

// NewFilter wraps inner with a policy built from pol. pol, audit, and tracer
// are all optional: with a nil pol the filter forwards everything but still
// traces (if a tracer is set); with a nil tracer it only enforces policy. The
// engine it builds is private to this filter, so rate limits and co-sign are
// per-connection — use NewFilterEngine to share them across a backend's
// connections.
func NewFilter(inner io.ReadWriteCloser, caller Caller, pol *Policy, audit *AuditLog, tracer *Tracer) *Filter {
	var eng *Engine
	if pol != nil {
		eng = NewEngine(pol, nil, nil)
	}
	return NewFilterEngine(inner, caller, eng, audit, tracer)
}

// NewFilterEngine wraps inner with a shared Engine (nil to only trace). Use
// this when several connections to the same backend must share rate-limit
// buckets and the co-sign store.
func NewFilterEngine(inner io.ReadWriteCloser, caller Caller, eng *Engine, audit *AuditLog, tracer *Tracer) *Filter {
	r, w := io.Pipe()
	f := &Filter{inner: inner, eng: eng, audit: audit, tracer: tracer, caller: caller, outR: r, outW: w}
	go f.pumpInner()
	return f
}

// traceLine records one message if a tracer is configured.
func (f *Filter) traceLine(dir string, line []byte, decision string) {
	if f.tracer != nil {
		f.tracer.record(f.caller, dir, line, decision)
	}
}

func decisionStr(allow bool) string {
	if allow {
		return "allow"
	}
	return "deny"
}

// Read returns backend output plus any synthetic denial responses.
func (f *Filter) Read(p []byte) (int, error) { return f.outR.Read(p) }

// Write authorizes and forwards peer -> backend bytes.
func (f *Filter) Write(p []byte) (int, error) {
	// Fast path only when there is nothing to enforce and nothing to trace.
	if f.eng == nil && f.tracer == nil {
		return f.inner.Write(p)
	}
	f.wbuf = append(f.wbuf, p...)
	for {
		i := bytes.IndexByte(f.wbuf, '\n')
		if i < 0 {
			break
		}
		line := f.wbuf[:i+1]
		rest := f.wbuf[i+1:]
		if err := f.handleLine(line); err != nil {
			return 0, err
		}
		f.wbuf = append(f.wbuf[:0], rest...)
	}
	return len(p), nil
}

// Close tears down the filter and the backend.
func (f *Filter) Close() error {
	err := f.inner.Close()
	f.closeOnce.Do(func() { f.outW.Close() })
	return err
}

type rpcPeek struct {
	Method string          `json:"method"`
	ID     json.RawMessage `json:"id,omitempty"`
	Params struct {
		Name string `json:"name"`
	} `json:"params"`
}

// handleLine authorizes one JSON-RPC line and either forwards it to the
// backend or answers/drops it per policy. It governs three shapes:
// tools/call (by tool name), other requests (by method), and client
// notifications (by method; denied notifications are dropped since there
// is no id to answer).
func (f *Filter) handleLine(line []byte) error {
	trimmed := bytes.TrimSpace(line)
	if len(trimmed) == 0 {
		return nil
	}
	// A JSON-RPC batch (top-level array) can't be authorized per-entry by
	// this line filter, so a batch-capable backend could smuggle a denied
	// tools/call inside one. Refuse batches (when enforcing) rather than
	// forward blind.
	if trimmed[0] == '[' {
		if f.eng != nil {
			f.audit.write(f.record("<batch>", "", "", Decision{RuleID: -1, Reason: "batches unsupported"}))
			f.traceLine("c2s", trimmed, "deny")
			f.writeDenial(json.RawMessage("null"), "JSON-RPC batches are not supported by the mesh policy filter")
			return nil
		}
		f.traceLine("c2s", trimmed, "")
		_, werr := f.inner.Write(line)
		return werr
	}
	var msg rpcPeek
	if err := json.Unmarshal(trimmed, &msg); err != nil {
		// Unparseable single message: trace and pass through untouched.
		f.traceLine("c2s", trimmed, "")
		_, werr := f.inner.Write(line)
		return werr
	}

	// Tracing-only (no policy): record and forward everything.
	if f.eng == nil {
		f.traceLine("c2s", trimmed, "")
		_, werr := f.inner.Write(line)
		return werr
	}

	if len(msg.ID) == 0 {
		return f.handleNotification(line, msg.Method)
	}
	if msg.Method == "tools/call" {
		return f.handleToolCall(line, msg)
	}
	return f.handleMethod(line, msg)
}

func (f *Filter) handleToolCall(line []byte, msg rpcPeek) error {
	tool := msg.Params.Name
	dec := f.eng.DecideToolCall(f.caller.Peer, f.caller.PeerKey, tool, f.tainted.Load())
	rec := f.record(msg.Method, tool, string(msg.ID), dec)
	f.audit.write(rec)
	f.traceLine("c2s", line, rec.Decision)

	switch dec.Outcome {
	case OutcomeAllow:
		if dec.SetTaint {
			// This call brings untrusted data into the session; every
			// subsequent taint_guard tool is now blocked.
			f.tainted.Store(true)
		}
		_, werr := f.inner.Write(line)
		return werr
	case OutcomeCosign:
		f.writeDenial(msg.ID, fmt.Sprintf("tool %q requires a human co-sign on the mesh: %s", tool, dec.Reason))
		return nil
	default:
		reason := dec.Reason
		if reason == "" {
			reason = "denied by mesh policy"
		}
		f.writeDenial(msg.ID, fmt.Sprintf("tool %q blocked for peer %s: %s", tool, f.caller.Peer, reason))
		return nil
	}
}

// handleMethod governs a non-tool request (e.g. tasks/cancel). Methods are
// audited and enforced only when a Methods rule matches; ungoverned methods
// (initialize, tools/list, ...) pass through unaudited.
func (f *Filter) handleMethod(line []byte, msg rpcPeek) error {
	dec := f.eng.pol.DecideMethod(f.caller.Peer, f.caller.PeerKey, msg.Method)
	if dec.RuleID == -1 {
		f.traceLine("c2s", line, "")
		_, werr := f.inner.Write(line)
		return werr
	}
	f.audit.write(f.record(msg.Method, "", string(msg.ID), dec))
	f.traceLine("c2s", line, decisionStr(dec.Allow))
	if dec.Allow {
		_, werr := f.inner.Write(line)
		return werr
	}
	f.writeDenial(msg.ID, fmt.Sprintf("method %q denied by mesh policy for peer %s", msg.Method, f.caller.Peer))
	return nil
}

// handleNotification governs a client notification. A denied notification
// is dropped (no id to answer). Ungoverned notifications pass through so
// protocol-critical ones like notifications/initialized are never lost.
func (f *Filter) handleNotification(line []byte, method string) error {
	dec := f.eng.pol.DecideMethod(f.caller.Peer, f.caller.PeerKey, method)
	if dec.RuleID == -1 {
		f.traceLine("c2s", line, "")
		_, werr := f.inner.Write(line)
		return werr
	}
	f.audit.write(f.record(method, "", "", dec))
	f.traceLine("c2s", line, decisionStr(dec.Allow))
	if !dec.Allow {
		return nil // drop
	}
	_, werr := f.inner.Write(line)
	return werr
}

func (f *Filter) record(method, tool, rpcID string, dec Decision) AuditRecord {
	return AuditRecord{
		Backend:  f.caller.Backend,
		Peer:     f.caller.Peer,
		PeerKey:  f.caller.PeerKey,
		PeerAddr: f.caller.PeerAddr,
		Method:   method,
		Tool:     tool,
		RPCID:    rpcID,
		Decision: dec.Outcome.String(),
		Reason:   dec.Reason,
		Rule:     dec.RuleID,
	}
}

// writeDenial emits a JSON-RPC error toward the peer for a blocked request.
func (f *Filter) writeDenial(id json.RawMessage, message string) {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	msg, _ := json.Marshal(message)
	resp := fmt.Sprintf(
		`{"jsonrpc":"2.0","id":%s,"error":{"code":-32001,"message":%s}}`+"\n",
		id, msg)
	f.writeOut([]byte(resp))
}

// pumpInner copies backend output to the read side, framed on newlines so
// synthetic denials never interleave inside a backend message.
func (f *Filter) pumpInner() {
	buf := make([]byte, 64*1024)
	var line []byte
	for {
		n, err := f.inner.Read(buf)
		if n > 0 {
			line = append(line, buf[:n]...)
			for {
				i := bytes.IndexByte(line, '\n')
				if i < 0 {
					break
				}
				f.traceLine("s2c", line[:i], "")
				f.writeOut(line[:i+1])
				line = line[i+1:]
			}
		}
		if err != nil {
			if len(line) > 0 {
				f.traceLine("s2c", line, "")
				f.writeOut(line)
			}
			f.closeOnce.Do(func() { f.outW.CloseWithError(err) })
			return
		}
	}
}

func (f *Filter) writeOut(b []byte) {
	f.omu.Lock()
	defer f.omu.Unlock()
	_, _ = f.outW.Write(b)
}
