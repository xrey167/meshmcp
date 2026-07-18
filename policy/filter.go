package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sync"
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
	inner       io.ReadWriteCloser
	eng         *Engine
	audit       *AuditLog
	tracer      *Tracer
	secrets     SecretResolver
	pending     PendingStore
	capVerifier *CapabilityVerifier
	capRequired bool
	caller      Caller
	hook        EventHook

	lmu    sync.Mutex      // guards labels
	labels map[string]bool // data-flow labels accumulated this session

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
	f := &Filter{inner: inner, eng: eng, audit: audit, tracer: tracer, caller: caller,
		labels: map[string]bool{}, outR: r, outW: w}
	go f.pumpInner()
	return f
}

// EventHook observes policy decisions as they are audited, so the gateway can
// publish them onto the event bus or a webhook. It is deliberately decoupled
// from enforcement: Emit MUST NOT block or error the request path — it is
// called inline on every decision, and a slow or failing sink must never delay
// or change a decision. Implementations should hand the record to a buffered
// worker and return immediately.
type EventHook interface {
	Emit(AuditRecord)
}

// SetEventHook attaches an EventHook. Safe to call before the filter carries
// traffic (during construction).
func (f *Filter) SetEventHook(h EventHook) { f.hook = h }

// audited writes a decision to the audit log and forwards it to the event hook
// (if any). The hook is fire-and-forget: it never blocks or fails the caller.
func (f *Filter) audited(rec AuditRecord) {
	f.audit.write(rec)
	if f.hook != nil {
		f.hook.Emit(rec)
	}
}

// labelSnapshot copies the current session label set for a decision.
func (f *Filter) labelSnapshot() map[string]bool {
	f.lmu.Lock()
	defer f.lmu.Unlock()
	if len(f.labels) == 0 {
		return nil
	}
	out := make(map[string]bool, len(f.labels))
	for k := range f.labels {
		out[k] = true
	}
	return out
}

// addLabels records labels an allowed call contributed to the session.
func (f *Filter) addLabels(ls []string) {
	if len(ls) == 0 {
		return
	}
	f.lmu.Lock()
	defer f.lmu.Unlock()
	for _, l := range ls {
		f.labels[l] = true
	}
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
			f.audited(f.record("<batch>", "", "", Decision{RuleID: -1, Reason: "batches unsupported"}))
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

	// Strip any presented capability from EVERY governed client->backend line
	// so the token never reaches the backend, trace, audit, or secret injection.
	// It is honored only on tools/call (below); on tasks/*, tools/list, and
	// notifications it is simply removed — a caller sets it once on the session,
	// so it rides along on follow-up requests (e.g. task polling) that must not
	// forward it. Non-token lines are returned byte-identical.
	var capToken string
	if f.capVerifier != nil {
		capToken, line = stripCapability(line)
	}

	if len(msg.ID) == 0 {
		return f.handleNotification(line, msg.Method)
	}
	if msg.Method == "tools/call" {
		return f.handleToolCall(line, msg, capToken)
	}
	return f.handleMethod(line, msg)
}

// handleToolCall authorizes a tools/call. The capability (if any) has already
// been stripped from line by handleLine and passed in as capToken, so every
// downstream step (audit, trace, secret injection, backend write) uses the
// token-free line.
func (f *Filter) handleToolCall(line []byte, msg rpcPeek, capToken string) error {
	tool := msg.Params.Name

	dec := f.eng.DecideToolCall(f.caller.Peer, f.caller.PeerKey, tool, f.labelSnapshot())
	if f.capVerifier != nil {
		dec = f.applyCapability(dec, capToken, tool)
	}
	rec := f.record(msg.Method, tool, string(msg.ID), dec)
	f.audited(rec)
	f.traceLine("c2s", line, rec.Decision)

	switch dec.Outcome {
	case OutcomeAllow:
		// This call may bring classified/untrusted data into the session;
		// record its labels so downstream block_labels rules can act on them.
		f.addLabels(dec.AddLabels)
		// Inject secrets last — after audit + trace — so the resolved value
		// reaches only the backend, never the audit or trace. A denied
		// injection (ungranted / tainted / unavailable) blocks the call.
		outLine := line
		if f.secrets != nil {
			resolved, ok, reason := f.secrets.Resolve(f.caller, tool, line, f.labelSnapshot())
			if !ok {
				f.writeDenial(msg.ID, fmt.Sprintf("tool %q blocked: %s", tool, reason))
				return nil
			}
			outLine = resolved
		}
		_, werr := f.inner.Write(outLine)
		return werr
	case OutcomeCosign:
		// Record the held request so a human (e.g. a phone on the mesh) can
		// see and approve it — the co-sign becomes an inbox, not a silent deny.
		if f.pending != nil {
			_ = f.pending.Record(Pending{
				Peer: f.caller.Peer, PeerKey: f.caller.PeerKey, Backend: f.caller.Backend,
				Tool: tool, RPCID: string(msg.ID),
			})
		}
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
	f.audited(f.record(msg.Method, "", string(msg.ID), dec))
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
	f.audited(f.record(method, "", "", dec))
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
