package policy

import (
	"bytes"
	"encoding/json"
	"errors"
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
	// SpiffeID is the caller's derived, additive SPIFFE identity label
	// (Feature A), stamped verbatim onto every audit record this filter
	// writes. Derivation happens at the edge (the serve wiring calls
	// SpiffeID(trustDomain, peerKey)); the filter itself stays ignorant of
	// trust domains. Empty means no label (no trust domain configured), and
	// the audit field is elided. A label only — enforcement keys on PeerKey.
	SpiffeID SpiffeLabel
}

// Filter wraps a backend MCP server's stdio and enforces a Policy on the
// JSON-RPC flowing through it. Writes (peer -> backend) are authorized;
// denied tools/call requests are answered with a JSON-RPC error and never
// reach the backend. Reads (backend -> peer) pass through, interleaved
// with any synthetic denial responses on whole-line boundaries.
// maxLineBytes caps a single reassembled client->backend JSON-RPC line, so a
// peer that never sends a newline cannot grow the filter's buffer without
// bound. Matches the audit/verify line cap.
const maxLineBytes = 16 << 20 // 16 MiB

// errLineTooLong tears down a connection whose pending line exceeds maxLineBytes.
var errLineTooLong = errors.New("policy: client line exceeds maximum length")

type Filter struct {
	inner       io.ReadWriteCloser
	eng         *Engine
	audit       *AuditLog
	tracer      *Tracer
	secrets     SecretResolver
	pending     PendingStore
	capVerifier *CapabilityVerifier
	capRequired bool

	// Router-delegation enforcement (Phase 4): verifies a signed per-call
	// DelegationToken from a pinned router authority and authorizes the
	// intersection of the original caller's and the router's permissions.
	delegVerifier *DelegationVerifier
	delegRequired bool
	hooks         []DecisionHook
	caller        Caller
	hook          EventHook

	redactor *Redactor // scrubs injected secret values from responses (Phase 8)

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
		labels: map[string]bool{}, outR: r, outW: w, redactor: &Redactor{}}
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
// (if any). It returns the write error so a fail-closed caller can deny an
// unrecorded call (F22); the hook is fire-and-forget and never blocks or fails
// the caller.
//
// Routing every decision through this one choke point keeps two controls in
// lock-step: the tamper-evident ledger AND the event hook (pub/sub bus /
// webhook) both observe the same decision, so no code path can record a
// decision without also publishing it (or vice versa).
//
// Every decision is recorded — including denials and rate-limit blocks. That is
// deliberate and differs from the pub/sub broker (which drops rate-limited
// attempts unaudited): the gateway's tool-call ledger is the non-repudiable
// security record, and denied/blocked attempts are precisely what a security
// audit must retain. Flood protection is the policy engine's per-rule rate
// limits plus operational log rotation, not silence about denials.
func (f *Filter) audited(rec AuditRecord) error {
	err := f.audit.write(rec)
	if f.hook != nil {
		f.hook.Emit(rec)
	}
	return err
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
	// A peer streaming bytes with no newline would grow this reassembly buffer
	// without bound — a memory-DoS on the enforcement path. Cap the pending
	// line and tear the connection down when it is exceeded.
	if len(f.wbuf) > maxLineBytes {
		f.wbuf = nil
		return 0, errLineTooLong
	}
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
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	} `json:"params"`
}

// handleLine authorizes one JSON-RPC line and either forwards it to the
// backend or answers/drops it per policy. It governs three shapes:
// tools/call (by tool name), other requests (by method), and client
// notifications (by method; denied notifications are dropped since there
// is no id to answer).
func (f *Filter) handleLine(line []byte) error {
	// Tracing-only (no policy): record and forward everything untouched,
	// including batches / unparseable lines (there is nothing to enforce).
	if f.eng == nil {
		trimmed := bytes.TrimSpace(line)
		if len(trimmed) == 0 {
			return nil
		}
		f.traceLine("c2s", trimmed, "")
		_, werr := f.inner.Write(line)
		return werr
	}

	// Classify + validate through the SHARED classifier, so the stdio path and
	// the Streamable-HTTP enforcer cannot drift on which requests are rejected,
	// governed, or passed through (Phase 7).
	class := ClassifyRPC(line)

	// Strip any presented capability from EVERY governed client->backend line so
	// the token never reaches the backend, trace, audit, or secret injection. It
	// is honored only on tools/call (via capToken); on tasks/*, tools/list, and
	// notifications it is simply removed — a caller sets it once on the session,
	// so it rides along on follow-up requests that must not forward it.
	var capToken string
	if f.capVerifier != nil {
		switch class.Kind {
		case RPCToolCall, RPCNotification, RPCMethod:
			capToken, line = stripCapability(line)
		}
	}

	// Strip any presented delegation token the same way: honored only on
	// tools/call, removed from every governed line so it never reaches the
	// backend, trace, audit, or secret injection.
	var delegToken string
	if f.delegVerifier != nil {
		switch class.Kind {
		case RPCToolCall, RPCNotification, RPCMethod:
			delegToken, line = stripMetaToken(line, DelegationMetaKey)
		}
	}

	switch class.Kind {
	case RPCEmpty:
		return nil
	case RPCBatch:
		_ = f.audited(f.record("<batch>", "", "", Decision{RuleID: -1, Reason: "batches unsupported"}))
		f.traceLine("c2s", line, "deny")
		f.writeDenial(json.RawMessage("null"), class.Reason)
		return nil
	case RPCInvalid:
		method := class.Method
		if method == "" {
			method = "<invalid>"
		}
		_ = f.audited(f.record(method, class.Tool, string(class.ID), Decision{RuleID: -1, Outcome: OutcomeDeny, Reason: class.Reason}))
		f.traceLine("c2s", line, "deny")
		f.writeDenial(class.ID, class.Reason)
		return nil
	case RPCToolCall:
		return f.handleToolCall(line, class.Tool, class.ID, class.Args, capToken, delegToken)
	case RPCNotification:
		return f.handleNotification(line, class.Method)
	default: // RPCMethod
		return f.handleMethod(line, class.Method, class.ID)
	}
}

// validRequestID reports whether id is a usable JSON-RPC request id: present
// and not null. A string (including "") or a number is accepted; an absent or
// null id is not. A tools/call lacking a valid id is a malformed MCP request.
func validRequestID(id json.RawMessage) bool {
	t := bytes.TrimSpace(id)
	return len(t) != 0 && !bytes.Equal(t, []byte("null"))
}

// checkNoDuplicateKeys walks a JSON document and returns an error if any object
// (at any depth) contains a duplicated key. This closes the parser-differential
// gap where the strict peek here and the downstream backend could disagree on
// method, id, or tool name.
func checkNoDuplicateKeys(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := scanNoDupKeys(dec); err != nil {
		return err
	}
	// Reject trailing garbage after the first value (a second concatenated
	// document could be re-parsed differently by a lenient backend).
	if _, err := dec.Token(); err != io.EOF {
		if err == nil {
			return errors.New("policy: trailing data after JSON value")
		}
		return err
	}
	return nil
}

func scanNoDupKeys(dec *json.Decoder) error {
	t, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := t.(json.Delim)
	if !ok {
		return nil // scalar
	}
	switch delim {
	case '{':
		seen := make(map[string]struct{})
		for dec.More() {
			kt, err := dec.Token()
			if err != nil {
				return err
			}
			key, ok := kt.(string)
			if !ok {
				return errors.New("policy: non-string object key")
			}
			if _, dup := seen[key]; dup {
				return fmt.Errorf("policy: duplicate JSON key %q", key)
			}
			seen[key] = struct{}{}
			if err := scanNoDupKeys(dec); err != nil {
				return err
			}
		}
		_, err := dec.Token() // consume '}'
		return err
	case '[':
		for dec.More() {
			if err := scanNoDupKeys(dec); err != nil {
				return err
			}
		}
		_, err := dec.Token() // consume ']'
		return err
	}
	return nil
}

// handleToolCall authorizes a tools/call. The capability and delegation
// tokens (if any) have already been stripped from line by handleLine and
// passed in as capToken/delegToken, so every downstream step (audit, trace,
// secret injection, backend write) uses the token-free line.
func (f *Filter) handleToolCall(line []byte, tool string, id, args json.RawMessage, capToken, delegToken string) error {
	// id validity and a non-empty tool name are guaranteed by ClassifyRPC (an
	// id-less / null-id / empty-name tools/call is rejected there as
	// protocol-invalid before reaching this handler).

	// Bind co-sign approvals to this exact backend + arguments (Phase 3): a
	// require_cosign rule is satisfied only by a signed, single-use approval for
	// precisely these arguments, which DecideToolCallBound consumes atomically.
	dec := f.eng.DecideToolCallBound(f.caller.Peer, f.caller.PeerKey, f.caller.Backend, tool, args, f.labelSnapshot())
	var pendingCap *CapabilityClaims
	if f.capVerifier != nil {
		dec, pendingCap = f.applyCapability(dec, capToken, tool)
	}
	// Router delegation runs AFTER the capability fold, so a capability held by
	// the connecting router can never upgrade a delegation deny (a delegation
	// deny always carries outcome deny out of applyDelegation) and the router
	// leg of the intersection reflects everything the router itself may do.
	var da delegationAudit
	if f.delegVerifier != nil {
		dec, da = f.applyDelegation(dec, delegToken, tool, args)
	}
	// Plugin decision hooks run last and may only tighten the outcome (deny /
	// co-sign) or add labels — never widen a deny into an allow.
	if len(f.hooks) > 0 {
		dec = applyDecisionHooks(f.hooks, ToolCallInfo{
			Caller: f.caller, Tool: tool, Arguments: args, Labels: f.labelSnapshot(),
		}, dec)
	}
	// Consume a load-bearing single-use grant only now that the final outcome
	// is known: a cosign hold or a delegation/hook deny must not burn it. A
	// replayed jti surfaces here and turns the allow into a deny, so the audit
	// record below reflects the true verdict.
	if pendingCap != nil && dec.Outcome == OutcomeAllow {
		if err := f.capVerifier.Consume(*pendingCap); err != nil {
			dec = Decision{Outcome: OutcomeDeny, RuleID: dec.RuleID, Reason: "invalid capability: " + err.Error()}
		}
	}
	rec := f.record("tools/call", tool, string(id), dec)
	if da.relevant {
		// Preserve BOTH identities + the nonce for a delegated (or
		// delegation-required) call, so it is attributable end to end — on
		// allows and denials alike (spec ROUTER-DELEGATION.md).
		rec.DelegatedCaller = da.caller
		rec.DelegationRouter = f.caller.PeerKey
		rec.DelegationNonce = da.nonce
	}
	if err := f.audited(rec); err != nil && f.audit.FailClosed() {
		// Audit is a control: if the tamper-evident record cannot be written
		// and the log is fail-closed, deny the call rather than let it reach
		// the backend unrecorded.
		f.traceLine("c2s", line, "deny")
		f.writeDenial(id, fmt.Sprintf("tool %q blocked: audit sink unavailable (fail-closed)", tool))
		return nil
	}
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
			resolved, injected, ok, reason := f.secrets.Resolve(f.caller, tool, line, f.labelSnapshot())
			if !ok {
				f.writeDenial(id, fmt.Sprintf("tool %q blocked: %s", tool, reason))
				return nil
			}
			// Record injected values so the response pump can scrub them: a
			// backend must not be able to echo an injected credential back to
			// the agent (best-effort; see Redactor / the threat model). The
			// redactor is created at construction, so this Add is concurrency-safe
			// against pumpInner's Redact.
			if len(injected) > 0 {
				f.redactor.Add(injected...)
			}
			outLine = resolved
		}
		_, werr := f.inner.Write(outLine)
		return werr
	case OutcomeCosign:
		// Record the held request so a human (e.g. a phone on the mesh) can
		// see and approve it — the co-sign becomes an inbox, not a silent deny.
		if f.pending != nil {
			// Carry the argument + policy binding so an approver can mint a
			// request-bound approval for exactly these arguments under this policy.
			_ = f.pending.Record(Pending{
				Peer: f.caller.Peer, PeerKey: f.caller.PeerKey, Backend: f.caller.Backend,
				Tool: tool, RPCID: string(id),
				ArgsHash: canonicalArgsHash(args), PolicyHash: f.eng.PolicyHash(),
			})
		}
		f.writeDenial(id, fmt.Sprintf("tool %q requires a human co-sign on the mesh: %s", tool, dec.Reason))
		return nil
	default:
		reason := dec.Reason
		if reason == "" {
			reason = "denied by mesh policy"
		}
		f.writeDenial(id, fmt.Sprintf("tool %q blocked for peer %s: %s", tool, f.caller.Peer, reason))
		return nil
	}
}

// handleMethod governs a non-tool request (e.g. tasks/cancel). Methods are
// audited and enforced only when a Methods rule matches; ungoverned methods
// (initialize, tools/list, ...) pass through unaudited.
func (f *Filter) handleMethod(line []byte, method string, id json.RawMessage) error {
	dec := f.eng.Policy().DecideMethod(f.caller.Peer, f.caller.PeerKey, method)
	if dec.RuleID == -1 {
		f.traceLine("c2s", line, "")
		_, werr := f.inner.Write(line)
		return werr
	}
	auditErr := f.audited(f.record(method, "", string(id), dec))
	f.traceLine("c2s", line, decisionStr(dec.Allow))
	if dec.Allow {
		if auditErr != nil && f.audit.FailClosed() {
			f.writeDenial(id, fmt.Sprintf("method %q blocked: audit sink unavailable (fail-closed)", method))
			return nil
		}
		_, werr := f.inner.Write(line)
		return werr
	}
	f.writeDenial(id, fmt.Sprintf("method %q denied by mesh policy for peer %s", method, f.caller.Peer))
	return nil
}

// handleNotification governs a client notification. A denied notification
// is dropped (no id to answer). Ungoverned notifications pass through so
// protocol-critical ones like notifications/initialized are never lost.
func (f *Filter) handleNotification(line []byte, method string) error {
	dec := f.eng.Policy().DecideMethod(f.caller.Peer, f.caller.PeerKey, method)
	if dec.RuleID == -1 {
		f.traceLine("c2s", line, "")
		_, werr := f.inner.Write(line)
		return werr
	}
	auditErr := f.audited(f.record(method, "", "", dec))
	f.traceLine("c2s", line, decisionStr(dec.Allow))
	if !dec.Allow {
		return nil // drop
	}
	if auditErr != nil && f.audit.FailClosed() {
		return nil // fail closed: drop an unaudited (would-be-allowed) notification
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
		Cost:     dec.Cost,

		PeerSpiffeID: f.caller.SpiffeID,
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
				// Scrub any injected secret value a backend tried to echo,
				// before it reaches the trace or the peer.
				red := f.redactor.Redact(line[:i+1])
				f.traceLine("s2c", bytes.TrimRight(red, "\n"), "")
				f.writeOut(red)
				line = line[i+1:]
			}
		}
		if err != nil {
			if len(line) > 0 {
				red := f.redactor.Redact(line)
				f.traceLine("s2c", red, "")
				f.writeOut(red)
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
