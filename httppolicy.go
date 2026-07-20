package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/xrey167/meshmcp/policy"
)

// httpEnforcer applies the same identity-keyed policy engine to a Streamable-HTTP
// backend that the stdio Filter applies to a stdio backend (F16). It parses the
// JSON-RPC in a POST body, authorizes tools/call by the caller's mesh identity,
// audits the decision, and denies inline — so the firewall is no longer
// stdio-only. Taint labels, secret injection, and capability upgrades stay on
// the stdio path for now (they need per-session state / body rewriting over
// SSE); policy, rate limits, time windows, co-sign, and audit all work here.
type httpEnforcer struct {
	eng     *policy.Engine
	audit   *policy.AuditLog
	pending *policy.FilePending
	backend string
}

// newHTTPEnforcer builds the enforcer for an HTTP backend that declares a
// policy. audit may be the gateway-wide shared ledger or a per-backend sink.
func newHTTPEnforcer(b *Backend, audit *policy.AuditLog) *httpEnforcer {
	var cosign policy.CosignStore
	var pending *policy.FilePending
	if b.CosignStore != "" {
		ttl := time.Duration(b.CosignTTLSeconds) * time.Second
		cosign = &policy.FileCosign{Dir: b.CosignStore, TTL: ttl}
		pending = &policy.FilePending{Dir: b.CosignStore, TTL: ttl}
	}
	eng := policy.NewEngine(b.Policy, func() time.Time { return time.Now() }, cosign)
	if len(b.groups) > 0 {
		eng.SetGroupResolver(policy.StaticGroups(b.groups))
	}
	return &httpEnforcer{eng: eng, audit: audit, pending: pending, backend: b.Name}
}

// decide authorizes the request. It returns ok=true (and possibly a rewound
// body to forward) when the call may proceed, or ok=false with a status code and
// a JSON-RPC error body to return without proxying. Non-tools/call requests and
// non-JSON bodies pass through (only tools/call is governed, mirroring the stdio
// filter's method handling).
func (e *httpEnforcer) decide(peer, peerKey string, r *http.Request) (ok bool, status int, denialBody []byte) {
	if r.Method != http.MethodPost || r.Body == nil {
		return true, 0, nil
	}
	// Bound and read the body so we can peek at the JSON-RPC and then restore it.
	body, err := io.ReadAll(io.LimitReader(r.Body, maxHTTPBody))
	r.Body.Close()
	if err != nil {
		return true, 0, nil // let the proxy surface a read error
	}
	// Always restore the body for the proxy (even on the pass-through paths).
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))

	// Classify + validate through the SHARED classifier, so an HTTP backend
	// makes the SAME decision as the stdio filter for the same request: id-less
	// / null-id / empty-name tools/call, duplicate keys, and batches are all
	// rejected identically (Phase 7 conformance).
	class := policy.ClassifyRPC(body)
	switch class.Kind {
	case policy.RPCEmpty:
		return true, 0, nil
	case policy.RPCBatch:
		_ = e.audit.Append(e.record("<batch>", "", "", policy.Decision{RuleID: -1, Reason: "batches unsupported"}, peer, peerKey))
		return false, http.StatusOK, jsonRPCError(json.RawMessage("null"), class.Reason)
	case policy.RPCInvalid:
		method := class.Method
		if method == "" {
			method = "<invalid>"
		}
		_ = e.audit.Append(e.record(method, class.Tool, string(class.ID), policy.Decision{RuleID: -1, Outcome: policy.OutcomeDeny, Reason: class.Reason}, peer, peerKey))
		return false, http.StatusOK, jsonRPCError(class.ID, class.Reason)
	case policy.RPCNotification:
		// A notification has no id to answer; mirror the stdio filter by dropping
		// it if a Methods rule denies it, otherwise pass through.
		if md := e.eng.Policy().DecideMethod(peer, peerKey, class.Method); md.RuleID != -1 && !md.Allow {
			_ = e.audit.Append(e.record(class.Method, "", "", md, peer, peerKey))
			return false, http.StatusOK, nil // dropped: no body
		}
		return true, 0, nil
	case policy.RPCMethod:
		// Govern non-tool methods identically to stdio (opt-in Methods rules).
		md := e.eng.Policy().DecideMethod(peer, peerKey, class.Method)
		if md.RuleID == -1 {
			return true, 0, nil // ungoverned: pass through
		}
		auditErr := e.audit.Append(e.record(class.Method, "", string(class.ID), md, peer, peerKey))
		if md.Allow {
			if auditErr != nil && e.audit.FailClosed() {
				return false, http.StatusOK, jsonRPCError(class.ID, fmt.Sprintf("method %q blocked: audit sink unavailable (fail-closed)", class.Method))
			}
			return true, 0, nil
		}
		return false, http.StatusOK, jsonRPCError(class.ID, fmt.Sprintf("method %q denied by mesh policy for peer %s", class.Method, peer))
	}

	// RPCToolCall.
	dec := e.eng.DecideToolCallBound(peer, peerKey, e.backend, class.Tool, class.Args, nil)
	auditErr := e.audit.Append(e.record("tools/call", class.Tool, string(class.ID), dec, peer, peerKey))
	switch dec.Outcome {
	case policy.OutcomeAllow:
		// Audit is a control: if the record cannot be written and the log is
		// fail-closed, deny rather than proxy an unrecorded call (parity with the
		// stdio filter).
		if auditErr != nil && e.audit.FailClosed() {
			return false, http.StatusOK, jsonRPCError(class.ID, fmt.Sprintf("tool %q blocked: audit sink unavailable (fail-closed)", class.Tool))
		}
		return true, 0, nil
	case policy.OutcomeCosign:
		if e.pending != nil {
			_ = e.pending.Record(policy.Pending{Peer: peer, PeerKey: peerKey, Backend: e.backend, Tool: class.Tool, RPCID: string(class.ID)})
		}
		return false, http.StatusOK, jsonRPCError(class.ID, fmt.Sprintf("tool %q requires a human co-sign on the mesh: %s", class.Tool, dec.Reason))
	default:
		reason := dec.Reason
		if reason == "" {
			reason = "denied by mesh policy"
		}
		return false, http.StatusOK, jsonRPCError(class.ID, fmt.Sprintf("tool %q blocked for peer %s: %s", class.Tool, peer, reason))
	}
}

func (e *httpEnforcer) record(method, tool, rpcID string, dec policy.Decision, peer, peerKey string) policy.AuditRecord {
	return policy.AuditRecord{
		Backend: e.backend, Peer: peer, PeerKey: peerKey,
		Method: method, Tool: tool, RPCID: rpcID,
		Decision: dec.Outcome.String(), Reason: dec.Reason, Rule: dec.RuleID, Cost: dec.Cost,
	}
}

// jsonRPCError renders a JSON-RPC error response body.
func jsonRPCError(id json.RawMessage, message string) []byte {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	m, _ := json.Marshal(message)
	return []byte(fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"error":{"code":-32001,"message":%s}}`+"\n", id, m))
}

// maxHTTPBody bounds a request body the enforcer will buffer to peek at.
const maxHTTPBody = 16 << 20
