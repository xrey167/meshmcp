package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"meshmcp/policy"
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
	return &httpEnforcer{eng: eng, audit: audit, pending: pending, backend: b.Name}
}

// httpPeek is the minimal JSON-RPC shape read from a request body.
type httpPeek struct {
	Method string          `json:"method"`
	ID     json.RawMessage `json:"id,omitempty"`
	Params struct {
		Name string `json:"name"`
	} `json:"params"`
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

	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return true, 0, nil
	}
	// A JSON-RPC batch can't be authorized per-entry — refuse it, as the stdio
	// filter does.
	if trimmed[0] == '[' {
		_ = e.audit.Append(e.record("<batch>", "", "", policy.Decision{RuleID: -1, Reason: "batches unsupported"}, peer, peerKey))
		return false, http.StatusOK, jsonRPCError(json.RawMessage("null"), "JSON-RPC batches are not supported by the mesh policy filter")
	}
	var msg httpPeek
	if json.Unmarshal(trimmed, &msg) != nil {
		// Under enforcement an unparseable body must not reach the backend.
		_ = e.audit.Append(e.record("<unparseable>", "", "", policy.Decision{RuleID: -1, Reason: "unparseable JSON-RPC"}, peer, peerKey))
		return false, http.StatusOK, jsonRPCError(json.RawMessage("null"), "unparseable JSON-RPC rejected by mesh policy")
	}
	if msg.Method != "tools/call" {
		return true, 0, nil // ungoverned method: pass through
	}

	dec := e.eng.DecideToolCall(peer, peerKey, msg.Params.Name, nil)
	_ = e.audit.Append(e.record(msg.Method, msg.Params.Name, string(msg.ID), dec, peer, peerKey))

	switch dec.Outcome {
	case policy.OutcomeAllow:
		return true, 0, nil
	case policy.OutcomeCosign:
		if e.pending != nil {
			_ = e.pending.Record(policy.Pending{Peer: peer, PeerKey: peerKey, Backend: e.backend, Tool: msg.Params.Name, RPCID: string(msg.ID)})
		}
		return false, http.StatusOK, jsonRPCError(msg.ID, fmt.Sprintf("tool %q requires a human co-sign on the mesh: %s", msg.Params.Name, dec.Reason))
	default:
		reason := dec.Reason
		if reason == "" {
			reason = "denied by mesh policy"
		}
		return false, http.StatusOK, jsonRPCError(msg.ID, fmt.Sprintf("tool %q blocked for peer %s: %s", msg.Params.Name, peer, reason))
	}
}

func (e *httpEnforcer) record(method, tool, rpcID string, dec policy.Decision, peer, peerKey string) policy.AuditRecord {
	return policy.AuditRecord{
		Backend: e.backend, Peer: peer, PeerKey: peerKey,
		Method: method, Tool: tool, RPCID: rpcID,
		Decision: dec.Outcome.String(), Reason: dec.Reason, Rule: dec.RuleID,
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
