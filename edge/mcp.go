package edge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/xrey167/meshmcp/policy"
)

// MCP session + protocol-version headers. Mcp-Session-Id is defined here (not in
// protocol/transport/streamablehttp, whose contract is the sessionless draft).
const (
	headerSessionID       = "Mcp-Session-Id"
	headerProtocolVersion = "MCP-Protocol-Version"
)

// supportedProtocolVersions are the MCP revisions the edge accepts. Absent
// header defaults to the earliest (back-compat); an unsupported value is a 400.
var supportedProtocolVersions = map[string]bool{
	"2025-03-26": true,
	"2025-06-18": true,
}

// handleMCP is the public MCP endpoint: POST relays one JSON-RPC request, GET
// opens the SSE server stream, DELETE ends a session. Every path is bearer- and
// policy-gated; there is no unauthenticated route to a tool.
func (s *Server) handleMCP(w http.ResponseWriter, r *http.Request) {
	if v := r.Header.Get(headerProtocolVersion); v != "" && !supportedProtocolVersions[v] {
		http.Error(w, "unsupported MCP-Protocol-Version", http.StatusBadRequest)
		return
	}
	switch r.Method {
	case http.MethodPost:
		s.mcpPost(w, r)
	case http.MethodGet:
		s.mcpGet(w, r)
	case http.MethodDelete:
		s.mcpDelete(w, r)
	default:
		methodNotAllowed(w, http.MethodPost, http.MethodGet, http.MethodDelete)
	}
}

// authed is the result of validating a bearer token on an MCP request.
type authed struct {
	clientID string
	access   accessRecord
}

// authenticate validates the bearer token: it must exist, be unexpired, and
// belong to a still-approved client. It does NOT check the capability here —
// that is the per-tool-call double-gate in mcpPost. On failure it writes the
// 401 challenge and returns ok=false.
func (s *Server) authenticate(w http.ResponseWriter, r *http.Request) (authed, bool) {
	tok := bearerToken(r)
	if tok == "" {
		s.writeBearerChallenge(w, "")
		return authed{}, false
	}
	acc, err := s.tokens.getAccess(tok)
	if err != nil {
		if os.IsNotExist(err) {
			s.writeBearerChallenge(w, "invalid_token")
			return authed{}, false
		}
		http.Error(w, "token lookup failed", http.StatusInternalServerError)
		return authed{}, false
	}
	if s.now().After(acc.ExpiresAt) {
		s.writeBearerChallenge(w, "invalid_token")
		return authed{}, false
	}
	client, err := s.clients.Get(acc.ClientID)
	if err != nil || client.Status != ClientApproved {
		// Client revoked/denied since the token was issued — immediate deny.
		s.writeBearerChallenge(w, "invalid_token")
		return authed{}, false
	}
	if !s.clientLimit.allow(oauthIdentity(acc.ClientID)) {
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return authed{}, false
	}
	return authed{clientID: acc.ClientID, access: acc}, true
}

// mcpPost relays one JSON-RPC request to the backend after enforcement.
func (s *Server) mcpPost(w http.ResponseWriter, r *http.Request) {
	au, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, int64(s.cfg.Limits.MaxMCPBodyBytes))
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
		return
	}

	class := policy.ClassifyRPC(body)
	switch class.Kind {
	case policy.RPCEmpty:
		http.Error(w, "empty request", http.StatusBadRequest)
		return
	case policy.RPCBatch, policy.RPCInvalid:
		http.Error(w, "unsupported or invalid JSON-RPC: "+class.Reason, http.StatusBadRequest)
		return
	}
	// The classifier extracts the tool name/arguments for policy, but the backend
	// must receive the ORIGINAL params (e.g. {"name","arguments"} for tools/call,
	// the initialize params, etc.), so forward those verbatim.
	var envelope struct {
		Params json.RawMessage `json:"params"`
	}
	_ = json.Unmarshal(body, &envelope)

	// Resolve or (on initialize) create the session; a session error is terminal.
	sess, status, serr := s.resolveSession(w, r, au, class)
	if serr != "" {
		http.Error(w, serr, status)
		return
	}

	// Enforce tool calls: the capability double-gate first (an Ed25519 grant the
	// on-disk record cannot widen), then the deny-by-default policy engine.
	var paid *paidCall
	if class.Kind == policy.RPCToolCall {
		if allowed, denyBody := s.enforceToolCall(au, class); !allowed {
			s.writeJSONRPC(w, denyBody)
			return
		}
		// Payment gate (opt-in): a priced tool needs a verified x402 payment
		// before it forwards; a free dry-run route answers without charging. Runs
		// AFTER the capability + policy double-gate — payment never buys access a
		// deny-by-default policy withheld. No-op when payment is disabled. On a
		// settled paid call it returns the evidence so a subsequent backend
		// failure can be recorded against the same (already-spent) settlement.
		if s.payment != nil {
			var proceed bool
			if proceed, paid = s.gatePayment(w, r, au, sess, class); !proceed {
				return // 402 challenge, dry-run result, or fail-closed error already written
			}
		}
	} else {
		// Non-tool methods/notifications: audit and forward (the backend is a
		// single tool-scoped surface; the tools/call gate is the control).
		_ = s.auditDecision(au.clientID, methodOf(class), toolOf(class), "allow", "")
	}

	// Notifications get no response.
	if class.Kind == policy.RPCNotification {
		if sess != nil {
			_ = sess.bridge.notify(class.Method, envelope.Params)
		} else {
			s.forwardOnce(r.Context(), au, func(b *bridge) {
				if b != nil {
					_ = b.notify(class.Method, envelope.Params)
				}
			})
		}
		w.WriteHeader(http.StatusAccepted)
		return
	}

	resp, ferr := s.forward(r.Context(), au, sess, methodOf(class), class.ID, envelope.Params)
	if ferr != nil {
		// A settled paid call whose backend then failed: record a compensating
		// x402/backend-error against the same evidence so the tamper-evident
		// ledger never implies the paid call was served. The payment is spent
		// (single-use); recovery is a settlement matter, not a silent re-serve.
		if paid != nil {
			_ = s.auditPayment(au.clientID, class.Tool, class.ID, "x402/backend-error", "deny", "paid call not served: backend unavailable after settlement", paid.evidence)
		}
		s.writeJSONRPC(w, jsonRPCErrorResponse(class.ID, -32603, "backend unavailable: "+ferr.Error()))
		return
	}
	if paid != nil {
		// A settled paid call whose backend returned an error result (JSON-RPC
		// error or a tools/call result with isError:true) was still charged. Record
		// a compensating x402/tool-error so the ledger reflects the true outcome.
		if toolCallErrored(resp) {
			_ = s.auditPayment(au.clientID, class.Tool, class.ID, "x402/tool-error", "deny", "paid call: backend returned an error result", paid.evidence)
		}
		// Cache the served response so a lost-response retry by the same client and
		// request replays it (idempotent) instead of being denied as a replay.
		s.payment.complete(paid.refHash, resp)
	}
	if sess != nil {
		w.Header().Set(headerSessionID, sess.id)
	}
	s.writeJSONRPC(w, resp)
}

// toolCallErrored reports whether a JSON-RPC response is an error response or a
// tools/call result marked isError:true — the outcomes a paid call should record
// as not-successfully-served.
func toolCallErrored(resp []byte) bool {
	var env struct {
		Error  json.RawMessage `json:"error"`
		Result struct {
			IsError bool `json:"isError"`
		} `json:"result"`
	}
	if err := json.Unmarshal(resp, &env); err != nil {
		return false
	}
	if len(env.Error) > 0 && string(env.Error) != "null" {
		return true
	}
	return env.Result.IsError
}

// enforceToolCall applies the capability + policy double-gate and audits the
// decision. It returns allowed=false with a JSON-RPC error body on denial.
func (s *Server) enforceToolCall(au authed, class policy.RPCClass) (bool, []byte) {
	id := oauthIdentity(au.clientID)
	// 1) Capability gate: the minted Ed25519 grant must cover this tool for this
	// identity and backend. Re-verified from the token's stored capability, so a
	// tampered on-disk record cannot widen the grant.
	if _, err := s.verify.Verify(au.access.Capability, id, s.cfg.Backend.Name, class.Tool); err != nil {
		_ = s.auditDecision(au.clientID, "tools/call", class.Tool, "deny", "capability: "+err.Error())
		return false, jsonRPCErrorResponse(class.ID, -32001, "tool not permitted by capability: "+err.Error())
	}
	// 2) Policy gate: deny-by-default engine keyed on the synthetic identity.
	dec := s.engine.DecideToolCallBound(id, id, s.cfg.Backend.Name, class.Tool, class.Args, nil)
	auditErr := s.auditDecision(au.clientID, "tools/call", class.Tool, outcomeString(dec.Outcome), dec.Reason)
	switch dec.Outcome {
	case policy.OutcomeAllow:
		if auditErr != nil {
			// Fail closed: an unrecorded allow is denied.
			return false, jsonRPCErrorResponse(class.ID, -32002, "tool blocked: audit sink unavailable (fail-closed)")
		}
		return true, nil
	case policy.OutcomeCosign:
		return false, jsonRPCErrorResponse(class.ID, -32003, "tool requires a human co-sign: "+dec.Reason)
	default:
		reason := dec.Reason
		if reason == "" {
			reason = "denied by policy"
		}
		return false, jsonRPCErrorResponse(class.ID, -32004, "tool blocked: "+reason)
	}
}

// forward relays a request through the session's bridge, or through a one-shot
// bridge when sessions are disabled.
func (s *Server) forward(ctx context.Context, au authed, sess *mcpSession, method string, id, params json.RawMessage) ([]byte, error) {
	if sess != nil {
		return sess.bridge.forward(ctx, method, id, params)
	}
	var out []byte
	var ferr error
	s.forwardOnce(ctx, au, func(b *bridge) {
		if b == nil {
			// The backend dial failed (forwardOnce passes nil). Surface it as a
			// forward error rather than dereferencing a nil bridge.
			ferr = errBackendDialFailed
			return
		}
		out, ferr = b.forward(ctx, method, id, params)
	})
	return out, ferr
}

// errBackendDialFailed is returned when the stateless one-shot bridge cannot be
// dialed (backend unreachable); it surfaces as a JSON-RPC "backend unavailable".
var errBackendDialFailed = errors.New("backend dial failed")

// forwardOnce dials a short-lived bridge, runs fn, and closes it — the stateless
// (sessions-disabled) path. On dial failure fn is invoked with a nil bridge; fn
// MUST nil-check (see forward).
func (s *Server) forwardOnce(ctx context.Context, au authed, fn func(*bridge)) {
	b, err := newBridge(ctx, s.dial)
	if err != nil {
		fn(nil)
		return
	}
	defer b.close()
	fn(b)
}

// resolveSession returns the session a POST belongs to. With sessions disabled
// it returns nil (stateless). An initialize request creates a new session bound
// to the token's client and family; any other request must present a valid,
// owner-and-family-matching Mcp-Session-Id.
func (s *Server) resolveSession(w http.ResponseWriter, r *http.Request, au authed, class policy.RPCClass) (*mcpSession, int, string) {
	if !s.cfg.OAuth.SessionsEnabled() {
		return nil, 0, ""
	}
	if class.Method == "initialize" {
		br, err := newBridge(r.Context(), s.dial)
		if err != nil {
			return nil, http.StatusBadGateway, "backend dial failed"
		}
		sess, ok := s.sessions.create(au.clientID, au.access.FamilyID, br)
		if !ok {
			br.close()
			return nil, http.StatusTooManyRequests, "session limit reached for this client"
		}
		return sess, 0, ""
	}
	id := r.Header.Get(headerSessionID)
	if id == "" {
		return nil, http.StatusBadRequest, "missing " + headerSessionID
	}
	sess := s.sessions.get(id, au.clientID)
	if sess == nil || sess.familyID != au.access.FamilyID {
		return nil, http.StatusNotFound, "unknown or unauthorized session"
	}
	return sess, 0, ""
}

// mcpGet opens the session's Server-Sent Events stream, relaying backend
// notifications to the client. The stream is cut when the access token expires
// (no authorization outlives its token) and closed if the per-session buffer
// overflows (bounded, never unbounded).
func (s *Server) mcpGet(w http.ResponseWriter, r *http.Request) {
	au, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	if !s.cfg.OAuth.SessionsEnabled() {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	id := r.Header.Get(headerSessionID)
	if id == "" {
		http.Error(w, "missing "+headerSessionID, http.StatusBadRequest)
		return
	}
	sess := s.sessions.get(id, au.clientID)
	if sess == nil || sess.familyID != au.access.FamilyID {
		http.NotFound(w, r)
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	ch := sess.attachStream(s.cfg.Limits.MaxSSEBufferMsgs)
	defer sess.detachStream()

	// Cut the stream when the access token expires (computed against the injected
	// clock so tests with a fixed clock behave deterministically).
	cutIn := au.access.ExpiresAt.Sub(s.now())
	if cutIn <= 0 {
		return
	}
	expiry := time.NewTimer(cutIn)
	defer expiry.Stop()
	keepalive := time.NewTicker(25 * time.Second)
	defer keepalive.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-expiry.C:
			_, _ = io.WriteString(w, "event: auth\ndata: {\"error\":\"token_expired\"}\n\n")
			flusher.Flush()
			return
		case <-keepalive.C:
			_, _ = io.WriteString(w, ": keepalive\n\n")
			flusher.Flush()
		case ev, ok := <-ch:
			if !ok {
				return // session ended or stream replaced
			}
			_, _ = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", ev.event, ev.data)
			flusher.Flush()
		}
	}
}

func methodOf(c policy.RPCClass) string {
	if c.Kind == policy.RPCToolCall {
		return "tools/call"
	}
	return c.Method
}

func toolOf(c policy.RPCClass) string {
	if c.Kind == policy.RPCToolCall {
		return c.Tool
	}
	return ""
}

func outcomeString(o policy.Outcome) string {
	switch o {
	case policy.OutcomeAllow:
		return "allow"
	case policy.OutcomeCosign:
		return "cosign"
	default:
		return "deny"
	}
}

// auditDecision records one MCP decision under the client's synthetic identity.
func (s *Server) auditDecision(clientID, method, tool, decision, reason string) error {
	return s.audit.append(policy.AuditRecord{
		Backend:  "edge:" + s.cfg.Backend.Name,
		Peer:     oauthIdentity(clientID),
		PeerKey:  oauthIdentity(clientID),
		Method:   method,
		Tool:     tool,
		Decision: decision,
		Reason:   reason,
		Rule:     -1,
	})
}

// writeJSONRPC writes a raw JSON-RPC response object as the HTTP body.
func (s *Server) writeJSONRPC(w http.ResponseWriter, body []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(body)
}

// mcpDelete ends a session.
func (s *Server) mcpDelete(w http.ResponseWriter, r *http.Request) {
	au, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	id := r.Header.Get(headerSessionID)
	if id == "" {
		http.Error(w, "missing "+headerSessionID, http.StatusBadRequest)
		return
	}
	if s.sessions.get(id, au.clientID) == nil {
		http.NotFound(w, r)
		return
	}
	s.sessions.delete(id)
	w.WriteHeader(http.StatusNoContent)
}
