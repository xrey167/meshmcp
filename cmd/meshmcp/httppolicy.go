package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/xrey167/meshmcp/policy"
	"github.com/xrey167/meshmcp/secrets"
)

// httpEnforcer applies the same identity-keyed policy engine to a Streamable-HTTP
// backend that the stdio Filter applies to a stdio backend (F16). It parses the
// JSON-RPC in a POST body, authorizes tools/call by the caller's mesh identity,
// audits the decision, and denies inline — so the firewall is no longer
// stdio-only. Per-session taint labels (keyed by the transport-proven peer key
// plus Mcp-Session-Id), secret injection with per-peer response redaction, and
// signed-capability upgrades are enforced here too, at parity with the stdio
// path. Router delegation, DLP, and shadow policies remain stdio-only and are
// refused for HTTP/remote backends at config load — never silently skipped.
type httpEnforcer struct {
	eng     *policy.Engine
	audit   *policy.AuditLog
	pending *policy.FilePending
	backend string
	// trustDomain is the gateway's LOCAL SPIFFE trust domain (Feature A); when
	// set, records carry the additive peer_spiffe_id label, keeping HTTP/remote
	// backends at parity with the stdio filter. Empty = no label.
	trustDomain string

	// capVerifier verifies signed capability tokens (pinned authority keys);
	// capRequired makes the backend a capability-only surface.
	capVerifier *policy.CapabilityVerifier
	capRequired bool

	// secrets is the credential broker: {{secret:NAME}} references in an
	// authorized tools/call are resolved by identity AFTER audit, so the value
	// reaches only the backend. Injected values feed the per-peer redactor.
	secrets policy.SecretResolver
	// grantsUseLabels is true when any secret grant carries block_labels —
	// label state must then be tracked (and a session id required) even if the
	// policy itself has no label rules.
	grantsUseLabels bool

	// sessions holds per-(peerKey, Mcp-Session-Id) taint labels and per-peer
	// response redactors. Always constructed by newHTTPEnforcer so a SIGHUP
	// that hot-swaps label rules into the policy finds it ready.
	sessions *httpSessionStore
}

// newHTTPEnforcer builds the enforcer for an HTTP/remote backend that declares
// a policy or capabilities. audit may be the gateway-wide shared ledger or a
// per-backend sink. Security wiring failures (unloadable approval key,
// uncreatable revocation store, unusable secrets store) are returned as an
// error at startup, matching the stdio path — never a silent downgrade.
func newHTTPEnforcer(b *Backend, audit *policy.AuditLog) (*httpEnforcer, error) {
	var cosign policy.CosignStore
	var pending *policy.FilePending
	ttl := time.Duration(b.CosignTTLSeconds) * time.Second
	if b.CosignStore != "" {
		cosign = &policy.FileCosign{Dir: b.CosignStore, TTL: ttl}
		pending = &policy.FilePending{Dir: b.CosignStore, TTL: ttl}
	}
	pol := b.Policy
	if pol == nil {
		// Capabilities need the engine path even without an explicit policy (a
		// capability upgrades a policy-DEFAULT deny), so synthesize the same
		// deny-by-default engine the stdio path uses.
		pol = &policy.Policy{DefaultAllow: false}
	}
	eng := policy.NewEngine(pol, func() time.Time { return time.Now() }, cosign)
	if len(b.groups) > 0 {
		eng.SetGroupResolver(policy.StaticGroups(b.groups))
	}
	// Request-bound approvals (Phase 3), at parity with the stdio path
	// (backendFactory): with a shared approval signing key configured, a
	// require_cosign call is released only by a signed, single-use token bound to
	// its exact arguments — and a configured-but-unreadable key is a hard startup
	// error, never a silent fall-back to the ambient (peer, tool) grant.
	if b.ApprovalSigningKey != "" {
		signer, err := policy.LoadSigner(b.ApprovalSigningKey)
		if err != nil {
			return nil, fmt.Errorf("backend %q: approval_signing_key %s: %w", b.Name, b.ApprovalSigningKey, err)
		}
		eng.SetRequestApprovals(policy.NewFileApprovalStore(b.CosignStore, ttl, signer))
		log.Printf("backend %q: request-bound approvals enabled over HTTP (approver key %s…); ambient co-sign no longer releases held calls", b.Name, signer.PubKeyHex()[:16])
	}
	e := &httpEnforcer{eng: eng, audit: audit, pending: pending, backend: b.Name,
		trustDomain: b.trustDomain, sessions: newHTTPSessionStore(nil)}
	if b.Capabilities != nil {
		v, err := policy.NewCapabilityVerifier(b.Capabilities.TrustedPublicKeys, func() time.Time { return time.Now() })
		if err != nil {
			return nil, fmt.Errorf("backend %q: capabilities: %w", b.Name, err)
		}
		// Single-use (jti) replay cache, shared across the backend's HTTP
		// connections so a one-shot grant is one-shot per backend — parity with the
		// stdio path (backendFactory), so a SingleUse capability is enforced
		// identically on both transports (without it, a SingleUse token would fail
		// closed here and could never authorize over HTTP). Per-process only: a
		// multi-gateway HA deployment needs a shared NonceStore.
		v = v.WithReplayCache(policy.NewMemNonceStore())
		if b.Capabilities.RevocationStore != "" {
			// Create the store at startup so IsRevoked can later fail closed on a
			// vanished/unavailable store (stdio precedent).
			rev, err := policy.NewFileRevocation(b.Capabilities.RevocationStore)
			if err != nil {
				return nil, fmt.Errorf("backend %q: capability revocation store %s: %w", b.Name, b.Capabilities.RevocationStore, err)
			}
			v = v.WithRevocation(rev.IsRevoked).WithSubjectRevocation(rev.IsSubjectRevoked)
			log.Printf("backend %q: capability revocation store: %s", b.Name, b.Capabilities.RevocationStore)
		}
		e.capVerifier = v
		e.capRequired = b.Capabilities.Required
	}
	if b.Secrets != nil {
		store, err := secretStore(b.Secrets)
		if err != nil {
			return nil, fmt.Errorf("backend %q: secrets store: %w", b.Name, err)
		}
		e.secrets = secrets.New(store, b.Secrets.Grants, audit)
		for _, g := range b.Secrets.Grants {
			if len(g.BlockLabels) > 0 {
				e.grantsUseLabels = true
			}
		}
	}
	return e, nil
}

// sessionsRequired reports whether per-session label state must be tracked for
// a tools/call: true when the active policy (SIGHUP-hot-swappable, so read per
// request) has any emit/block label rule, or any secret grant blocks on labels.
// When true, a governed tools/call without a valid Mcp-Session-Id is DENIED —
// an unenforceable label rule must refuse, never silently skip.
func (e *httpEnforcer) sessionsRequired() bool {
	if e.sessions == nil {
		return false
	}
	return e.grantsUseLabels || e.eng.Policy().UsesLabels()
}

// redactsResponses reports whether this enforcer needs the response-rewrite
// seam (a secrets broker is configured, so injected values must be scrubbed
// from backend responses).
func (e *httpEnforcer) redactsResponses() bool { return e != nil && e.secrets != nil }

// responseRedactor returns the peer's redactor if any secret was ever injected
// for it (nil otherwise; the response path never creates one).
func (e *httpEnforcer) responseRedactor(peerKey string) *policy.Redactor {
	if e == nil || e.sessions == nil {
		return nil
	}
	return e.sessions.lookupRedactor(peerKey)
}

// setBody replaces the request body the proxy (or remote client) will forward.
// net/http writes Content-Length from r.ContentLength, so the stale header is
// dropped rather than trusted.
func setBody(r *http.Request, body []byte) {
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	r.Header.Del("Content-Length")
}

// decide authorizes the request. It returns ok=true (and possibly a rewritten
// body to forward) when the call may proceed, or ok=false with a status code and
// a JSON-RPC error body to return without proxying. Non-tools/call requests and
// non-JSON bodies pass through (only tools/call is governed, mirroring the stdio
// filter's method handling), though a presented capability token is stripped
// from every governed body so it never reaches the backend.
func (e *httpEnforcer) decide(peer, peerKey string, r *http.Request) (ok bool, status int, denialBody []byte) {
	if r.Method == http.MethodDelete {
		// Spec session teardown: drop the session's label state and pass the
		// DELETE through unchanged.
		if sid := r.Header.Get(mcpSessionHeader); e.sessions != nil && validSessionID(sid) {
			e.sessions.drop(peerKey, sid)
		}
		return true, 0, nil
	}
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
	setBody(r, body)

	// Classify + validate through the SHARED classifier, so an HTTP backend
	// makes the SAME decision as the stdio filter for the same request: id-less
	// / null-id / empty-name tools/call, duplicate keys, and batches are all
	// rejected identically (Phase 7 conformance). Classification reads the
	// ORIGINAL bytes (pre-strip), matching stdio.
	class := policy.ClassifyRPC(body)

	// Strip any presented capability token from EVERY governed body so it never
	// reaches the backend, trace, or audit — including pass-through method and
	// notification bodies, which would otherwise leak a session-riding token
	// (stdio strips on all governed kinds; HTTP must too).
	var capToken string
	if e.capVerifier != nil {
		switch class.Kind {
		case policy.RPCToolCall, policy.RPCNotification, policy.RPCMethod:
			capToken, body = policy.StripCapabilityToken(body)
			setBody(r, body)
		}
	}

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

	// RPCToolCall. Resolve per-session label state first: when the policy (or a
	// secret grant) uses labels, a tools/call MUST carry a valid Mcp-Session-Id
	// — a client omitting the header would otherwise evade accumulated taint,
	// so the unenforceable call is denied, never silently un-labeled. These
	// denials are audited like every other decision (RuleID -1).
	denyTool := func(reason string) (bool, int, []byte) {
		_ = e.audit.Append(e.record("tools/call", class.Tool, string(class.ID),
			policy.Decision{RuleID: -1, Outcome: policy.OutcomeDeny, Reason: reason}, peer, peerKey))
		return false, http.StatusOK, jsonRPCError(class.ID, fmt.Sprintf("tool %q blocked: %s", class.Tool, reason))
	}
	sid := r.Header.Get(mcpSessionHeader)
	trackSession := e.sessionsRequired()
	var labels map[string]bool
	if trackSession {
		if peerKey == "" {
			return denyTool("this backend's policy tracks session labels, which need a transport-proven peer identity")
		}
		if !validSessionID(sid) {
			return denyTool("this backend's policy tracks session labels; tools/call must carry a valid Mcp-Session-Id header")
		}
		if ok, reason := e.sessions.ensure(peerKey, sid); !ok {
			return denyTool(reason)
		}
		labels = e.sessions.snapshot(peerKey, sid)
	}

	dec := e.eng.DecideToolCallBound(peer, peerKey, e.backend, class.Tool, class.Args, labels)
	var pendingCap *policy.CapabilityClaims
	if e.capVerifier != nil {
		dec, pendingCap = policy.FoldCapability(dec, e.capVerifier, e.capRequired, capToken, peerKey, e.backend, class.Tool)
	}
	// Consume a load-bearing single-use grant only now that the final outcome is
	// known — HTTP has no delegation/hook stage, so the fold's outcome is final —
	// so a co-sign hold or a policy deny never burns it (parity with the stdio
	// filter's deferred Consume). A replayed jti turns the allow into a deny, and
	// consumption runs BEFORE the audit append so the record reflects the true
	// verdict; the grant is spent before secrets are injected.
	if pendingCap != nil && dec.Outcome == policy.OutcomeAllow {
		if err := e.capVerifier.Consume(*pendingCap); err != nil {
			dec = policy.Decision{Outcome: policy.OutcomeDeny, RuleID: dec.RuleID, Reason: "invalid capability: " + err.Error()}
		}
	}
	auditErr := e.audit.Append(e.record("tools/call", class.Tool, string(class.ID), dec, peer, peerKey))
	switch dec.Outcome {
	case policy.OutcomeAllow:
		// Audit is a control: if the record cannot be written and the log is
		// fail-closed, deny rather than proxy an unrecorded call (parity with the
		// stdio filter).
		if auditErr != nil && e.audit.FailClosed() {
			return false, http.StatusOK, jsonRPCError(class.ID, fmt.Sprintf("tool %q blocked: audit sink unavailable (fail-closed)", class.Tool))
		}
		// Record labels this call contributed BEFORE resolving secrets, so the
		// injection decision sees the freshest label set (stdio order).
		if trackSession {
			e.sessions.addLabels(peerKey, sid, dec.AddLabels)
			labels = e.sessions.snapshot(peerKey, sid)
		}
		// Inject secrets last — after audit — so the resolved value reaches only
		// the backend, never the audit. A denied injection (ungranted / tainted /
		// unavailable) blocks the call before the backend is contacted.
		if e.secrets != nil {
			resolved, injected, rok, reason := e.secrets.Resolve(policy.Caller{
				Backend: e.backend, Peer: peer, PeerKey: peerKey,
				SpiffeID: policy.SpiffeID(e.trustDomain, peerKey),
			}, class.Tool, body, labels)
			if !rok {
				return false, http.StatusOK, jsonRPCError(class.ID, fmt.Sprintf("tool %q blocked: %s", class.Tool, reason))
			}
			if len(injected) > 0 {
				// Remember injected values so the response path can scrub them.
				// A value beyond the redactor's capacity could NOT be scrubbed,
				// so the injection is refused (fail closed), not forwarded.
				// Redactors are keyed by the transport-proven peer key — per-peer
				// scoping is what prevents a cross-peer match oracle (see
				// httpSessionStore). A key-less peer would collapse onto one
				// shared redactor, so an injection that cannot be per-peer scoped
				// is refused the same way.
				if peerKey == "" {
					return denyTool("secret injection needs a transport-proven peer identity (injected values are scrubbed from responses per peer)")
				}
				red := e.sessions.redactorFor(peerKey)
				if red.Len()+len(injected) > e.sessions.redCap {
					return denyTool("secret-redaction capacity for this peer is exhausted (injected value could not be scrubbed from responses)")
				}
				red.Add(injected...)
			}
			setBody(r, resolved)
		}
		return true, 0, nil
	case policy.OutcomeCosign:
		if e.pending != nil {
			// Carry the argument + policy binding so an approver can mint a
			// request-bound approval for exactly these arguments under this
			// policy (parity with the stdio filter's pending record).
			_ = e.pending.Record(policy.Pending{
				Peer: peer, PeerKey: peerKey, Backend: e.backend, Tool: class.Tool, RPCID: string(class.ID),
				ArgsHash: policy.CanonicalArgsHash(class.Args), PolicyHash: e.eng.PolicyHash(),
			})
		}
		return false, http.StatusOK, jsonRPCError(class.ID, fmt.Sprintf("tool %q requires a human co-sign on the mesh: %s", class.Tool, dec.Reason))
	default:
		reason := dec.Reason
		if reason == "" {
			reason = "denied by mesh policy"
		}
		return false, http.StatusOK, policy.DenialBody(class.ID, fmt.Sprintf("tool %q blocked for peer %s: %s", class.Tool, peer, reason), dec.RetryAfter)
	}
}

func (e *httpEnforcer) record(method, tool, rpcID string, dec policy.Decision, peer, peerKey string) policy.AuditRecord {
	return policy.AuditRecord{
		Backend: e.backend, Peer: peer, PeerKey: peerKey,
		Method: method, Tool: tool, RPCID: rpcID,
		Decision: dec.Outcome.String(), Reason: dec.Reason, Rule: dec.RuleID, Cost: dec.Cost,
		PeerSpiffeID: policy.SpiffeID(e.trustDomain, peerKey),
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
