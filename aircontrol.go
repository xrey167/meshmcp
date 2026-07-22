package main

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/xrey167/meshmcp/policy"
	"github.com/xrey167/meshmcp/session"
)

// The Air control endpoint exposes a gateway's live resumable sessions over the
// mesh: list them (GET /v1/sessions) and steer one (POST /v1/steer). It listens
// only on the mesh, resolves the caller's WireGuard identity, gates on an ACL,
// and audits every steer — so it is just another governed mesh client, not a
// backdoor. The steer itself is the line-safe server->client notification P2
// shipped (session.Server.Steer).

// AirSession is one live session in the control endpoint's view: the session
// layer's SessionInfo enriched with the backend it belongs to.
type AirSession struct {
	Backend string `json:"backend"`
	ID      string `json:"id"`
	Peer    string `json:"peer"`
	AgeSec  int    `json:"age_sec"`
}

// airController is the gateway capability the HTTP handler needs, injectable so
// the handler is testable with a fake (mirrors approvalsHandler's approver). Both
// methods take the resolved caller identity so the controller can enforce the
// *target backend's own* ACL — the control endpoint's global Allow gates who may
// reach the endpoint at all, but it must not let a caller list or steer sessions
// on a backend that backend's own allow list would deny.
type airController interface {
	sessions(pubKey, fqdn string) []AirSession
	steer(pubKey, fqdn, backend, id, method string, params any) error
}

// airSteerMethods is the allowlist of server->client notification methods a
// caller may drive through /v1/steer. The CLI (air steer) and the served page
// both send notifications/air/steer; anything else is rejected before dispatch so
// the endpoint can't be used to inject arbitrary server->client JSON-RPC methods.
var airSteerMethods = map[string]bool{
	"notifications/air/steer": true,
}

// airControlHandler builds the control surface. identify resolves the caller's
// (pubkey, fqdn); allow gates them; audit records accepted steers.
func airControlHandler(c airController, identify func(*http.Request) (pubkey, fqdn string), allow acl, audit func(rec airSteerAudit)) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/v1/sessions", func(w http.ResponseWriter, r *http.Request) {
		pubKey, fqdn := identify(r)
		if !allow.allows(pubKey, fqdn) {
			if audit != nil {
				audit(airSteerAudit{Peer: fqdnOr(fqdn), PeerKey: pubKey, Method: "air/sessions", OK: false})
			}
			http.Error(w, "not permitted", http.StatusForbidden)
			return
		}
		list := c.sessions(pubKey, fqdn)
		if list == nil {
			list = []AirSession{}
		}
		if audit != nil {
			ob, obKey := onBehalfOf(r, allow, pubKey, fqdn)
			audit(airSteerAudit{Peer: fqdnOr(fqdn), PeerKey: pubKey, OnBehalf: ob, OnBehalfKey: obKey, Method: "air/sessions", OK: true})
		}
		writeJSONResp(w, http.StatusOK, map[string]any{"sessions": list, "you": fqdnOr(fqdn)})
	})

	mux.HandleFunc("/v1/steer", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		pubKey, fqdn := identify(r)
		if !allow.allows(pubKey, fqdn) {
			if audit != nil {
				audit(airSteerAudit{Peer: fqdnOr(fqdn), PeerKey: pubKey, Method: "air/steer", OK: false})
			}
			http.Error(w, "not permitted", http.StatusForbidden)
			return
		}
		var body struct {
			Backend string          `json:"backend"`
			ID      string          `json:"id"`
			Method  string          `json:"method"`
			Params  json.RawMessage `json:"params"`
		}
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body) != nil || body.Backend == "" || body.ID == "" || body.Method == "" {
			http.Error(w, "backend, id and method are required", http.StatusBadRequest)
			return
		}
		// A trusted (ACL-allowed) proxy — the served Air page — may attest the
		// browser identity it resolved from the mesh, so receipts show the human
		// who clicked, not the relay. Relay-attested, not cryptographically bound.
		onBehalf, onBehalfKey := onBehalfOf(r, allow, pubKey, fqdn)
		if !airSteerMethods[body.Method] {
			if audit != nil {
				audit(airSteerAudit{Backend: body.Backend, Peer: fqdnOr(fqdn), PeerKey: pubKey, OnBehalf: onBehalf, OnBehalfKey: onBehalfKey, Session: body.ID, Method: body.Method, OK: false})
			}
			http.Error(w, "method not permitted", http.StatusBadRequest)
			return
		}
		var params any
		if len(body.Params) > 0 {
			params = body.Params
		}
		err := c.steer(pubKey, fqdn, body.Backend, body.ID, body.Method, params)
		if audit != nil {
			audit(airSteerAudit{Backend: body.Backend, Peer: fqdnOr(fqdn), PeerKey: pubKey, OnBehalf: onBehalf, OnBehalfKey: onBehalfKey, Session: body.ID, Method: body.Method, OK: err == nil})
		}
		switch {
		case err == nil:
			writeJSONResp(w, http.StatusOK, map[string]any{"status": "steered", "backend": body.Backend, "id": body.ID, "by": actingIdentity(onBehalf, fqdn)})
		case err == session.ErrNoSession || err == errNoBackend:
			http.Error(w, err.Error(), http.StatusNotFound)
		case err == errBackendForbidden:
			http.Error(w, err.Error(), http.StatusForbidden)
		default:
			http.Error(w, err.Error(), http.StatusBadRequest)
		}
	})

	return mux
}

// onBehalfOf returns the browser identity (FQDN and, when supplied, WireGuard
// key) a trusted proxy attests via the X-Air-On-Behalf / X-Air-On-Behalf-Key
// headers. It is honoured only when the *connecting* peer (the proxy) is itself
// ACL-allowed, so an ordinary caller can't spoof attribution by setting the
// headers. Empty when absent or unattested; the key is never honoured without
// the FQDN.
func onBehalfOf(r *http.Request, allow acl, proxyKey, proxyFQDN string) (fqdn, key string) {
	ob := r.Header.Get("X-Air-On-Behalf")
	if ob == "" || !allow.allows(proxyKey, proxyFQDN) {
		return "", ""
	}
	return ob, r.Header.Get("X-Air-On-Behalf-Key")
}

// actingIdentity is who the audit/receipt attributes the steer to: the attested
// browser identity when present, else the connecting peer.
func actingIdentity(onBehalf, fqdn string) string {
	if onBehalf != "" {
		return onBehalf
	}
	return fqdnOr(fqdn)
}

func fqdnOr(fqdn string) string {
	if fqdn == "" {
		return "unknown-mesh-peer"
	}
	return fqdn
}

// errNoBackend is returned by the gateway controller when the named backend has
// no resumable session server.
var errNoBackend = &noBackendError{}

type noBackendError struct{}

func (*noBackendError) Error() string { return "no such steerable backend" }

// errBackendForbidden is returned when the caller is allowed on the control
// endpoint but the *target backend's own* ACL denies them — the control endpoint
// must not become a way around a backend's allow list.
var errBackendForbidden = &backendForbiddenError{}

type backendForbiddenError struct{}

func (*backendForbiddenError) Error() string { return "not permitted for this backend" }

// gatewayAirControl is the live implementation over cmdServe's session servers.
// acls carries each backend's own allow list so list/steer are re-checked against
// the target backend, not just the global control-endpoint Allow. A backend with
// no entry falls back to a permissive ACL (mirrors an empty Allow = any peer).
type gatewayAirControl struct {
	servers map[string]*session.Server
	acls    map[string]acl
	mu      *sync.Mutex
}

func (g *gatewayAirControl) backendAllows(backend, pubKey, fqdn string) bool {
	a, ok := g.acls[backend]
	if !ok {
		a = newACL(nil)
	}
	return a.allows(pubKey, fqdn)
}

func (g *gatewayAirControl) sessions(pubKey, fqdn string) []AirSession {
	g.mu.Lock()
	defer g.mu.Unlock()
	var out []AirSession
	for name, srv := range g.servers {
		if !g.backendAllows(name, pubKey, fqdn) {
			continue
		}
		for _, s := range srv.Sessions() {
			out = append(out, AirSession{Backend: name, ID: s.ID, Peer: s.Peer, AgeSec: int(s.Age / time.Second)})
		}
	}
	return out
}

func (g *gatewayAirControl) steer(pubKey, fqdn, backend, id, method string, params any) error {
	g.mu.Lock()
	srv, ok := g.servers[backend]
	g.mu.Unlock()
	if !ok {
		return errNoBackend
	}
	if !g.backendAllows(backend, pubKey, fqdn) {
		return errBackendForbidden
	}
	return srv.Steer(id, method, params)
}

// airSteerAudit is one control-endpoint action (a steer or a sessions read),
// recorded in the shared ledger. OnBehalf/OnBehalfKey are the browser identity
// a trusted proxy (the served Air page) attests; empty for a direct caller.
type airSteerAudit struct {
	Backend, Peer, PeerKey, OnBehalf, OnBehalfKey, Session, Method string
	OK                                                             bool
}

// airAuditFunc adapts the shared audit ledger to the control handler. It records
// who steered which session on which backend; nil audit is a no-op.
func airAuditFunc(audit *policy.AuditLog) func(airSteerAudit) {
	if audit == nil {
		return nil
	}
	return func(rec airSteerAudit) {
		decision := "allow"
		if !rec.OK {
			decision = "deny"
		}
		// Attribute the human when a trusted proxy attested them: the receipt's
		// Peer becomes the browser identity and Reason records the relay it
		// arrived through so the chain of custody stays visible. PeerKey ALWAYS
		// holds the transport-VERIFIED key of the connecting peer (the relay) —
		// never the relay-asserted, unverified browser key, which would put an
		// unproven value where the ledger's verified keys live. The attested
		// browser key is recorded in Reason, clearly labelled as a relay claim.
		base := "air/steer"
		if rec.Method == "air/sessions" {
			base = "air/sessions"
		}
		peer, reason := rec.Peer, base
		if rec.OnBehalf != "" {
			peer = rec.OnBehalf
			reason = base + " via " + rec.Peer + " (relay-attested)"
			if rec.OnBehalfKey != "" {
				reason += "; attested-key=" + rec.OnBehalfKey
			}
		}
		audit.Append(policy.AuditRecord{
			Backend:  rec.Backend,
			Peer:     peer,
			PeerKey:  rec.PeerKey, // verified connecting-peer key, never the attested one
			Method:   rec.Method,
			Tool:     rec.Session,
			Decision: decision,
			Reason:   reason,
			Rule:     -1,
		})
	}
}
