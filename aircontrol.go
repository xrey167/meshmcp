package main

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"meshmcp/policy"
	"meshmcp/session"
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
// the handler is testable with a fake (mirrors approvalsHandler's approver).
type airController interface {
	sessions() []AirSession
	steer(backend, id, method string, params any) error
}

// airControlHandler builds the control surface. identify resolves the caller's
// (pubkey, fqdn); allow gates them; audit records accepted steers.
func airControlHandler(c airController, identify func(*http.Request) (pubkey, fqdn string), allow acl, audit func(rec airSteerAudit)) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/v1/sessions", func(w http.ResponseWriter, r *http.Request) {
		pubKey, fqdn := identify(r)
		if !allow.allows(pubKey, fqdn) {
			http.Error(w, "not permitted", http.StatusForbidden)
			return
		}
		list := c.sessions()
		if list == nil {
			list = []AirSession{}
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
		var params any
		if len(body.Params) > 0 {
			params = body.Params
		}
		err := c.steer(body.Backend, body.ID, body.Method, params)
		if audit != nil {
			audit(airSteerAudit{Backend: body.Backend, Peer: fqdnOr(fqdn), PeerKey: pubKey, Session: body.ID, Method: body.Method, OK: err == nil})
		}
		switch {
		case err == nil:
			writeJSONResp(w, http.StatusOK, map[string]any{"status": "steered", "backend": body.Backend, "id": body.ID, "by": fqdnOr(fqdn)})
		case err == session.ErrNoSession || err == errNoBackend:
			http.Error(w, err.Error(), http.StatusNotFound)
		default:
			http.Error(w, err.Error(), http.StatusBadRequest)
		}
	})

	return mux
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

// gatewayAirControl is the live implementation over cmdServe's session servers.
type gatewayAirControl struct {
	servers map[string]*session.Server
	mu      *sync.Mutex
}

func (g *gatewayAirControl) sessions() []AirSession {
	g.mu.Lock()
	defer g.mu.Unlock()
	var out []AirSession
	for name, srv := range g.servers {
		for _, s := range srv.Sessions() {
			out = append(out, AirSession{Backend: name, ID: s.ID, Peer: s.Peer, AgeSec: int(s.Age / time.Second)})
		}
	}
	return out
}

func (g *gatewayAirControl) steer(backend, id, method string, params any) error {
	g.mu.Lock()
	srv, ok := g.servers[backend]
	g.mu.Unlock()
	if !ok {
		return errNoBackend
	}
	return srv.Steer(id, method, params)
}

// airSteerAudit is one control-endpoint steer, recorded in the shared ledger.
type airSteerAudit struct {
	Backend, Peer, PeerKey, Session, Method string
	OK                                      bool
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
		audit.Append(policy.AuditRecord{
			Backend:  rec.Backend,
			Peer:     rec.Peer,
			PeerKey:  rec.PeerKey,
			Method:   rec.Method,
			Tool:     rec.Session,
			Decision: decision,
			Reason:   "air/steer",
			Rule:     -1,
		})
	}
}
