package main

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/xrey167/meshmcp/air"
	"github.com/xrey167/meshmcp/policy"
	"github.com/xrey167/meshmcp/session"
)

// The Air control endpoint exposes a gateway's live resumable sessions over the
// mesh: list them (GET /v1/sessions) and steer one (POST /v1/steer). It listens
// only on the mesh, resolves the caller's WireGuard identity, gates on an ACL,
// and audits every steer — so it is just another governed mesh client, not a
// backdoor. The steer itself is the line-safe server->client notification P2
// shipped (session.Server.Steer).

// airController is the gateway capability the HTTP handler needs, injectable so
// the handler is testable with a fake (mirrors approvalsHandler's approver). Both
// methods take the resolved caller identity so the controller can enforce the
// *target backend's own* ACL — the control endpoint's global Allow gates who may
// reach the endpoint at all, but it must not let a caller list or steer sessions
// on a backend that backend's own allow list would deny.
type airController interface {
	sessions(pubKey, fqdn string) []AirSession
	steer(pubKey, fqdn, backend, id, method string, params any) error
	catalog(pubKey, fqdn string) AirCatalog
	nearby(now time.Time) []air.Presence
	announce(pubKey, fqdn, observedIP string, a air.Announcement, now time.Time) (air.Presence, bool, error)
	leave(pubKey string) bool
}

// airSteerMethods is the allowlist of server->client notification methods a
// caller may drive through /v1/steer. The CLI (air steer) and the served page
// both send notifications/air/steer; anything else is rejected before dispatch so
// the endpoint can't be used to inject arbitrary server->client JSON-RPC methods.
var airSteerMethods = map[string]bool{
	"notifications/air/steer": true,
}

// airControlHandler builds the control surface. identify resolves the caller's
// (pubkey, fqdn); allow gates who may reach the endpoint; onBehalfAllow is the
// SEPARATE, dedicated list of proxy identities (the air-serve relay) permitted
// to attest an X-Air-On-Behalf browser identity — it is NOT the general allow
// list, so an ordinary allowed caller cannot forge attribution, and it fails
// closed when empty (no peer may attest). audit records accepted actions.
func airControlHandler(c airController, identify func(*http.Request) (pubkey, fqdn string), allow, onBehalfAllow acl, audit func(rec airSteerAudit)) http.Handler {
	mux := http.NewServeMux()

	// Discovery: the ARD-style well-known catalog. Unlike list/steer it is NOT
	// gated on the control Allow — any identified mesh peer may discover — but
	// the result is filtered per-caller by each backend's own ACL, and an
	// unidentifiable peer (no key and no FQDN) discovers nothing.
	mux.HandleFunc(airCatalogPath, func(w http.ResponseWriter, r *http.Request) {
		if !getOnly(w, r) {
			return
		}
		pubKey, fqdn := identify(r)
		if pubKey == "" && fqdn == "" {
			if audit != nil {
				audit(airSteerAudit{Peer: fqdnOr(fqdn), PeerKey: pubKey, Method: "air/catalog", OK: false})
			}
			http.Error(w, "unidentified mesh peer", http.StatusForbidden)
			return
		}
		cat := c.catalog(pubKey, fqdn)
		if audit != nil {
			audit(airSteerAudit{Peer: fqdnOr(fqdn), PeerKey: pubKey, Method: "air/catalog", OK: true})
		}
		writeCatalog(w, cat)
	})

	mux.HandleFunc("/v1/sessions", func(w http.ResponseWriter, r *http.Request) {
		if !getOnly(w, r) {
			return
		}
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
			ob, obKey := onBehalfOf(r, onBehalfAllow, pubKey, fqdn)
			audit(airSteerAudit{Peer: fqdnOr(fqdn), PeerKey: pubKey, OnBehalf: ob, OnBehalfKey: obKey, Method: "air/sessions", OK: true})
		}
		writeJSONResp(w, http.StatusOK, map[string]any{"sessions": list, "you": fqdnOr(fqdn)})
	})

	// Presence is Air's ambient ecosystem directory. A caller authors only an
	// Announcement; the controller stamps its verified key/FQDN and the source
	// IP observed on this HTTP connection. On-behalf headers are deliberately
	// ignored for POST/DELETE: a relay may help render a browser's read, but it
	// may never create or remove another identity's card.
	mux.HandleFunc("/v1/presence", func(w http.ResponseWriter, r *http.Request) {
		pubKey, fqdn := identify(r)
		if !allow.allows(pubKey, fqdn) {
			if audit != nil {
				audit(airSteerAudit{Peer: fqdnOr(fqdn), PeerKey: pubKey, Method: presenceMethod(r.Method), OK: false})
			}
			http.Error(w, "not permitted", http.StatusForbidden)
			return
		}

		switch r.Method {
		case http.MethodGet, http.MethodHead:
			cards := c.nearby(time.Now())
			if cards == nil {
				cards = []air.Presence{}
			}
			if audit != nil {
				ob, obKey := onBehalfOf(r, onBehalfAllow, pubKey, fqdn)
				audit(airSteerAudit{Peer: fqdnOr(fqdn), PeerKey: pubKey, OnBehalf: ob, OnBehalfKey: obKey, Method: "air/presence.list", OK: true})
			}
			writeJSONResp(w, http.StatusOK, map[string]any{"presence": cards, "you": fqdnOr(fqdn)})

		case http.MethodPost:
			// A stable card must be owned by a cryptographic key, not merely a
			// name that happened to resolve on the mesh.
			if pubKey == "" {
				if audit != nil {
					audit(airSteerAudit{Peer: fqdnOr(fqdn), Method: "air/presence.announce", OK: false})
				}
				http.Error(w, "presence requires a transport-verified public key", http.StatusForbidden)
				return
			}
			var body air.Announcement
			dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<10))
			if err := dec.Decode(&body); err != nil || dec.Decode(&struct{}{}) != io.EOF {
				if audit != nil {
					audit(airSteerAudit{Peer: fqdnOr(fqdn), PeerKey: pubKey, Method: "air/presence.announce", OK: false})
				}
				http.Error(w, "bad presence announcement", http.StatusBadRequest)
				return
			}
			card, changed, err := c.announce(pubKey, fqdn, observedPeerIP(r.RemoteAddr), body, time.Now())
			if err != nil {
				if audit != nil {
					audit(airSteerAudit{Peer: fqdnOr(fqdn), PeerKey: pubKey, Session: body.Name, Method: "air/presence.announce", OK: false})
				}
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			// Do not append an enforcement record every few seconds for an
			// unchanged heartbeat. Material card changes remain attributable.
			if changed && audit != nil {
				audit(airSteerAudit{Peer: fqdnOr(fqdn), PeerKey: pubKey, Session: card.Name, Method: "air/presence.announce", OK: true})
			}
			writeJSONResp(w, http.StatusOK, map[string]any{"status": "present", "changed": changed, "presence": card})

		case http.MethodDelete:
			if pubKey == "" {
				if audit != nil {
					audit(airSteerAudit{Peer: fqdnOr(fqdn), Method: "air/presence.leave", OK: false})
				}
				http.Error(w, "presence requires a transport-verified public key", http.StatusForbidden)
				return
			}
			removed := c.leave(pubKey)
			if audit != nil {
				audit(airSteerAudit{Peer: fqdnOr(fqdn), PeerKey: pubKey, Method: "air/presence.leave", OK: true})
			}
			writeJSONResp(w, http.StatusOK, map[string]any{"status": "left", "removed": removed})

		default:
			if audit != nil {
				audit(airSteerAudit{Peer: fqdnOr(fqdn), PeerKey: pubKey, Method: "air/presence", OK: false})
			}
			w.Header().Set("Allow", "GET, POST, DELETE")
			http.Error(w, "GET, POST, or DELETE only", http.StatusMethodNotAllowed)
		}
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
		onBehalf, onBehalfKey := onBehalfOf(r, onBehalfAllow, pubKey, fqdn)
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
// headers. It is honoured only when the *connecting* peer (the proxy) is on the
// dedicated on-behalf proxy allow list — NOT the general control allow — so an
// ordinary allowed caller can't forge attribution by setting the headers. It
// FAILS CLOSED: an empty proxy allow list trusts no one, so no header is
// honoured and attribution stays the verified connecting peer. The key is never
// honoured without the FQDN.
func onBehalfOf(r *http.Request, onBehalfAllow acl, proxyKey, proxyFQDN string) (fqdn, key string) {
	ob := r.Header.Get("X-Air-On-Behalf")
	if ob == "" || onBehalfAllow.empty() || !onBehalfAllow.allows(proxyKey, proxyFQDN) {
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
	servers  map[string]*session.Server
	acls     map[string]acl
	mu       *sync.Mutex
	backends []AirCatalogEntry // canonical cards; live steerability is added per response
	gateway  string            // this gateway's mesh FQDN, for the catalog
	presence *air.Registry     // TTL directory: one identity-stamped card per peer key
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
			out = append(out, AirSession{
				Backend: name, ID: s.ID, Peer: s.Peer, PeerKey: s.PeerKey,
				AgeSec: int(s.Age / time.Second),
			})
		}
	}
	return out
}

// catalog returns the backends the caller's identity is permitted to reach —
// discovery that respects the per-backend ACL, so a peer never learns of a
// backend it could not already call.
func (g *gatewayAirControl) catalog(pubKey, fqdn string) AirCatalog {
	cat := AirCatalog{Schema: air.CatalogSchemaV1, Service: "meshmcp", Version: version, Gateway: g.gateway}
	for _, b := range g.backends {
		if !g.backendAllows(b.Name, pubKey, fqdn) {
			continue
		}
		g.mu.Lock()
		_, steerable := g.servers[b.Name]
		g.mu.Unlock()
		entry := b
		entry.Features = append([]air.Feature(nil), b.Features...)
		if steerable {
			entry.Steerable = true
			entry.Features = append(entry.Features, air.Feature{Name: air.FeatureAirSteerV1})
		}
		// Static cards were validated at startup and the only dynamic addition
		// is the standard steer feature, so normalization cannot fail here.
		if normalized, err := entry.Normalized(); err == nil {
			cat.Endpoints = append(cat.Endpoints, normalized)
		}
	}
	return cat
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

func (g *gatewayAirControl) nearby(now time.Time) []air.Presence {
	return g.presenceRegistry().List(now)
}

func (g *gatewayAirControl) announce(pubKey, fqdn, observedIP string, a air.Announcement, now time.Time) (air.Presence, bool, error) {
	return g.presenceRegistry().Upsert(air.VerifiedIdentity{PublicKey: pubKey, FQDN: fqdn}, observedIP, a, now)
}

func (g *gatewayAirControl) leave(pubKey string) bool {
	return g.presenceRegistry().Remove(pubKey)
}

func (g *gatewayAirControl) presenceRegistry() *air.Registry {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.presence == nil {
		g.presence = air.NewRegistry(air.DefaultPresenceRegistryMax)
	}
	return g.presence
}

func observedPeerIP(remote string) string {
	host, _, err := net.SplitHostPort(remote)
	if err != nil || net.ParseIP(host) == nil {
		return ""
	}
	return host
}

func presenceMethod(method string) string {
	switch method {
	case http.MethodGet, http.MethodHead:
		return "air/presence.list"
	case http.MethodPost:
		return "air/presence.announce"
	case http.MethodDelete:
		return "air/presence.leave"
	default:
		return "air/presence"
	}
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
		// The method already names the action (air/steer, air/sessions,
		// air/catalog); use it as the reason base directly.
		base := rec.Method
		if base == "" {
			base = "air/steer"
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
