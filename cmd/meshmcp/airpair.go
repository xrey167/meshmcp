package main

import (
	"log"
	"net/http"
	"time"

	"github.com/xrey167/meshmcp/air"
	"github.com/xrey167/meshmcp/policy"
)

// The Air pairing endpoint is meshmcp's "Accept?" moment. It replaces
// hand-editing an --allow / YAML ACL with a request-then-approve flow: a peer
// that is NOT yet allowed asks for access, an operator taps approve, and the
// recognized-peer store updates itself. It mounts on the existing Air control
// listener (serve.go) and shares its identity resolution and audit chain.
//
// Two tiers of surface, by deliberate design:
//   - Open (NOT admission-gated): POST /v1/pair/request and GET /v1/pair/status.
//     An un-allowed peer MUST be able to reach these — asking is the whole
//     point. They resolve the caller's VERIFIED transport identity (never a
//     body-supplied one), are rate-limited per identity, and GRANT NOTHING: a
//     request only queues a pending entry; status reports the caller's own
//     standing and nothing about anyone else.
//   - Operator-gated (deny-by-default): GET /v1/pair/pending and
//     POST /v1/pair/approve|deny|revoke. Only an already-allowed operator
//     identity may reach these. An un-allowed peer can request but can NEVER
//     approve.
//
// The boundary this endpoint enforces: approving establishes a RECOGNIZED peer
// identity in the paired store; it does NOT add the peer to the privileged
// control-steer allow or to any backend/tool ACL. Actual tool access is a
// separate, explicit step (grant-on-request). Recognition is not capability.

// pairRatePerMin bounds pair requests per source identity. The request endpoint
// is reachable by peers that hold no admission at all, so it must be
// DoS-resistant; a legitimate peer needs to ask at most a handful of times.
const pairRatePerMin = 12

// pairControlHandler builds the pairing surface over a PairedStore. identify
// resolves the caller's verified (pubkey, fqdn); operator gates the approve/
// deny/revoke/pending surface deny-by-default; limiter throttles requests per
// identity; audit records every state transition on the shared chain.
func pairControlHandler(store *air.PairedStore, identify func(*http.Request) (pubkey, fqdn string), operator acl, limiter *ringLimiter, audit func(pairAudit)) http.Handler {
	mux := http.NewServeMux()

	// gate resolves the caller and enforces the operator ACL deny-by-default. An
	// EMPTY operator ACL trusts no one here (unlike a backend's open-by-omission
	// ACL): the approve surface mutates the recognized set, so it must never be
	// open by omission. On refusal it writes the 403, audits the deny, and
	// returns ok=false so the route stops.
	gate := func(w http.ResponseWriter, r *http.Request, method string) (pubKey, fqdn string, ok bool) {
		pubKey, fqdn = identify(r)
		if operator.empty() || !operator.allows(pubKey, fqdn) {
			emitPairAudit(audit, pairAudit{Method: method, Peer: fqdnOr(fqdn), PeerKey: pubKey, Reason: "pair admin: caller is not an operator", OK: false})
			http.Error(w, "not permitted", http.StatusForbidden)
			return "", "", false
		}
		return pubKey, fqdn, true
	}

	// POST /v1/pair/request — open to un-allowed peers; grants nothing.
	mux.HandleFunc("/v1/pair/request", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		pubKey, fqdn := identify(r)
		// A pending request must be attributable to an unforgeable identity — a
		// peer that resolves no transport-verified key cannot pair.
		if pubKey == "" {
			emitPairAudit(audit, pairAudit{Method: "air/pair.request", Peer: fqdnOr(fqdn), Reason: "pair request without a transport-verified key", OK: false})
			http.Error(w, "pairing requires a transport-verified public key", http.StatusForbidden)
			return
		}
		// Rate-limit on the VERIFIED key, so a peer's own framing cannot bypass
		// it. An un-allowed party can reach this endpoint, so it must be
		// DoS-resistant (mirrors air listen's ring limiter).
		if !limiter.allow(pubKey, time.Now()) {
			emitPairAudit(audit, pairAudit{Method: "air/pair.request", Peer: fqdnOr(fqdn), PeerKey: pubKey, Reason: "pair request rate-limited", OK: false})
			http.Error(w, "too many pair requests, slow down", http.StatusTooManyRequests)
			return
		}
		var body struct {
			Label string `json:"label"`
		}
		// The body is optional (only a friendly label); an absent body is fine.
		if r.ContentLength != 0 && !decodeJSONBody(w, r, &body) {
			return
		}
		_, added, err := store.Request(air.VerifiedIdentity{PublicKey: pubKey, FQDN: fqdn}, body.Label, time.Now())
		if err != nil {
			emitPairAudit(audit, pairAudit{Method: "air/pair.request", Peer: fqdnOr(fqdn), PeerKey: pubKey, Reason: "pair request rejected: " + err.Error(), OK: false})
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// Audit only a NEWLY queued request; an idempotent re-poll is not a new
		// state transition and must not flood the chain (mirrors presence's
		// unchanged-heartbeat quieting).
		if added {
			emitPairAudit(audit, pairAudit{Method: "air/pair.request", Peer: fqdnOr(fqdn), PeerKey: pubKey, Reason: "pair request queued (grants nothing until an operator approves)", OK: true})
			// A minimal live line for the operator running the daemon, so a new
			// request is visible without watching the audit stream. Approval stays
			// an explicit `air pair approve` — this only notices, never grants.
			log.Printf("air pair: %s (%s) is requesting access — approve with `air pair approve`", fqdnOr(fqdn), shortKey(pubKey))
		}
		writeJSONResp(w, http.StatusOK, map[string]any{"status": store.Status(pubKey), "you": fqdnOr(fqdn)})
	})

	// GET /v1/pair/status — open; reports only the caller's own standing.
	mux.HandleFunc("/v1/pair/status", func(w http.ResponseWriter, r *http.Request) {
		if !getOnly(w, r) {
			return
		}
		pubKey, fqdn := identify(r)
		writeJSONResp(w, http.StatusOK, map[string]any{"status": store.Status(pubKey), "you": fqdnOr(fqdn)})
	})

	// GET /v1/pair/pending — operator-gated; lists pending + recognized peers.
	mux.HandleFunc("/v1/pair/pending", func(w http.ResponseWriter, r *http.Request) {
		if !getOnly(w, r) {
			return
		}
		if _, _, ok := gate(w, r, "air/pair.pending"); !ok {
			return
		}
		writeJSONResp(w, http.StatusOK, pairListResponse{
			Pending: nonNilPending(store.Pending()),
			Paired:  nonNilPaired(store.Paired()),
		})
	})

	mux.HandleFunc("/v1/pair/approve", pairMutation(store, identify, gate, audit, "approve"))
	mux.HandleFunc("/v1/pair/deny", pairMutation(store, identify, gate, audit, "deny"))
	mux.HandleFunc("/v1/pair/revoke", pairMutation(store, identify, gate, audit, "revoke"))

	return mux
}

// pairMutation builds the approve/deny/revoke handler. All three are POST,
// operator-gated, take {"pubkey": <key>}, and audit their transition. Approve
// moves a pending request into the recognized set; deny drops it; revoke
// removes a recognized peer.
func pairMutation(store *air.PairedStore, identify func(*http.Request) (string, string), gate func(http.ResponseWriter, *http.Request, string) (string, string, bool), audit func(pairAudit), op string) http.HandlerFunc {
	method := "air/pair." + op
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		opKey, opFQDN, ok := gate(w, r, method)
		if !ok {
			return
		}
		var body struct {
			PublicKey string `json:"pubkey"`
		}
		if !decodeJSONBody(w, r, &body) {
			return
		}
		if body.PublicKey == "" {
			http.Error(w, "pubkey is required", http.StatusBadRequest)
			return
		}
		operator := fqdnOr(opFQDN)
		rec := pairAudit{Method: method, Peer: operator, PeerKey: opKey, Subject: body.PublicKey}

		switch op {
		case "approve":
			peer, err := store.Approve(body.PublicKey, operator, time.Now())
			if err != nil {
				rec.OK = false
				rec.Reason = "approve failed: " + err.Error()
				emitPairAudit(audit, rec)
				http.Error(w, err.Error(), http.StatusNotFound)
				return
			}
			rec.OK = true
			rec.Reason = "approved paired peer (recognized identity; NOT granted any tool or control capability)"
			emitPairAudit(audit, rec)
			writeJSONResp(w, http.StatusOK, map[string]any{"status": "approved", "peer": peer})
		case "deny":
			removed, err := store.Deny(body.PublicKey)
			if err != nil {
				rec.OK = false
				rec.Reason = "deny failed: " + err.Error()
				emitPairAudit(audit, rec)
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			rec.OK = true
			rec.Reason = "denied pending pair request"
			emitPairAudit(audit, rec)
			writeJSONResp(w, http.StatusOK, map[string]any{"status": "denied", "removed": removed})
		case "revoke":
			removed, err := store.Revoke(body.PublicKey)
			if err != nil {
				rec.OK = false
				rec.Reason = "revoke failed: " + err.Error()
				emitPairAudit(audit, rec)
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			rec.OK = true
			rec.Reason = "revoked paired peer (no longer recognized)"
			emitPairAudit(audit, rec)
			writeJSONResp(w, http.StatusOK, map[string]any{"status": "revoked", "removed": removed})
		}
	}
}

// pairListResponse is the operator's view: everything waiting and everyone
// recognized.
type pairListResponse struct {
	Pending []air.PendingRequest `json:"pending"`
	Paired  []air.PairedPeer     `json:"paired"`
}

func nonNilPending(p []air.PendingRequest) []air.PendingRequest {
	if p == nil {
		return []air.PendingRequest{}
	}
	return p
}

func nonNilPaired(p []air.PairedPeer) []air.PairedPeer {
	if p == nil {
		return []air.PairedPeer{}
	}
	return p
}

// pairAudit is one pairing state transition, recorded on the shared ledger.
// Peer/PeerKey are the acting identity (the requester for a request, the
// operator for an admin action); Subject is the peer being approved/denied/
// revoked, empty for a request (the requester IS the subject).
type pairAudit struct {
	Method, Peer, PeerKey, Subject, Reason string
	OK                                     bool
}

func emitPairAudit(audit func(pairAudit), rec pairAudit) {
	if audit != nil {
		audit(rec)
	}
}

// pairAuditFunc adapts the shared audit ledger to the pairing handler, so
// request/approve/deny/revoke land on the SAME hash chain as every other
// governed Air action — no parallel audit path. A nil ledger is a no-op.
func pairAuditFunc(audit *policy.AuditLog) func(pairAudit) {
	if audit == nil {
		return nil
	}
	return func(rec pairAudit) {
		decision := "allow"
		if !rec.OK {
			decision = "deny"
		}
		method := rec.Method
		if method == "" {
			method = "air/pair"
		}
		audit.Append(policy.AuditRecord{
			Backend:  "pair",
			Peer:     rec.Peer,
			PeerKey:  rec.PeerKey, // verified acting-peer key
			Method:   method,
			Tool:     rec.Subject, // the peer acted upon (for admin actions)
			Decision: decision,
			Reason:   rec.Reason,
			Rule:     -1,
		})
	}
}
