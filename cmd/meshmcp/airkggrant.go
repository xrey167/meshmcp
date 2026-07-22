package main

import (
	"log"
	"net/http"
	"time"

	"github.com/xrey167/meshmcp/air"
	"github.com/xrey167/meshmcp/air/know"
	"github.com/xrey167/meshmcp/air/knowstore"
	"github.com/xrey167/meshmcp/policy"
)

// Grant-on-request wiring for air kg — the REFERENCE integration. The kg grant
// bridge consults, per call, BOTH the operator's static --grant map AND the
// dynamic air.GrantStore, so a recognized peer that was denied a corpus can have
// that denial turned into a pending opportunity an operator resolves with one
// `air grant allow`. Deny-by-default is preserved throughout: with no static and
// no dynamic grant, the facade's know.Allowed still rejects.
//
// How another verb opts in: build a bridge like this one (its own verb string),
// fold GrantStore.ScopesFor into the per-call capability its authorization gate
// reads, call ConsumeOnceMatching when a single-use grant is the deciding factor,
// and Record (gated on air.PairedStore.Recognized) when the gate denies. Then
// mount grantControlHandler on its listener with the same verb. The store, CLI,
// and endpoints are verb-agnostic; only this bridge knows corpus-glob semantics.

const (
	// grantVerbKG namespaces kg grants in the shared store, so a kg grant never
	// confers a different verb's access (invariant 6).
	grantVerbKG = "kg"

	grantAuditBackend  = "air-grant"
	grantMethodRequest = "grant.request" // a recognized peer's denied call recorded an opportunity
	grantMethodConsume = "grant.consume" // a single-use grant was spent authorizing a call
	grantMethodPending = "grant.pending" // operator listed pending/active grants

	// grantRecordRatePerMin throttles the opportunity audit line + log notice per
	// identity, so a recognized peer probing many distinct scopes cannot flood the
	// ledger. The store itself dedups and is bounded independently.
	grantRecordRatePerMin = 30
)

// kgGrantBridge resolves a caller's corpora for one request by folding the
// dynamic grant-store into the operator's static --grant map. It owns the
// dynamic store's lifecycle: consuming a single-use grant when it authorizes a
// call, and recording a grant opportunity (recognized peers only) when nothing
// does. With a nil dyn it degrades to exactly the static-grant behavior.
type kgGrantBridge struct {
	static  kgGrants
	dyn     *air.GrantStore  // nil ⇒ dynamic grant-on-request disabled
	paired  *air.PairedStore // nil ⇒ no peer is recognized ⇒ no opportunity recorded
	limiter *ringLimiter     // throttles opportunity-audit emission per identity
	audit   policy.AuditSink
}

// caller builds the verified knowstore.Caller for a request against corpus, with
// write distinguishing an assert from a read. Its capability claims are the
// corpora the caller is granted for THIS corpus — static ∪ any authorizing
// dynamic grant — so the facade's know.Allowed remains the single enforcer.
func (b *kgGrantBridge) caller(pubKey, fqdn, corpus string, write bool) knowstore.Caller {
	peer := fqdn
	if peer == "" {
		peer = pubKey
	}
	return knowstore.Caller{
		Claims:  policy.CapabilityClaims{Corpora: b.corporaForRequest(pubKey, fqdn, corpus, write)},
		Peer:    peer,
		PeerKey: pubKey,
	}
}

// corporaForRequest is the heart of the bridge. It returns the corpora the facade
// will authorize against, and as a side effect consumes a single-use grant that
// decides this call or records a grant opportunity when the call is denied.
//
// The decision uses know.Allowed — the exact gate the facade re-applies — as its
// oracle, so the bridge never diverges from the enforcer:
//   - static ∪ persistent already authorizes  → nothing to consume; return it.
//   - a single-use grant is the deciding factor → consume exactly the one that
//     authorizes THIS corpus/op, so a second attempt is denied again.
//   - denied even with every grant folded in    → record an opportunity, but ONLY
//     for a recognized (paired) peer; an un-paired peer records nothing.
func (b *kgGrantBridge) corporaForRequest(pubKey, fqdn, corpus string, write bool) []string {
	static := b.static.corporaFor(pubKey, fqdn)
	if b.dyn == nil || pubKey == "" || corpus == "" {
		return static
	}
	op := know.KnowOp{Corpus: corpus, Write: write}
	persistent, once := b.dyn.ScopesFor(pubKey, grantVerbKG)

	base := dedupeStrings(append(append([]string{}, static...), persistent...))
	if know.Allowed(policy.CapabilityClaims{Corpora: base}, op) {
		return base // static or a persistent dynamic grant already authorizes
	}

	all := dedupeStrings(append(append([]string{}, base...), once...))
	if know.Allowed(policy.CapabilityClaims{Corpora: all}, op) {
		// A single-use grant tips authorization. Consume exactly the one whose
		// scope — added to base — authorizes this corpus/op.
		authorizes := func(scope string) bool {
			return know.Allowed(policy.CapabilityClaims{Corpora: append(append([]string{}, base...), scope)}, op)
		}
		if g, ok, err := b.dyn.ConsumeOnceMatching(pubKey, grantVerbKG, authorizes, time.Now()); err == nil && ok {
			appendGrantAudit(b.audit, grantMethodConsume, fqdnOr(fqdn), pubKey, g.Scope, "allow",
				"single-use grant consumed for this request (now spent)")
		}
		return all
	}

	// Denied even with every grant. Record an opportunity for a RECOGNIZED peer
	// only — an un-paired stranger's denial records nothing and cannot be granted.
	if b.paired != nil && b.paired.Recognized(pubKey, fqdn) {
		if opp, added, err := b.dyn.Record(pubKey, grantVerbKG, corpus, time.Now()); err == nil && added {
			if b.limiter == nil || b.limiter.allow(pubKey, time.Now()) {
				appendGrantAudit(b.audit, grantMethodRequest, fqdnOr(fqdn), pubKey, opp.Scope, "deny",
					"grant opportunity recorded (recognized peer denied scope; grants nothing until an operator approves)")
				log.Printf("air grant: %s (%s) was denied %q — approve with `air grant allow`", fqdnOr(fqdn), shortKey(pubKey), corpus)
			}
		}
	}
	return static
}

// appendGrantAudit records one grant-lifecycle transition on the SHARED audit
// chain (backend "air-grant"), so request→allow→consume→revoke land on the same
// hash-chained ledger as every other governed Air action and pass VerifyChain.
// Peer/PeerKey are the acting identity; Tool carries the scope. A nil sink no-ops.
func appendGrantAudit(sink policy.AuditSink, method, peer, peerKey, scope, decision, reason string) {
	if sink == nil {
		return
	}
	_ = sink.Append(policy.AuditRecord{
		Backend:  grantAuditBackend,
		Peer:     peer,
		PeerKey:  peerKey,
		Method:   method,
		Tool:     scope,
		Decision: decision,
		Reason:   reason,
		Rule:     -1,
	})
}

// grantListResponse is the operator's view of one verb's grant state: everything
// waiting and everything currently granted.
type grantListResponse struct {
	Pending []air.GrantOpportunity `json:"pending"`
	Grants  []air.Grant            `json:"grants"`
}

// grantControlHandler builds the operator-gated grant admin surface over a
// GrantStore for one verb. It mirrors the pairing admin surface: deny-by-default,
// fail-closed on an empty operator ACL (an approve surface that mutates capability
// must never be open by omission), every action audited on the shared chain. The
// verb scopes what this handler sees and writes, so one listener's operator never
// sees or touches another verb's grants.
func grantControlHandler(store *air.GrantStore, identify func(*http.Request) (pubkey, fqdn string), operator acl, verb string, audit policy.AuditSink) http.Handler {
	mux := http.NewServeMux()

	gate := func(w http.ResponseWriter, r *http.Request, method string) (opKey, opFQDN string, ok bool) {
		opKey, opFQDN = identify(r)
		if operator.empty() || !operator.allows(opKey, opFQDN) {
			appendGrantAudit(audit, method, fqdnOr(opFQDN), opKey, "", "deny", "grant admin: caller is not an operator")
			http.Error(w, "not permitted", http.StatusForbidden)
			return "", "", false
		}
		return opKey, opFQDN, true
	}

	mux.HandleFunc("/v1/grant/pending", func(w http.ResponseWriter, r *http.Request) {
		if !getOnly(w, r) {
			return
		}
		if _, _, ok := gate(w, r, grantMethodPending); !ok {
			return
		}
		writeJSONResp(w, http.StatusOK, grantListResponse{
			Pending: opportunitiesForVerb(store.Pending(), verb),
			Grants:  grantsForVerb(store.Grants(), verb),
		})
	})

	mux.HandleFunc("/v1/grant/allow", grantMutation(store, gate, audit, verb, "allow"))
	mux.HandleFunc("/v1/grant/deny", grantMutation(store, gate, audit, verb, "deny"))
	mux.HandleFunc("/v1/grant/revoke", grantMutation(store, gate, audit, verb, "revoke"))

	return mux
}

// grantMutation builds the allow/deny/revoke handler. All three are POST,
// operator-gated, and audited. allow WRITES a grant ({pubkey, scope, once});
// deny drops the pending opportunity ({pubkey, scope}) without granting; revoke
// removes an active grant ({pubkey, scope}). scope is verb-namespaced here.
func grantMutation(store *air.GrantStore, gate func(http.ResponseWriter, *http.Request, string) (string, string, bool), audit policy.AuditSink, verb, op string) http.HandlerFunc {
	method := "grant." + op
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
			Scope     string `json:"scope"`
			Once      bool   `json:"once"`
		}
		if !decodeJSONBody(w, r, &body) {
			return
		}
		if body.PublicKey == "" || body.Scope == "" {
			http.Error(w, "pubkey and scope are required", http.StatusBadRequest)
			return
		}
		operator := fqdnOr(opFQDN)

		switch op {
		case "allow":
			g, err := store.Add(body.PublicKey, verb, body.Scope, body.Once, operator, time.Now())
			if err != nil {
				appendGrantAudit(audit, method, operator, opKey, body.Scope, "deny", "allow failed: "+err.Error())
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			appendGrantAudit(audit, method, operator, opKey, g.Scope, "allow", grantAllowReason(g))
			writeJSONResp(w, http.StatusOK, map[string]any{"status": "granted", "grant": g})
		case "deny":
			removed, err := store.DropOpportunity(body.PublicKey, verb, body.Scope)
			if err != nil {
				appendGrantAudit(audit, method, operator, opKey, body.Scope, "deny", "deny failed: "+err.Error())
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			appendGrantAudit(audit, method, operator, opKey, body.Scope, "allow", "denied pending grant opportunity (nothing granted)")
			writeJSONResp(w, http.StatusOK, map[string]any{"status": "denied", "removed": removed})
		case "revoke":
			removed, err := store.Remove(body.PublicKey, verb, body.Scope)
			if err != nil {
				appendGrantAudit(audit, method, operator, opKey, body.Scope, "deny", "revoke failed: "+err.Error())
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			appendGrantAudit(audit, method, operator, opKey, body.Scope, "allow", "revoked grant (no longer authorized)")
			writeJSONResp(w, http.StatusOK, map[string]any{"status": "revoked", "removed": removed})
		}
	}
}

func grantAllowReason(g air.Grant) string {
	if g.Once {
		return "granted scope (allow once — single use)"
	}
	return "granted scope (always — persistent)"
}

// opportunitiesForVerb filters a snapshot to one verb, normalizing nil to an
// empty slice so the JSON response carries [] rather than null.
func opportunitiesForVerb(all []air.GrantOpportunity, verb string) []air.GrantOpportunity {
	out := make([]air.GrantOpportunity, 0, len(all))
	for _, p := range all {
		if p.Verb == verb {
			out = append(out, p)
		}
	}
	return out
}

func grantsForVerb(all []air.Grant, verb string) []air.Grant {
	out := make([]air.Grant, 0, len(all))
	for _, g := range all {
		if g.Verb == verb {
			out = append(out, g)
		}
	}
	return out
}
