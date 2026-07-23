package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/xrey167/meshmcp/policy"
)

// ssoAttestHandler serves POST /v1/sso/attest (F31): a mesh peer presents an
// OIDC token over its already-authenticated mesh connection, and the gateway
// binds the token's verified groups to the caller's WireGuard TRANSPORT key for
// a bounded lifetime.
//
// SACRED ordering: the transport peerKey is resolved from the CONNECTION first
// (never from the token), so it is itself WireGuard-authenticated — the token
// alone authenticates nothing. Only after the transport root is established does
// the token get verified; on success its groups become an ADDITIVE attribution
// bound to that key. Every verification failure (forged/expired/wrong-audience/
// unpinned) binds NOTHING and leaves the caller's mesh admission untouched.
//
// This is self-service: any authenticated mesh peer may attest — it binds groups
// to its OWN transport key only, and those groups come from a token an external
// IdP issued to it and that this gateway verified against a pinned key, so a peer
// can never attribute a group it was not actually issued. An unattributable
// transport (no WireGuard key) is denied — there is nothing to bind to.
func ssoAttestHandler(verifier *policy.OIDCVerifier, store *policy.SSOGroups, identify func(*http.Request) (pubKey, fqdn string), bindTTLMax time.Duration, now func() time.Time, audit func(rec ssoAttestAudit)) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/sso/attest", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		if !sameOrigin(r) {
			http.Error(w, "cross-origin request refused", http.StatusForbidden)
			return
		}
		// TRANSPORT ROOT: the WireGuard key is resolved from the connection, never
		// from the token. Fail closed on an unattributable transport.
		peerKey, fqdn := identify(r)
		if peerKey == "" {
			if audit != nil {
				audit(ssoAttestAudit{Peer: fqdnOr(fqdn), PeerKey: peerKey, OK: false, Reason: "unattributable transport (no WireGuard key)"})
			}
			http.Error(w, "sso attest requires a transport-verified public key", http.StatusUnauthorized)
			return
		}
		var body struct {
			Token string `json:"token"`
		}
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&body) != nil || body.Token == "" {
			http.Error(w, "token is required", http.StatusBadRequest)
			return
		}
		claims, err := verifier.Verify(body.Token, now())
		if err != nil {
			// Every forgery / expiry / audience / issuer failure lands here: NO BIND.
			if audit != nil {
				audit(ssoAttestAudit{Peer: fqdnOr(fqdn), PeerKey: peerKey, OK: false, Reason: err.Error()})
			}
			http.Error(w, "token verification failed", http.StatusUnauthorized)
			return
		}
		// Bound the binding to min(token exp, now + cap).
		exp := time.Unix(claims.ExpiresAt, 0)
		if bindTTLMax > 0 {
			if ceiling := now().Add(bindTTLMax); exp.After(ceiling) {
				exp = ceiling
			}
		}
		store.Bind(peerKey, claims, exp)
		if audit != nil {
			audit(ssoAttestAudit{Peer: fqdnOr(fqdn), PeerKey: peerKey, Subject: claims.Subject, Groups: claims.Groups, OK: true})
		}
		writeJSONResp(w, http.StatusOK, map[string]any{
			"status":     "bound",
			"subject":    claims.Subject,
			"email":      claims.Email,
			"groups":     claims.Groups,
			"expires_at": exp.Unix(),
			"you":        fqdnOr(fqdn),
		})
	})
	return mux
}

// ssoAttestAudit is one attestation attempt recorded in the shared ledger.
type ssoAttestAudit struct {
	Peer, PeerKey, Subject, Reason string
	Groups                         []string
	OK                             bool
}

// ssoAuditFunc adapts the shared audit ledger to the attest handler; nil audit
// is a no-op. PeerKey always holds the transport-verified key the attribution
// binds to; Tool records the attributed IdP subject.
func ssoAuditFunc(audit *policy.AuditLog) func(ssoAttestAudit) {
	if audit == nil {
		return nil
	}
	return func(rec ssoAttestAudit) {
		decision := "allow"
		if !rec.OK {
			decision = "deny"
		}
		reason := rec.Reason
		if rec.OK {
			reason = "sso attribution bound: groups=[" + strings.Join(rec.Groups, ",") + "]"
		}
		audit.Append(policy.AuditRecord{
			Backend:  "sso-attest",
			Peer:     rec.Peer,
			PeerKey:  rec.PeerKey,
			Method:   "sso/attest",
			Tool:     rec.Subject,
			Decision: decision,
			Reason:   reason,
			Rule:     -1,
		})
	}
}
