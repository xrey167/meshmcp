package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/xrey167/meshmcp/air"
	"github.com/xrey167/meshmcp/air/knowstore"
	"github.com/xrey167/meshmcp/kg"
	"github.com/xrey167/meshmcp/policy"
)

// grantRig is a served air-kg endpoint wired to a dynamic grant-store, a paired
// (recognition) store, and the operator grant-admin surface — all over ONE real
// facade, ONE real grant-store, and ONE shared audit chain, so the tests exercise
// the actual deny-by-default / recognition / single-use semantics end to end.
type grantRig struct {
	facade   *knowstore.Facade
	bridge   *kgGrantBridge
	grants   *air.GrantStore
	paired   *air.PairedStore
	audit    policy.AuditSink
	buf      *bytes.Buffer
	allow    acl
	operator acl
}

func newGrantRig(t *testing.T, allow, operator []string) *grantRig {
	t.Helper()
	dir := t.TempDir()
	st, err := kg.Open(filepath.Join(dir, "kg.jsonl"), func() string { return "t" })
	if err != nil {
		t.Fatalf("kg.Open: %v", err)
	}
	grants, err := air.OpenGrantStore(filepath.Join(dir, "grants.json"))
	if err != nil {
		t.Fatalf("OpenGrantStore: %v", err)
	}
	paired, err := air.OpenPairedStore(filepath.Join(dir, "paired.json"))
	if err != nil {
		t.Fatalf("OpenPairedStore: %v", err)
	}
	var buf bytes.Buffer
	audit := policy.NewAuditLog(&buf, func() string { return "t" })
	facade := knowstore.New(st, audit)
	bridge := &kgGrantBridge{
		static:  nil,
		dyn:     grants,
		paired:  paired,
		limiter: newRingLimiter(grantRecordRatePerMin),
		audit:   audit,
	}
	return &grantRig{
		facade: facade, bridge: bridge, grants: grants, paired: paired,
		audit: audit, buf: &buf, allow: newACL(allow), operator: newACL(operator),
	}
}

// kgFor builds a kg handler that identifies its caller as (pubKey, fqdn).
func (r *grantRig) kgFor(pubKey, fqdn string) http.Handler {
	return kgControlHandler(r.facade, fixedIdentify(pubKey, fqdn), r.allow, r.bridge, nil, r.audit)
}

// grantFor builds the operator grant-admin handler identifying as (pubKey, fqdn).
func (r *grantRig) grantFor(pubKey, fqdn string) http.Handler {
	return grantControlHandler(r.grants, fixedIdentify(pubKey, fqdn), r.operator, grantVerbKG, r.audit)
}

// recognize marks (pubKey, fqdn) as a paired (recognized) peer.
func (r *grantRig) recognize(t *testing.T, pubKey, fqdn string) {
	t.Helper()
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	if _, _, err := r.paired.Request(air.VerifiedIdentity{PublicKey: pubKey, FQDN: fqdn}, "", now); err != nil {
		t.Fatalf("pair request: %v", err)
	}
	if _, err := r.paired.Approve(pubKey, "op.mesh", now); err != nil {
		t.Fatalf("pair approve: %v", err)
	}
}

const (
	grPeerKey  = "peer-key"
	grPeerFQDN = "peer.mesh"
	grOpKey    = "op-key"
	grOpFQDN   = "op.mesh"
)

func grantAllowList() []string    { return []string{"*.mesh"} } // reachability: any mesh FQDN
func grantOperatorList() []string { return []string{"pubkey:" + grOpKey} }

// TestGrantRecognizedOnlyRecordsOpportunity proves invariant 1: a RECOGNIZED
// peer's denied kg request records a pending opportunity; an un-paired peer's
// denied request records nothing and cannot be granted.
func TestGrantRecognizedOnlyRecordsOpportunity(t *testing.T) {
	rig := newGrantRig(t, grantAllowList(), grantOperatorList())
	rig.recognize(t, grPeerKey, grPeerFQDN)

	// Recognized peer, denied (no grant) → opportunity recorded.
	if rr := do(rig.kgFor(grPeerKey, grPeerFQDN), http.MethodGet, "/v1/kg/query?corpus=proj", ""); rr.Code != http.StatusForbidden {
		t.Fatalf("recognized peer query = %d, want 403 (no grant yet)", rr.Code)
	}
	// Un-paired stranger, reachable but not recognized, denied → records nothing.
	if rr := do(rig.kgFor("stranger-key", "stranger.mesh"), http.MethodGet, "/v1/kg/query?corpus=proj", ""); rr.Code != http.StatusForbidden {
		t.Fatalf("stranger query = %d, want 403", rr.Code)
	}

	pend := rig.grants.Pending()
	if len(pend) != 1 {
		t.Fatalf("pending = %+v, want exactly one (the recognized peer's)", pend)
	}
	if pend[0].Identity != grPeerKey || pend[0].Scope != "proj" || pend[0].Verb != grantVerbKG {
		t.Fatalf("pending[0] = %+v, want peer-key/kg/proj", pend[0])
	}
}

// TestGrantAllowAlwaysThenRetrySucceeds proves an operator "always" grant is
// consulted by the served handler so the peer's retry succeeds (invariant 2:
// a grant WIDENS access, only after explicit operator approval).
func TestGrantAllowAlwaysThenRetrySucceeds(t *testing.T) {
	rig := newGrantRig(t, grantAllowList(), grantOperatorList())
	rig.recognize(t, grPeerKey, grPeerFQDN)
	kgH := rig.kgFor(grPeerKey, grPeerFQDN)

	if rr := do(kgH, http.MethodGet, "/v1/kg/query?corpus=proj", ""); rr.Code != http.StatusForbidden {
		t.Fatalf("pre-grant query = %d, want 403", rr.Code)
	}
	if rr := do(rig.grantFor(grOpKey, grOpFQDN), http.MethodPost, "/v1/grant/allow", `{"pubkey":"peer-key","scope":"proj","once":false}`); rr.Code != http.StatusOK {
		t.Fatalf("operator allow = %d, want 200: %s", rr.Code, rr.Body)
	}
	if rr := do(kgH, http.MethodGet, "/v1/kg/query?corpus=proj", ""); rr.Code != http.StatusOK {
		t.Fatalf("post-grant query = %d, want 200: %s", rr.Code, rr.Body)
	}
}

// TestGrantAllowOnceConsumedOnce proves invariant 3: a single-use grant lets the
// first retry through and the second is denied again (consumed exactly once).
func TestGrantAllowOnceConsumedOnce(t *testing.T) {
	rig := newGrantRig(t, grantAllowList(), grantOperatorList())
	rig.recognize(t, grPeerKey, grPeerFQDN)
	kgH := rig.kgFor(grPeerKey, grPeerFQDN)

	if rr := do(rig.grantFor(grOpKey, grOpFQDN), http.MethodPost, "/v1/grant/allow", `{"pubkey":"peer-key","scope":"proj","once":true}`); rr.Code != http.StatusOK {
		t.Fatalf("operator allow --once = %d: %s", rr.Code, rr.Body)
	}
	if rr := do(kgH, http.MethodGet, "/v1/kg/query?corpus=proj", ""); rr.Code != http.StatusOK {
		t.Fatalf("first retry = %d, want 200 (once-grant authorizes): %s", rr.Code, rr.Body)
	}
	if rr := do(kgH, http.MethodGet, "/v1/kg/query?corpus=proj", ""); rr.Code != http.StatusForbidden {
		t.Fatalf("second retry = %d, want 403 (once-grant consumed)", rr.Code)
	}
	if rig.grants.Check(grPeerKey, grantVerbKG, "proj") {
		t.Fatal("consumed once-grant must be gone from the store")
	}
}

// TestGrantDenyLeavesDenied proves the operator "deny" tap drops the pending ask
// and grants nothing (default-deny preserved).
func TestGrantDenyLeavesDenied(t *testing.T) {
	rig := newGrantRig(t, grantAllowList(), grantOperatorList())
	rig.recognize(t, grPeerKey, grPeerFQDN)
	kgH := rig.kgFor(grPeerKey, grPeerFQDN)

	do(kgH, http.MethodGet, "/v1/kg/query?corpus=proj", "") // records opportunity
	if rr := do(rig.grantFor(grOpKey, grOpFQDN), http.MethodPost, "/v1/grant/deny", `{"pubkey":"peer-key","scope":"proj"}`); rr.Code != http.StatusOK {
		t.Fatalf("operator deny = %d: %s", rr.Code, rr.Body)
	}
	// The deny dropped the pending ask and granted nothing (checked before any
	// re-query, which would legitimately re-record the ask for a recognized peer).
	if len(rig.grants.Pending()) != 0 {
		t.Fatal("deny must drop the pending opportunity")
	}
	if rig.grants.Check(grPeerKey, grantVerbKG, "proj") {
		t.Fatal("deny must not write a grant")
	}
	if rr := do(kgH, http.MethodGet, "/v1/kg/query?corpus=proj", ""); rr.Code != http.StatusForbidden {
		t.Fatalf("query after deny = %d, want 403 (still denied)", rr.Code)
	}
}

// TestGrantRevokeDeniesAgain proves a revoked grant no longer authorizes
// (invariant 5: revoke removes).
func TestGrantRevokeDeniesAgain(t *testing.T) {
	rig := newGrantRig(t, grantAllowList(), grantOperatorList())
	rig.recognize(t, grPeerKey, grPeerFQDN)
	kgH := rig.kgFor(grPeerKey, grPeerFQDN)
	opH := rig.grantFor(grOpKey, grOpFQDN)

	do(opH, http.MethodPost, "/v1/grant/allow", `{"pubkey":"peer-key","scope":"proj","once":false}`)
	if rr := do(kgH, http.MethodGet, "/v1/kg/query?corpus=proj", ""); rr.Code != http.StatusOK {
		t.Fatalf("granted query = %d, want 200", rr.Code)
	}
	if rr := do(opH, http.MethodPost, "/v1/grant/revoke", `{"pubkey":"peer-key","scope":"proj"}`); rr.Code != http.StatusOK {
		t.Fatalf("revoke = %d: %s", rr.Code, rr.Body)
	}
	if rr := do(kgH, http.MethodGet, "/v1/kg/query?corpus=proj", ""); rr.Code != http.StatusForbidden {
		t.Fatalf("query after revoke = %d, want 403", rr.Code)
	}
}

// TestGrantOperatorGate403 proves invariant 4: the admin surface is operator-
// gated deny-by-default, and fail-closed on an empty operator ACL.
func TestGrantOperatorGate403(t *testing.T) {
	rig := newGrantRig(t, grantAllowList(), grantOperatorList())
	// A non-operator (the peer identity) is refused on every admin route.
	nonOp := rig.grantFor(grPeerKey, grPeerFQDN)
	for _, tc := range []struct{ method, path, body string }{
		{http.MethodGet, "/v1/grant/pending", ""},
		{http.MethodPost, "/v1/grant/allow", `{"pubkey":"peer-key","scope":"proj"}`},
		{http.MethodPost, "/v1/grant/deny", `{"pubkey":"peer-key","scope":"proj"}`},
		{http.MethodPost, "/v1/grant/revoke", `{"pubkey":"peer-key","scope":"proj"}`},
	} {
		if rr := do(nonOp, tc.method, tc.path, tc.body); rr.Code != http.StatusForbidden {
			t.Fatalf("%s %s = %d, want 403 for non-operator", tc.method, tc.path, rr.Code)
		}
	}
	// The non-operator could not have written a grant.
	if rig.grants.Check(grPeerKey, grantVerbKG, "proj") {
		t.Fatal("a non-operator must never be able to write a grant")
	}

	// An EMPTY operator ACL trusts no one (fail-closed), unlike an open backend ACL.
	empty := newGrantRig(t, grantAllowList(), nil)
	if rr := do(empty.grantFor("anyone", "anyone.mesh"), http.MethodGet, "/v1/grant/pending", ""); rr.Code != http.StatusForbidden {
		t.Fatalf("empty operator ACL must fail closed, got %d", rr.Code)
	}
}

// TestGrantScopeIsolation proves invariant 6: a grant of corpus X does not confer
// corpus Y.
func TestGrantScopeIsolation(t *testing.T) {
	rig := newGrantRig(t, grantAllowList(), grantOperatorList())
	rig.recognize(t, grPeerKey, grPeerFQDN)
	kgH := rig.kgFor(grPeerKey, grPeerFQDN)

	if rr := do(rig.grantFor(grOpKey, grOpFQDN), http.MethodPost, "/v1/grant/allow", `{"pubkey":"peer-key","scope":"X","once":false}`); rr.Code != http.StatusOK {
		t.Fatalf("allow X = %d: %s", rr.Code, rr.Body)
	}
	if rr := do(kgH, http.MethodGet, "/v1/kg/query?corpus=Y", ""); rr.Code != http.StatusForbidden {
		t.Fatalf("query Y = %d, want 403 (grant of X must not confer Y)", rr.Code)
	}
	if rr := do(kgH, http.MethodGet, "/v1/kg/query?corpus=X", ""); rr.Code != http.StatusOK {
		t.Fatalf("query X = %d, want 200 (its own grant)", rr.Code)
	}
}

// TestGrantAuditChainVerifies proves invariant 5: every grant transition lands on
// the shared hash chain and it verifies over request→allow→consume→revoke.
func TestGrantAuditChainVerifies(t *testing.T) {
	rig := newGrantRig(t, grantAllowList(), grantOperatorList())
	rig.recognize(t, grPeerKey, grPeerFQDN)
	kgH := rig.kgFor(grPeerKey, grPeerFQDN)
	opH := rig.grantFor(grOpKey, grOpFQDN)

	do(kgH, http.MethodGet, "/v1/kg/query?corpus=proj", "")                                         // request (opportunity) + deny
	do(opH, http.MethodPost, "/v1/grant/allow", `{"pubkey":"peer-key","scope":"proj","once":true}`) // allow
	do(kgH, http.MethodGet, "/v1/kg/query?corpus=proj", "")                                         // consume + allow
	do(opH, http.MethodPost, "/v1/grant/allow", `{"pubkey":"peer-key","scope":"docs","once":false}`)
	do(opH, http.MethodPost, "/v1/grant/revoke", `{"pubkey":"peer-key","scope":"docs"}`) // revoke

	res, err := policy.VerifyChain(bytes.NewReader(rig.buf.Bytes()))
	if err != nil {
		t.Fatalf("VerifyChain error: %v", err)
	}
	if !res.OK {
		t.Fatalf("grant audit chain broke at seq %d: %s", res.BreakSeq, res.Reason)
	}
	if res.Count < 5 {
		t.Fatalf("want >=5 audited transitions across request→allow→consume→revoke, got %d", res.Count)
	}

	// The pending endpoint reflects the store for the operator.
	rr := do(opH, http.MethodGet, "/v1/grant/pending", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("pending = %d", rr.Code)
	}
	var out grantListResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("pending bad json: %v", err)
	}
}
