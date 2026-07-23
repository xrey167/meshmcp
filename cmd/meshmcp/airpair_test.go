package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/xrey167/meshmcp/air"
	"github.com/xrey167/meshmcp/policy"
)

func pairTestNowCLI() time.Time { return time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC) }

// fixedIdentify returns a handler identity func that always resolves to one peer.
func fixedIdentify(pubKey, fqdn string) func(*http.Request) (string, string) {
	return func(*http.Request) (string, string) { return pubKey, fqdn }
}

// newPairRig builds a pairing handler over a real store in a temp dir. identify
// is the caller identity; operator is the ACL that gates approve/deny/revoke.
func newPairRig(t *testing.T, identify func(*http.Request) (string, string), operator acl) (*air.PairedStore, http.Handler, *bytes.Buffer) {
	t.Helper()
	store, err := air.OpenPairedStore(t.TempDir() + "/paired.json")
	if err != nil {
		t.Fatalf("OpenPairedStore: %v", err)
	}
	var buf bytes.Buffer
	audit := policy.NewAuditLog(&buf, func() string { return "t" })
	h := pairControlHandler(store, identify, operator, newRingLimiter(pairRatePerMin), pairAuditFunc(audit))
	return store, h, &buf
}

func do(h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	rr := httptest.NewRecorder()
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, path, nil)
	} else {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
	}
	h.ServeHTTP(rr, r)
	return rr
}

// TestPairRequestFromUnallowedPeerGrantsNothing proves an un-allowed peer can
// queue a request (verified identity recorded, not body-supplied) but is
// granted no recognition by the act of asking.
func TestPairRequestFromUnallowedPeerGrantsNothing(t *testing.T) {
	// Operator ACL does NOT list the requester — it is un-allowed, as a new peer
	// always is. It must still be able to ask.
	store, h, _ := newPairRig(t, fixedIdentify("newpeer-key", "newpeer.mesh"), newACL([]string{"pubkey:operator-key"}))

	// The body carries a forged public_key; the handler must ignore it and use
	// the VERIFIED transport identity.
	rr := do(h, http.MethodPost, "/v1/pair/request", `{"label":"my laptop","public_key":"FORGED"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("request status = %d, want 200: %s", rr.Code, rr.Body)
	}
	var out struct{ Status, You string }
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("bad json: %v", err)
	}
	if out.Status != string(air.StatusPending) {
		t.Fatalf("status = %q, want pending", out.Status)
	}
	pend := store.Pending()
	if len(pend) != 1 || pend[0].PublicKey != "newpeer-key" || pend[0].Label != "my laptop" {
		t.Fatalf("verified identity not recorded (or body-supplied key leaked): %+v", pend)
	}
	// Grants nothing.
	if store.Recognized("newpeer-key", "newpeer.mesh") {
		t.Fatalf("asking must not confer recognition")
	}
}

// TestPairRequestRequiresVerifiedKey proves an unidentifiable peer cannot pair.
func TestPairRequestRequiresVerifiedKey(t *testing.T) {
	_, h, _ := newPairRig(t, fixedIdentify("", ""), newACL([]string{"pubkey:operator-key"}))
	rr := do(h, http.MethodPost, "/v1/pair/request", "")
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for a keyless peer", rr.Code)
	}
}

// TestPairApproveRecognizesAndStatusFlips proves an operator approval moves a
// pending request into the recognized set, and the peer's own status flips.
func TestPairApproveRecognizesAndStatusFlips(t *testing.T) {
	// The requester asks via a requester-identified handler…
	store, reqH, _ := newPairRig(t, fixedIdentify("peerX", "x.mesh"), newACL([]string{"pubkey:op"}))
	if rr := do(reqH, http.MethodPost, "/v1/pair/request", `{"label":"x"}`); rr.Code != http.StatusOK {
		t.Fatalf("request: %d %s", rr.Code, rr.Body)
	}

	// …and the operator approves via an operator-identified handler over the SAME
	// store (mirrors the operator connecting as an allowed identity).
	opH := pairControlHandler(store, fixedIdentify("op", "op.mesh"), newACL([]string{"pubkey:op"}), newRingLimiter(pairRatePerMin), nil)
	if rr := do(opH, http.MethodPost, "/v1/pair/approve", `{"pubkey":"peerX"}`); rr.Code != http.StatusOK {
		t.Fatalf("approve: %d %s", rr.Code, rr.Body)
	}
	if !store.Recognized("peerX", "x.mesh") {
		t.Fatalf("approved peer must be recognized")
	}
	// The requester polling its own status now sees approved.
	rr := do(reqH, http.MethodGet, "/v1/pair/status", "")
	var out struct{ Status string }
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	if out.Status != string(air.StatusApproved) {
		t.Fatalf("requester status = %q, want approved", out.Status)
	}
}

// TestPairAdminRefusesNonOperator proves approve/deny/revoke/pending are gated
// deny-by-default: an un-allowed caller is refused 403 on every one.
func TestPairAdminRefusesNonOperator(t *testing.T) {
	// Caller is "intruder", operator ACL lists only "operator-key".
	store, h, _ := newPairRig(t, fixedIdentify("intruder-key", "intruder.mesh"), newACL([]string{"pubkey:operator-key"}))
	// Seed a pending request directly so approve has something to target.
	if _, _, err := store.Request(air.VerifiedIdentity{PublicKey: "victim", FQDN: "v.mesh"}, "", pairTestNowCLI()); err != nil {
		t.Fatalf("seed: %v", err)
	}
	for _, tc := range []struct {
		method, path, body string
	}{
		{http.MethodGet, "/v1/pair/pending", ""},
		{http.MethodPost, "/v1/pair/approve", `{"pubkey":"victim"}`},
		{http.MethodPost, "/v1/pair/deny", `{"pubkey":"victim"}`},
		{http.MethodPost, "/v1/pair/revoke", `{"pubkey":"victim"}`},
	} {
		rr := do(h, tc.method, tc.path, tc.body)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("%s %s = %d, want 403 for non-operator", tc.method, tc.path, rr.Code)
		}
	}
	// The un-allowed caller could not approve anyone.
	if store.Recognized("victim", "v.mesh") {
		t.Fatalf("non-operator must never be able to recognize a peer")
	}
}

// TestPairEmptyOperatorFailsClosed proves an EMPTY operator ACL trusts no one on
// the admin surface (unlike an open-by-omission backend ACL).
func TestPairEmptyOperatorFailsClosed(t *testing.T) {
	_, h, _ := newPairRig(t, fixedIdentify("anyone", "anyone.mesh"), newACL(nil))
	rr := do(h, http.MethodGet, "/v1/pair/pending", "")
	if rr.Code != http.StatusForbidden {
		t.Fatalf("empty operator ACL must fail closed on admin surface, got %d", rr.Code)
	}
}

// TestPairRecognitionIsNotControlAccess proves the boundary: a recognized
// (paired) peer is still denied on the privileged control endpoint unless it is
// separately on the control Allow. Pairing never widens the control ACL.
func TestPairRecognitionIsNotControlAccess(t *testing.T) {
	store, _, _ := newPairRig(t, fixedIdentify("op", "op.mesh"), newACL([]string{"pubkey:op"}))
	// Recognize the peer directly.
	if _, _, err := store.Request(air.VerifiedIdentity{PublicKey: "paired-key", FQDN: "paired.mesh"}, "", pairTestNowCLI()); err != nil {
		t.Fatalf("seed request: %v", err)
	}
	if _, err := store.Approve("paired-key", "op.mesh", pairTestNowCLI()); err != nil {
		t.Fatalf("approve: %v", err)
	}
	if !store.Recognized("paired-key", "paired.mesh") {
		t.Fatalf("precondition: peer should be recognized")
	}

	// The control endpoint's allow does NOT list the paired peer. Being paired
	// must not let it list/steer sessions.
	ctl := &fakeAirControl{list: []AirSession{{Backend: "fs", ID: "1"}}}
	controlAllow := newACL([]string{"pubkey:someone-else"})
	ch := airControlHandler(ctl, fixedIdentify("paired-key", "paired.mesh"), controlAllow, newACL(nil), nil)
	rr := do(ch, http.MethodGet, "/v1/sessions", "")
	if rr.Code != http.StatusForbidden {
		t.Fatalf("recognized peer must still be denied on control endpoint, got %d", rr.Code)
	}
}

// TestPairRequestRateLimited proves a burst of pair requests from one identity
// is throttled (the endpoint is DoS-resistant against un-allowed callers).
func TestPairRequestRateLimited(t *testing.T) {
	store, err := air.OpenPairedStore(t.TempDir() + "/paired.json")
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	// Burst of 1: the first request passes, the next is rate-limited.
	h := pairControlHandler(store, fixedIdentify("flooder", "flood.mesh"), newACL([]string{"pubkey:op"}), newRingLimiter(1), nil)
	if rr := do(h, http.MethodPost, "/v1/pair/request", ""); rr.Code != http.StatusOK {
		t.Fatalf("first request = %d, want 200", rr.Code)
	}
	got429 := false
	for i := 0; i < 5; i++ {
		if rr := do(h, http.MethodPost, "/v1/pair/request", ""); rr.Code == http.StatusTooManyRequests {
			got429 = true
			break
		}
	}
	if !got429 {
		t.Fatalf("expected a burst of pair requests to be rate-limited")
	}
}

// TestPairAuditChainVerifies proves every pairing transition lands on the shared
// hash chain and the chain verifies over request→approve→revoke.
func TestPairAuditChainVerifies(t *testing.T) {
	store, reqH, buf := newPairRig(t, fixedIdentify("peerA", "a.mesh"), newACL([]string{"pubkey:op"}))
	audit := policy.NewAuditLog(buf, func() string { return "t" })
	// Rebuild handlers sharing one audit log so all records chain together.
	reqH = pairControlHandler(store, fixedIdentify("peerA", "a.mesh"), newACL([]string{"pubkey:op"}), newRingLimiter(pairRatePerMin), pairAuditFunc(audit))
	opH := pairControlHandler(store, fixedIdentify("op", "op.mesh"), newACL([]string{"pubkey:op"}), newRingLimiter(pairRatePerMin), pairAuditFunc(audit))

	if rr := do(reqH, http.MethodPost, "/v1/pair/request", `{"label":"a"}`); rr.Code != http.StatusOK {
		t.Fatalf("request: %d", rr.Code)
	}
	if rr := do(opH, http.MethodPost, "/v1/pair/approve", `{"pubkey":"peerA"}`); rr.Code != http.StatusOK {
		t.Fatalf("approve: %d %s", rr.Code, rr.Body)
	}
	if rr := do(opH, http.MethodPost, "/v1/pair/revoke", `{"pubkey":"peerA"}`); rr.Code != http.StatusOK {
		t.Fatalf("revoke: %d %s", rr.Code, rr.Body)
	}
	res, err := policy.VerifyChain(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("VerifyChain error: %v", err)
	}
	if !res.OK {
		t.Fatalf("pairing audit chain broke at seq %d: %s", res.BreakSeq, res.Reason)
	}
	if res.Count < 3 {
		t.Fatalf("want >=3 audited transitions, got %d", res.Count)
	}
}

// TestPairJoinClientRoundTrip exercises the `air join` client helpers against an
// httptest server, mirroring aircontrol_test's client round-trip.
func TestPairJoinClientRoundTrip(t *testing.T) {
	store, h, _ := newPairRig(t, fixedIdentify("joiner", "joiner.mesh"), newACL([]string{"pubkey:op"}))
	ts := httptest.NewServer(h)
	defer ts.Close()
	tsURL, _ := url.Parse(ts.URL)
	// A client that dials the test server regardless of the "air-control" host,
	// the same indirection airControlHTTP uses over the mesh.
	hc := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return net.Dial(network, tsURL.Host)
		},
	}}

	status, you, err := postPairRequest(context.Background(), hc, "my phone")
	if err != nil {
		t.Fatalf("postPairRequest: %v", err)
	}
	if status != string(air.StatusPending) || you != "joiner.mesh" {
		t.Fatalf("request round-trip: status=%q you=%q", status, you)
	}

	// Operator approves out-of-band, then the client polls approved.
	if _, err := store.Approve("joiner", "op.mesh", pairTestNowCLI()); err != nil {
		t.Fatalf("approve: %v", err)
	}
	st, err := getPairStatus(context.Background(), hc)
	if err != nil {
		t.Fatalf("getPairStatus: %v", err)
	}
	if st.Status != string(air.StatusApproved) {
		t.Fatalf("status after approval = %q, want approved", st.Status)
	}
}
