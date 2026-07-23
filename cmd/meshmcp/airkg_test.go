package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xrey167/meshmcp/air"
	"github.com/xrey167/meshmcp/air/knowstore"
	"github.com/xrey167/meshmcp/federation"
	"github.com/xrey167/meshmcp/kg"
	"github.com/xrey167/meshmcp/policy"
)

// kgTestRig is a served air-kg handler over a real facade (real store + real
// audit chain) and a real ACL, plus the buffer the audit chain is written to —
// so the governance tests exercise the actual deny-by-default semantics, not a
// mock. identify is fixed per rig to the chosen caller identity.
type kgTestRig struct {
	h     http.Handler
	audit *bytes.Buffer
}

func newKGRig(t *testing.T, pubKey, fqdn string, allow []string, grants kgGrants) kgTestRig {
	t.Helper()
	st, err := kg.Open(filepath.Join(t.TempDir(), "kg.jsonl"), func() string { return "t" })
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	var buf bytes.Buffer
	audit := policy.NewAuditLog(&buf, func() string { return "t" })
	f := knowstore.New(st, audit)
	identify := func(*http.Request) (string, string) { return pubKey, fqdn }
	bridge := &kgGrantBridge{static: grants, audit: audit}
	return kgTestRig{h: kgControlHandler(f, identify, newACL(allow), bridge, nil, audit), audit: &buf}
}

// newKGRigShared builds TWO handlers over ONE facade/store/audit chain, each
// fixed to a different caller identity — the shape for proving two granted
// callers are isolated on a single kg.jsonl.
func newKGRigShared(t *testing.T, allow []string, grants kgGrants, callers [][2]string) []kgTestRig {
	t.Helper()
	st, err := kg.Open(filepath.Join(t.TempDir(), "kg.jsonl"), func() string { return "t" })
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	var buf bytes.Buffer
	audit := policy.NewAuditLog(&buf, func() string { return "t" })
	f := knowstore.New(st, audit)
	rigs := make([]kgTestRig, 0, len(callers))
	for _, c := range callers {
		pubKey, fqdn := c[0], c[1]
		identify := func(*http.Request) (string, string) { return pubKey, fqdn }
		bridge := &kgGrantBridge{static: grants, audit: audit}
		rigs = append(rigs, kgTestRig{h: kgControlHandler(f, identify, newACL(allow), bridge, nil, audit), audit: &buf})
	}
	return rigs
}

// do runs one request against the rig and returns the recorder.
func (r kgTestRig) do(method, target string, body string) *httptest.ResponseRecorder {
	rr := httptest.NewRecorder()
	var rdr *strings.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	} else {
		rdr = strings.NewReader("")
	}
	req := httptest.NewRequest(method, target, rdr)
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/json")
	}
	r.h.ServeHTTP(rr, req)
	return rr
}

// TestAirKGGovernedRoundTrip proves an allowed, exactly-granted identity can
// assert then read the fact back via query and neighbors.
func TestAirKGGovernedRoundTrip(t *testing.T) {
	rig := newKGRig(t, "key1", "caller.mesh", []string{"pubkey:key1"},
		kgGrants{{pattern: "pubkey:key1", corpora: []string{"notes"}}})

	// assert
	rr := rig.do(http.MethodPost, "/v1/kg/assert", `{"corpus":"notes","s":"atlas","p":"ownedBy","o":"platform"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("assert status = %d, want 200: %s", rr.Code, rr.Body)
	}
	var rcpt struct {
		KnowHash string `json:"know_hash"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &rcpt); err != nil || !strings.HasPrefix(rcpt.KnowHash, "kh_") {
		t.Fatalf("assert receipt = %s (err %v), want kh_ hash", rr.Body, err)
	}

	// query
	rr = rig.do(http.MethodGet, "/v1/kg/query?corpus=notes", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("query status = %d, want 200: %s", rr.Code, rr.Body)
	}
	var qout kgRecordsResp
	if err := json.Unmarshal(rr.Body.Bytes(), &qout); err != nil {
		t.Fatalf("query bad json: %v", err)
	}
	if len(qout.Records) != 1 || qout.Records[0].S != "atlas" || qout.Records[0].Peer != "caller.mesh" {
		t.Fatalf("query = %+v, want one atlas triple stamped caller.mesh", qout.Records)
	}

	// neighbors
	rr = rig.do(http.MethodGet, "/v1/kg/neighbors?corpus=notes&node=platform", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("neighbors status = %d, want 200: %s", rr.Code, rr.Body)
	}
	var nout kgRecordsResp
	_ = json.Unmarshal(rr.Body.Bytes(), &nout)
	if len(nout.Records) != 1 || nout.Records[0].O != "platform" {
		t.Fatalf("neighbors = %+v, want the atlas->platform edge", nout.Records)
	}
}

// TestAirKGReachabilityDenied proves a caller absent from the endpoint ACL is
// refused before the store is touched, and the refusal is audited as a deny.
func TestAirKGReachabilityDenied(t *testing.T) {
	rig := newKGRig(t, "key1", "caller.mesh", []string{"pubkey:someone-else"},
		kgGrants{{pattern: "pubkey:key1", corpora: []string{"notes"}}})

	for _, tc := range []struct{ method, target, body string }{
		{http.MethodPost, "/v1/kg/assert", `{"corpus":"notes","s":"a","p":"b","o":"c"}`},
		{http.MethodGet, "/v1/kg/query?corpus=notes", ""},
	} {
		rr := rig.do(tc.method, tc.target, tc.body)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("%s %s status = %d, want 403", tc.method, tc.target, rr.Code)
		}
	}
	// Nothing was written and the ACL deny was audited.
	if strings.Contains(rig.audit.String(), `"decision":"allow"`) {
		t.Fatalf("denied caller produced an allow record:\n%s", rig.audit.String())
	}
	if !strings.Contains(rig.audit.String(), `"decision":"deny"`) {
		t.Fatalf("ACL refusal not audited:\n%s", rig.audit.String())
	}
}

// TestAirKGWriteNeedsExactGrant proves the facade's deny-by-default write rule is
// enforced end-to-end: a reachable caller holding only a broad read glob may READ
// the corpus but its write is refused 403 and audited as a know.assert deny.
func TestAirKGWriteNeedsExactGrant(t *testing.T) {
	rig := newKGRig(t, "key1", "caller.mesh", []string{"pubkey:key1"},
		kgGrants{{pattern: "pubkey:key1", corpora: []string{"acme/*"}}}) // glob: read-only power

	// Write to an exact corpus the glob does not grant for writes → 403.
	rr := rig.do(http.MethodPost, "/v1/kg/assert", `{"corpus":"acme/product","s":"x","p":"y","o":"z"}`)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("glob-only write status = %d, want 403: %s", rr.Code, rr.Body)
	}
	// The read side of the same glob still works (deny-by-default is about writes
	// being strictly narrower than reads).
	rr = rig.do(http.MethodGet, "/v1/kg/query?corpus=acme/product", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("glob read status = %d, want 200: %s", rr.Code, rr.Body)
	}
	// The denied write was audited as a know.assert deny.
	log := rig.audit.String()
	if !strings.Contains(log, `"method":"know.assert"`) || !strings.Contains(log, `"decision":"deny"`) {
		t.Fatalf("denied write not audited as know.assert deny:\n%s", log)
	}
}

// TestAirKGSubgraph proves the k-hop subgraph endpoint assembles a bounded
// neighborhood from governed reads.
func TestAirKGSubgraph(t *testing.T) {
	rig := newKGRig(t, "key1", "caller.mesh", []string{"pubkey:key1"},
		kgGrants{{pattern: "pubkey:key1", corpora: []string{"notes"}}})

	for _, spo := range [][3]string{
		{"atlas", "ownedBy", "platform"},
		{"platform", "leads", "dana"},
		{"dana", "reportsTo", "erin"},
	} {
		body := `{"corpus":"notes","s":"` + spo[0] + `","p":"` + spo[1] + `","o":"` + spo[2] + `"}`
		if rr := rig.do(http.MethodPost, "/v1/kg/assert", body); rr.Code != http.StatusOK {
			t.Fatalf("seed assert %v: %d %s", spo, rr.Code, rr.Body)
		}
	}

	rr := rig.do(http.MethodGet, "/v1/kg/subgraph?corpus=notes&seed=atlas&hops=2", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("subgraph status = %d, want 200: %s", rr.Code, rr.Body)
	}
	var sg air.KGSubgraph
	if err := json.Unmarshal(rr.Body.Bytes(), &sg); err != nil {
		t.Fatalf("subgraph bad json: %v", err)
	}
	// 2 hops from atlas: atlas->platform, platform->dana (dana->erin is 3 hops).
	if len(sg.Triples) != 2 {
		t.Fatalf("2-hop subgraph = %d edges, want 2: %+v", len(sg.Triples), sg.Triples)
	}
}

// TestAirKGSubgraph_TraversalCannotCrossCorpusBoundary proves record-level
// subgraph scoping holds through the k-hop assembler: with a path seed→X→Y
// whose first edge lives in a corpus the caller is NOT reading, the traversal
// discovers nothing — an invisible edge cannot be crossed to reach a visible
// one.
func TestAirKGSubgraph_TraversalCannotCrossCorpusBoundary(t *testing.T) {
	rigs := newKGRigShared(t,
		[]string{"pubkey:keyA", "pubkey:keyB"},
		kgGrants{
			{pattern: "pubkey:keyA", corpora: []string{"corpus-a"}},
			{pattern: "pubkey:keyB", corpora: []string{"corpus-b"}},
		},
		[][2]string{{"keyA", "a.mesh"}, {"keyB", "b.mesh"}},
	)
	rigA, rigB := rigs[0], rigs[1]

	// corpus-b holds seed→X; corpus-a holds X→Y.
	if rr := rigB.do(http.MethodPost, "/v1/kg/assert", `{"corpus":"corpus-b","s":"seed","p":"linksTo","o":"X"}`); rr.Code != http.StatusOK {
		t.Fatalf("seed edge: %d %s", rr.Code, rr.Body)
	}
	if rr := rigA.do(http.MethodPost, "/v1/kg/assert", `{"corpus":"corpus-a","s":"X","p":"linksTo","o":"Y"}`); rr.Code != http.StatusOK {
		t.Fatalf("second edge: %d %s", rr.Code, rr.Body)
	}

	// Caller A, reading corpus-a, seeds at "seed": the seed→X edge is corpus-b
	// (invisible), so the walk finds nothing — not even the corpus-a X→Y edge,
	// because the only path to X runs through an invisible edge.
	rr := rigA.do(http.MethodGet, "/v1/kg/subgraph?corpus=corpus-a&seed=seed&hops=4", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("subgraph status = %d: %s", rr.Code, rr.Body)
	}
	var sg air.KGSubgraph
	if err := json.Unmarshal(rr.Body.Bytes(), &sg); err != nil {
		t.Fatal(err)
	}
	if len(sg.Triples) != 0 {
		t.Fatalf("traversal crossed a corpus boundary: %+v", sg.Triples)
	}
}

// TestAirKGServe_TwoGrantedCallersIsolatedOnOneStore proves two callers, each
// granted a different corpus over ONE shared store, cannot see each other's
// facts through any read verb.
func TestAirKGServe_TwoGrantedCallersIsolatedOnOneStore(t *testing.T) {
	rigs := newKGRigShared(t,
		[]string{"pubkey:keyA", "pubkey:keyB"},
		kgGrants{
			{pattern: "pubkey:keyA", corpora: []string{"corpus-a"}},
			{pattern: "pubkey:keyB", corpora: []string{"corpus-b"}},
		},
		[][2]string{{"keyA", "a.mesh"}, {"keyB", "b.mesh"}},
	)
	rigA, rigB := rigs[0], rigs[1]

	if rr := rigA.do(http.MethodPost, "/v1/kg/assert", `{"corpus":"corpus-a","s":"secret-a","p":"is","o":"private"}`); rr.Code != http.StatusOK {
		t.Fatalf("assert a: %d %s", rr.Code, rr.Body)
	}
	if rr := rigB.do(http.MethodPost, "/v1/kg/assert", `{"corpus":"corpus-b","s":"secret-b","p":"is","o":"private"}`); rr.Code != http.StatusOK {
		t.Fatalf("assert b: %d %s", rr.Code, rr.Body)
	}

	// A's wildcard read of its own corpus returns only corpus-a.
	rr := rigA.do(http.MethodGet, "/v1/kg/query?corpus=corpus-a", "")
	var qa kgRecordsResp
	_ = json.Unmarshal(rr.Body.Bytes(), &qa)
	if len(qa.Records) != 1 || qa.Records[0].S != "secret-a" {
		t.Fatalf("caller A sees %+v, want only its own fact", qa.Records)
	}
	// A cannot read corpus-b at all (no grant): 403, and nothing leaks.
	rr = rigA.do(http.MethodGet, "/v1/kg/query?corpus=corpus-b", "")
	if rr.Code != http.StatusForbidden {
		t.Fatalf("cross-corpus read status = %d, want 403", rr.Code)
	}
	if strings.Contains(rr.Body.String(), "secret-b") {
		t.Fatalf("denied read leaked content: %s", rr.Body)
	}
	// And B's mirror-image view holds.
	rr = rigB.do(http.MethodGet, "/v1/kg/query?corpus=corpus-b", "")
	var qb kgRecordsResp
	_ = json.Unmarshal(rr.Body.Bytes(), &qb)
	if len(qb.Records) != 1 || qb.Records[0].S != "secret-b" {
		t.Fatalf("caller B sees %+v, want only its own fact", qb.Records)
	}
}

// TestAirKGSupersede_EndpointRoundTrip drives the supersede wire verb: assert,
// supersede via the endpoint, and confirm the replacement is active while the
// original replays at as-of.
func TestAirKGSupersede_EndpointRoundTrip(t *testing.T) {
	rig := newKGRig(t, "key1", "caller.mesh", []string{"pubkey:key1"},
		kgGrants{{pattern: "pubkey:key1", corpora: []string{"notes"}}})

	if rr := rig.do(http.MethodPost, "/v1/kg/assert", `{"corpus":"notes","s":"acme","p":"exposure","o":"LOW"}`); rr.Code != http.StatusOK {
		t.Fatalf("assert: %d %s", rr.Code, rr.Body)
	}
	rr := rig.do(http.MethodGet, "/v1/kg/query?corpus=notes", "")
	var q kgRecordsResp
	_ = json.Unmarshal(rr.Body.Bytes(), &q)
	if len(q.Records) != 1 {
		t.Fatalf("seed = %+v", q.Records)
	}
	oldID := q.Records[0].ID

	rr = rig.do(http.MethodPost, "/v1/kg/supersede",
		`{"corpus":"notes","old_id":"`+oldID+`","s":"acme","p":"exposure","o":"HIGH","source":"incident-42"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("supersede status = %d: %s", rr.Code, rr.Body)
	}
	if !strings.Contains(rr.Body.String(), "kh_") {
		t.Fatalf("supersede receipt missing KnowHash: %s", rr.Body)
	}

	rr = rig.do(http.MethodGet, "/v1/kg/query?corpus=notes&p=exposure", "")
	_ = json.Unmarshal(rr.Body.Bytes(), &q)
	if len(q.Records) != 1 || q.Records[0].O != "HIGH" {
		t.Fatalf("active after supersede = %+v, want just HIGH", q.Records)
	}
	// History: as-of the first record's seq, LOW still replays.
	rr = rig.do(http.MethodGet, "/v1/kg/query?corpus=notes&p=exposure&as_of=1", "")
	_ = json.Unmarshal(rr.Body.Bytes(), &q)
	if len(q.Records) != 1 || q.Records[0].O != "LOW" {
		t.Fatalf("as-of history = %+v, want the original LOW", q.Records)
	}
	// A missing/foreign old id is refused 403 (fail-closed, no existence leak).
	rr = rig.do(http.MethodPost, "/v1/kg/supersede",
		`{"corpus":"notes","old_id":"t_nope","s":"a","p":"b","o":"c"}`)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("bogus old-id status = %d, want 403", rr.Code)
	}
}

// TestDelta_SenderFiltersToGrantedCorpus proves the delta WIRE PAYLOAD is
// filtered on the sender: a record outside the requested corpus is absent from
// the bytes on the wire, not merely hidden by a client.
func TestDelta_SenderFiltersToGrantedCorpus(t *testing.T) {
	rigs := newKGRigShared(t,
		[]string{"pubkey:keyA", "pubkey:keyB"},
		kgGrants{
			{pattern: "pubkey:keyA", corpora: []string{"corpus-a"}},
			{pattern: "pubkey:keyB", corpora: []string{"corpus-b"}},
		},
		[][2]string{{"keyA", "a.mesh"}, {"keyB", "b.mesh"}},
	)
	rigA, rigB := rigs[0], rigs[1]

	if rr := rigA.do(http.MethodPost, "/v1/kg/assert", `{"corpus":"corpus-a","s":"visible","p":"is","o":"mine"}`); rr.Code != http.StatusOK {
		t.Fatalf("assert a: %d %s", rr.Code, rr.Body)
	}
	if rr := rigB.do(http.MethodPost, "/v1/kg/assert", `{"corpus":"corpus-b","s":"hidden-fact","p":"is","o":"foreign-secret"}`); rr.Code != http.StatusOK {
		t.Fatalf("assert b: %d %s", rr.Code, rr.Body)
	}

	rr := rigA.do(http.MethodGet, "/v1/kg/delta?corpus=corpus-a&since=0", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("delta status = %d: %s", rr.Code, rr.Body)
	}
	wire := rr.Body.String()
	if strings.Contains(wire, "hidden-fact") || strings.Contains(wire, "foreign-secret") {
		t.Fatalf("out-of-corpus record present in the wire payload:\n%s", wire)
	}
	var out kgRecordsResp
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	if len(out.Records) != 1 || out.Records[0].S != "visible" {
		t.Fatalf("delta = %+v, want only the corpus-a record", out.Records)
	}
}

// TestDelta_CrossOrgEmptyGrantDenied proves the federation gate: a delta
// naming an org is refused when no org grant covers the corpus — with no
// boundary configured at all (deny-by-default) and with a boundary granting a
// different corpus.
func TestDelta_CrossOrgEmptyGrantDenied(t *testing.T) {
	// No boundary configured: any org claim is refused.
	rig := newKGRig(t, "key1", "caller.mesh", []string{"pubkey:key1"},
		kgGrants{{pattern: "pubkey:key1", corpora: []string{"notes"}}})
	rr := rig.do(http.MethodGet, "/v1/kg/delta?corpus=notes&org=acme", "")
	if rr.Code != http.StatusForbidden {
		t.Fatalf("org claim with no boundary: status = %d, want 403", rr.Code)
	}
	if !strings.Contains(rig.audit.String(), `"decision":"deny"`) {
		t.Fatalf("cross-org refusal not audited:\n%s", rig.audit.String())
	}

	// A boundary granting a DIFFERENT corpus still refuses this one.
	st, err := kg.Open(filepath.Join(t.TempDir(), "kg.jsonl"), func() string { return "t" })
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	audit := policy.NewAuditLog(&buf, func() string { return "t" })
	f := knowstore.New(st, audit)
	boundary := federation.NewBoundary([]federation.Grant{{Org: "acme", Corpora: []string{"public-only"}}}, nil, audit)
	identify := func(*http.Request) (string, string) { return "key1", "caller.mesh" }
	bridge := &kgGrantBridge{static: kgGrants{{pattern: "pubkey:key1", corpora: []string{"notes"}}}, audit: audit}
	h := kgControlHandler(f, identify, newACL([]string{"pubkey:key1"}), bridge, boundary, audit)

	rr2 := httptest.NewRecorder()
	h.ServeHTTP(rr2, httptest.NewRequest(http.MethodGet, "/v1/kg/delta?corpus=notes&org=acme", nil))
	if rr2.Code != http.StatusForbidden {
		t.Fatalf("ungranted org corpus: status = %d, want 403: %s", rr2.Code, rr2.Body)
	}
	// The boundary self-audits the denied crossing.
	if !strings.Contains(buf.String(), "corpus not granted to org") {
		t.Fatalf("boundary crossing not audited:\n%s", buf.String())
	}

	// And the granted corpus DOES pass the org gate (while the caller's own
	// corpus grant still applies underneath).
	rr3 := httptest.NewRecorder()
	h.ServeHTTP(rr3, httptest.NewRequest(http.MethodGet, "/v1/kg/delta?corpus=public-only&org=acme", nil))
	if rr3.Code != http.StatusForbidden { // caller has no "public-only" grant → facade denies
		t.Fatalf("org-granted but caller-ungranted corpus: status = %d, want 403 from the facade", rr3.Code)
	}
}

// TestAirKGSyncRoundTrip_TombstoneSurvives drives the full wire round trip:
// assert + delete on the served store, pull the delta with the real client
// decode shape, apply it into a local store, and confirm the tombstone holds.
func TestAirKGSyncRoundTrip_TombstoneSurvives(t *testing.T) {
	rig := newKGRig(t, "key1", "caller.mesh", []string{"pubkey:key1"},
		kgGrants{{pattern: "pubkey:key1", corpora: []string{"notes"}}})

	if rr := rig.do(http.MethodPost, "/v1/kg/assert", `{"corpus":"notes","s":"kept","p":"is","o":"alive"}`); rr.Code != http.StatusOK {
		t.Fatalf("assert kept: %d", rr.Code)
	}
	if rr := rig.do(http.MethodPost, "/v1/kg/assert", `{"corpus":"notes","s":"gone","p":"is","o":"dead"}`); rr.Code != http.StatusOK {
		t.Fatalf("assert gone: %d", rr.Code)
	}
	rr := rig.do(http.MethodGet, "/v1/kg/query?corpus=notes&s=gone", "")
	var q kgRecordsResp
	_ = json.Unmarshal(rr.Body.Bytes(), &q)
	if len(q.Records) != 1 {
		t.Fatalf("seed gone = %+v", q.Records)
	}
	// Tombstone via supersede's sibling: the endpoint has no bare delete verb,
	// so supersede "gone" with a replacement, which tombstones the original.
	rr = rig.do(http.MethodPost, "/v1/kg/supersede",
		`{"corpus":"notes","old_id":"`+q.Records[0].ID+`","s":"gone","p":"is","o":"superseded"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("supersede: %d %s", rr.Code, rr.Body)
	}

	rr = rig.do(http.MethodGet, "/v1/kg/delta?corpus=notes&since=0", "")
	var delta kgRecordsResp
	if err := json.Unmarshal(rr.Body.Bytes(), &delta); err != nil {
		t.Fatal(err)
	}

	local, err := kg.Open(filepath.Join(t.TempDir(), "local.jsonl"), func() string { return "t" })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := local.ApplyDelta(delta.Records); err != nil {
		t.Fatal(err)
	}
	if err := local.Verify(); err != nil {
		t.Fatalf("local chain after apply: %v", err)
	}
	// The tombstoned original is inactive locally; kept + replacement active.
	if got := local.Query("gone", "is", "dead", 0); len(got) != 0 {
		t.Fatalf("tombstone did not survive the wire round trip: %+v", got)
	}
	if got := local.Query("kept", "", "", 0); len(got) != 1 {
		t.Fatalf("kept fact lost in sync: %+v", got)
	}
	if got := local.Query("gone", "is", "superseded", 0); len(got) != 1 {
		t.Fatalf("replacement missing after sync: %+v", got)
	}
}

// TestAirKGAuditChainVerifies runs a mix of allowed and denied ops through the
// served handler, then proves the whole audit ledger they produced is one
// unbroken hash chain under policy.VerifyChain.
func TestAirKGAuditChainVerifies(t *testing.T) {
	rig := newKGRig(t, "key1", "caller.mesh", []string{"pubkey:key1"},
		kgGrants{{pattern: "pubkey:key1", corpora: []string{"notes"}}})

	rig.do(http.MethodPost, "/v1/kg/assert", `{"corpus":"notes","s":"a","p":"b","o":"c"}`)  // allow write
	rig.do(http.MethodPost, "/v1/kg/assert", `{"corpus":"secret","s":"x","p":"y","o":"z"}`) // deny write (no grant)
	rig.do(http.MethodGet, "/v1/kg/query?corpus=notes", "")                                 // allow read
	rig.do(http.MethodGet, "/v1/kg/query?corpus=secret", "")                                // deny read

	res, err := policy.VerifyChain(bytes.NewReader(rig.audit.Bytes()))
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !res.OK {
		t.Fatalf("audit chain not intact: %s", res.Reason)
	}
	if res.Count != 4 {
		t.Fatalf("audit records = %d, want 4 (2 writes + 2 reads, allow and deny)", res.Count)
	}
}

// TestKGGrantsCorporaFor covers the identity→corpora mapping: union across
// matching patterns, deny-by-default for an unmatched or unidentifiable caller.
func TestKGGrantsCorporaFor(t *testing.T) {
	g := kgGrants{
		{pattern: "pubkey:key1", corpora: []string{"notes", "acme/product"}},
		{pattern: "*.mesh", corpora: []string{"public"}},
	}
	got := g.corporaFor("key1", "caller.mesh")
	if len(got) != 3 { // notes, acme/product (key match) + public (fqdn glob)
		t.Fatalf("union corpora = %v, want 3", got)
	}
	if c := g.corporaFor("other", "nomatch.example"); c != nil {
		t.Fatalf("unmatched caller granted %v, want none", c)
	}
	if c := g.corporaFor("", ""); c != nil {
		t.Fatalf("unidentifiable caller granted %v, want none", c)
	}
}

// TestAirKGClientRoundTrip drives the real client path (kgDo) against the real
// handler over an httptest server, proving request marshaling and response
// decoding round-trip end to end without a mesh.
func TestAirKGClientRoundTrip(t *testing.T) {
	rig := newKGRig(t, "key1", "caller.mesh", []string{"pubkey:key1"},
		kgGrants{{pattern: "pubkey:key1", corpora: []string{"notes"}}})
	ts := httptest.NewServer(rig.h)
	defer ts.Close()
	tsURL, _ := url.Parse(ts.URL)
	// A client that routes the placeholder air-kg host to the test server, exactly
	// as airControlHTTP routes it to the mesh endpoint in production — so kgDo's
	// real request path is exercised without a mesh.
	client := &http.Client{Transport: &http.Transport{
		DialContext: func(_ context.Context, _, _ string) (net.Conn, error) { return net.Dial("tcp", tsURL.Host) },
	}}

	body, _ := json.Marshal(kgAssertBody{Corpus: "notes", S: "atlas", P: "ownedBy", O: "platform"})
	raw, err := kgDo(client, http.MethodPost, "/v1/kg/assert", nil, body)
	if err != nil {
		t.Fatalf("client assert: %v", err)
	}
	var rcpt kgReceiptView
	if err := json.Unmarshal(raw, &rcpt); err != nil || rcpt.Triple.S != "atlas" {
		t.Fatalf("client assert receipt = %s (err %v)", raw, err)
	}

	q := url.Values{}
	q.Set("corpus", "notes")
	raw, err = kgDo(client, http.MethodGet, "/v1/kg/query", q, nil)
	if err != nil {
		t.Fatalf("client query: %v", err)
	}
	var out kgRecordsResp
	if err := json.Unmarshal(raw, &out); err != nil || len(out.Records) != 1 {
		t.Fatalf("client query = %s (err %v), want 1 record", raw, err)
	}
}
