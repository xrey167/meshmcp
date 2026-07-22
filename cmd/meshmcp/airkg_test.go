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
	return kgTestRig{h: kgControlHandler(f, identify, newACL(allow), bridge, audit), audit: &buf}
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

// TestAirKGAuditChainVerifies runs a mix of allowed and denied ops through the
// served handler, then proves the whole audit ledger they produced is one
// unbroken hash chain under policy.VerifyChain.
func TestAirKGAuditChainVerifies(t *testing.T) {
	rig := newKGRig(t, "key1", "caller.mesh", []string{"pubkey:key1"},
		kgGrants{{pattern: "pubkey:key1", corpora: []string{"notes"}}})

	rig.do(http.MethodPost, "/v1/kg/assert", `{"corpus":"notes","s":"a","p":"b","o":"c"}`)         // allow write
	rig.do(http.MethodPost, "/v1/kg/assert", `{"corpus":"secret","s":"x","p":"y","o":"z"}`)        // deny write (no grant)
	rig.do(http.MethodGet, "/v1/kg/query?corpus=notes", "")                                        // allow read
	rig.do(http.MethodGet, "/v1/kg/query?corpus=secret", "")                                       // deny read

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
