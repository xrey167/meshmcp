package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/xrey167/meshmcp/air/rag"
	"github.com/xrey167/meshmcp/policy"
)

// newTestRagStore builds an in-memory rag store (no file) seeded with a couple of
// documents across two corpora.
func newTestRagStore(t *testing.T) *ragStore {
	t.Helper()
	s, err := newRagStore("", "backend.mesh", 40, 8, nil)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	if _, err := s.Ingest("handbook", "sec.md",
		"To rotate a leaked API key: revoke the old key immediately, issue a fresh key, and review the audit ledger. Secrets live in environment variables, never in source."); err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if _, err := s.Ingest("private", "salary.md",
		"Executive compensation figures are confidential and stored under lock."); err != nil {
		t.Fatalf("ingest private: %v", err)
	}
	return s
}

// grantsFor returns a ragGrants that grants the given corpora to caller key k1.
func grantsFor(corpora ...string) ragGrants {
	return func(pubKey, fqdn string) policy.CapabilityClaims {
		if pubKey == "k1" {
			return policy.CapabilityClaims{Subject: pubKey, Corpora: corpora}
		}
		return policy.CapabilityClaims{Subject: pubKey}
	}
}

func idFunc(pubKey, fqdn string) func(*http.Request) (string, string) {
	return func(*http.Request) (string, string) { return pubKey, fqdn }
}

func postJSON(h http.Handler, path string, v any) *httptest.ResponseRecorder {
	b, _ := json.Marshal(v)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, path, bytes.NewReader(b)))
	return rr
}

func newAuditBuf() (*policy.AuditLog, *bytes.Buffer) {
	buf := &bytes.Buffer{}
	seq := 0
	log := policy.NewAuditLog(buf, func() string { seq++; return "t" })
	return log, buf
}

// TestRagSearch_GrantedReturnsWrappedHits proves an allowed identity with a
// covering corpus grant gets hits, the chunk text is wrapped in the untrusted
// envelope, and the retrieval is audited allow.
func TestRagSearch_GrantedReturnsWrappedHits(t *testing.T) {
	store := newTestRagStore(t)
	audit, buf := newAuditBuf()
	h := ragHandler(store, idFunc("k1", "caller.mesh"), newACL([]string{"pubkey:k1"}), grantsFor("handbook"), defaultRagCaps(), audit)

	rr := postJSON(h, "/v1/rag/search", ragSearchReq{Corpus: "handbook", Query: "rotate a leaked api key", K: 3})
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body)
	}
	var out struct {
		Count   int         `json:"count"`
		Results []ragResult `json:"results"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("bad json: %v", err)
	}
	if out.Count == 0 {
		t.Fatal("expected hits for a granted corpus")
	}
	// Every returned chunk must be wrapped as UNTRUSTED DATA before it leaves.
	for _, r := range out.Results {
		if !strings.Contains(r.Text, "UNTRUSTED DATA") {
			t.Fatalf("chunk not wrapped untrusted: %q", r.Text)
		}
	}
	// Audited allow with provenance, and the chain verifies.
	if !strings.Contains(buf.String(), `"decision":"allow"`) || !strings.Contains(buf.String(), "know.retrieve") {
		t.Fatalf("retrieval not audited as allow: %s", buf.String())
	}
	if res, _ := policy.VerifyChain(bytes.NewReader(buf.Bytes())); !res.OK {
		t.Fatalf("audit chain broken: %+v", res)
	}
}

// TestRagSearch_DeniesUngrantedCorpus proves deny-by-default: a caller without a
// grant over the requested corpus is refused and audited deny, and no content
// leaks.
func TestRagSearch_DeniesUngrantedCorpus(t *testing.T) {
	store := newTestRagStore(t)
	audit, buf := newAuditBuf()
	// Caller is granted "handbook" but asks for "private".
	h := ragHandler(store, idFunc("k1", "caller.mesh"), newACL([]string{"pubkey:k1"}), grantsFor("handbook"), defaultRagCaps(), audit)

	rr := postJSON(h, "/v1/rag/search", ragSearchReq{Corpus: "private", Query: "compensation", K: 3})
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rr.Code)
	}
	if strings.Contains(rr.Body.String(), "confidential") || strings.Contains(rr.Body.String(), "compensation") {
		t.Fatalf("denied query leaked corpus content: %s", rr.Body)
	}
	if !strings.Contains(buf.String(), `"decision":"deny"`) {
		t.Fatalf("deny not audited: %s", buf.String())
	}
	if res, _ := policy.VerifyChain(bytes.NewReader(buf.Bytes())); !res.OK {
		t.Fatalf("audit chain broken: %+v", res)
	}
}

// TestRagSearch_EmptyGrantDeniedByDefault proves an identity with NO configured
// grant shares nothing, even for an existing corpus.
func TestRagSearch_EmptyGrantDeniedByDefault(t *testing.T) {
	store := newTestRagStore(t)
	h := ragHandler(store, idFunc("k1", "caller.mesh"), newACL([]string{"pubkey:k1"}), grantsFor(), defaultRagCaps(), nil)
	rr := postJSON(h, "/v1/rag/search", ragSearchReq{Corpus: "handbook", Query: "key", K: 3})
	if rr.Code != http.StatusForbidden {
		t.Fatalf("empty grant must deny, status = %d", rr.Code)
	}
}

// TestRagSearch_AdmissionACLDeny proves an identity off the admission ACL cannot
// reach the endpoint at all.
func TestRagSearch_AdmissionACLDeny(t *testing.T) {
	store := newTestRagStore(t)
	h := ragHandler(store, idFunc("stranger", "x.mesh"), newACL([]string{"pubkey:k1"}), grantsFor("handbook"), defaultRagCaps(), nil)
	rr := postJSON(h, "/v1/rag/search", ragSearchReq{Corpus: "handbook", Query: "key", K: 3})
	if rr.Code != http.StatusForbidden {
		t.Fatalf("off-ACL caller must be denied, status = %d", rr.Code)
	}
}

// TestRagSearch_RowCapEnforced proves the server caps returned rows regardless of
// the requested k.
func TestRagSearch_RowCapEnforced(t *testing.T) {
	store := newTestRagStore(t)
	// Ingest enough distinct chunks to exceed a tiny row cap.
	for i := 0; i < 10; i++ {
		store.Ingest("handbook", "doc"+string(rune('a'+i))+".md", "policy note "+strings.Repeat("word ", 60))
	}
	caps := ragCaps{MaxRows: 3, MaxBytes: 1 << 20}
	h := ragHandler(store, idFunc("k1", "caller.mesh"), newACL([]string{"pubkey:k1"}), grantsFor("handbook"), caps, nil)
	rr := postJSON(h, "/v1/rag/search", ragSearchReq{Corpus: "handbook", Query: "policy note word", K: 100})
	var out struct {
		Results []ragResult `json:"results"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	if len(out.Results) > caps.MaxRows {
		t.Fatalf("row cap not enforced: got %d, cap %d", len(out.Results), caps.MaxRows)
	}
}

// TestRagSearch_ByteCapEnforced proves the total-byte cap on returned context:
// with a tiny byte budget only the first (always-admitted) result returns, no
// matter how many hits matched.
func TestRagSearch_ByteCapEnforced(t *testing.T) {
	store := newTestRagStore(t)
	for i := 0; i < 6; i++ {
		store.Ingest("handbook", "cap"+string(rune('a'+i))+".md", "byte cap policy filler "+strings.Repeat("word ", 80))
	}
	caps := ragCaps{MaxRows: 20, MaxBytes: 1} // one byte: only the guaranteed first result fits
	h := ragHandler(store, idFunc("k1", "caller.mesh"), newACL([]string{"pubkey:k1"}), grantsFor("handbook"), caps, nil)
	rr := postJSON(h, "/v1/rag/search", ragSearchReq{Corpus: "handbook", Query: "byte cap policy filler word", K: 20})
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rr.Code, rr.Body)
	}
	var out struct {
		Results []ragResult `json:"results"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	if len(out.Results) != 1 {
		t.Fatalf("byte cap not enforced: got %d results, want exactly the first", len(out.Results))
	}
}

// evalBackend builds an in-process served rag backend and returns a search
// func shaped exactly like the CLI's (real HTTP round trip through the real
// handler), for driving runRagEval without a mesh.
func evalBackend(t *testing.T, grants ragGrants) func(query string, k int) ([]string, error) {
	t.Helper()
	store := newTestRagStore(t)
	h := ragHandler(store, idFunc("k1", "caller.mesh"), newACL([]string{"pubkey:k1"}), grants, defaultRagCaps(), nil)
	return func(query string, k int) ([]string, error) {
		rr := postJSON(h, "/v1/rag/search", ragSearchReq{Corpus: "handbook", Query: query, K: k})
		if rr.Code != http.StatusOK {
			return nil, errStatus(rr.Code, rr.Body.String())
		}
		var out struct {
			Results []ragResult `json:"results"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
			return nil, err
		}
		ids := make([]string, 0, len(out.Results))
		for _, r := range out.Results {
			ids = append(ids, r.ID)
		}
		return ids, nil
	}
}

func errStatus(code int, body string) error {
	return &statusErr{code: code, body: body}
}

type statusErr struct {
	code int
	body string
}

func (e *statusErr) Error() string { return strings.TrimSpace(e.body) }

// TestRagEval_ExitsNonZeroBelowThreshold proves the CI gate: a gold set the
// backend cannot satisfy fails the threshold with a non-nil error, while an
// achievable gold set passes.
func TestRagEval_ExitsNonZeroBelowThreshold(t *testing.T) {
	search := evalBackend(t, grantsFor("handbook"))

	// Deliberately wrong gold: ids that no retrieval can return.
	bad := []rag.EvalCase{{Question: "rotate a leaked api key", Gold: []string{"nonexistent#c0"}}}
	var buf bytes.Buffer
	err := runRagEval(bad, search, 3, 0.5, 0.5, false, &buf)
	if err == nil {
		t.Fatalf("below-threshold eval must fail; output:\n%s", buf.String())
	}
	if !strings.Contains(err.Error(), "below threshold") {
		t.Fatalf("unexpected failure: %v", err)
	}

	// Achievable gold: whatever the search actually returns for the question.
	ids, err := search("rotate a leaked api key", 3)
	if err != nil || len(ids) == 0 {
		t.Fatalf("seed search: ids=%v err=%v", ids, err)
	}
	good := []rag.EvalCase{{Question: "rotate a leaked api key", Gold: ids}}
	buf.Reset()
	if err := runRagEval(good, search, 3, 0.5, 0.5, false, &buf); err != nil {
		t.Fatalf("achievable gold must pass: %v\n%s", err, buf.String())
	}
	if !strings.Contains(buf.String(), "mean precision") {
		t.Fatalf("summary not printed:\n%s", buf.String())
	}
}

// TestRagEval_DeniedCorpusFailsClosed proves an ungranted caller's eval is a
// hard error — never a silent 0.0 score that a threshold of 0 would let pass.
func TestRagEval_DeniedCorpusFailsClosed(t *testing.T) {
	search := evalBackend(t, grantsFor() /* no grants */)
	cases := []rag.EvalCase{{Question: "anything", Gold: []string{"x"}}}
	err := runRagEval(cases, search, 3, 0, 0, false, &bytes.Buffer{})
	if err == nil {
		t.Fatal("denied corpus must fail the eval closed, not score 0.0")
	}
	if !strings.Contains(err.Error(), "search") {
		t.Fatalf("failure must surface the denied search: %v", err)
	}
}

// TestRagEval_EmptyGoldSetRefused proves an empty suite cannot green-light CI.
func TestRagEval_EmptyGoldSetRefused(t *testing.T) {
	if err := runRagEval(nil, func(string, int) ([]string, error) { return nil, nil }, 3, 0, 0, false, &bytes.Buffer{}); err == nil {
		t.Fatal("empty gold set must be an error")
	}
}

// TestRagIngest_RequiresExactWriteGrant proves ingest needs an exact corpus grant
// (a read glob does not confer write), mirroring air/know.Allowed write semantics.
func TestRagIngest_RequiresExactWriteGrant(t *testing.T) {
	store := newTestRagStore(t)
	audit, buf := newAuditBuf()
	// Caller has a broad read glob "*", which must NOT confer write.
	h := ragHandler(store, idFunc("k1", "caller.mesh"), newACL([]string{"pubkey:k1"}), grantsFor("*"), defaultRagCaps(), audit)
	rr := postJSON(h, "/v1/rag/ingest", ragIngestReq{Corpus: "handbook", Docs: []ragWireDoc{{ID: "x", Text: "hello world"}}})
	if rr.Code != http.StatusForbidden {
		t.Fatalf("broad read grant must not allow write, status = %d", rr.Code)
	}
	if !strings.Contains(buf.String(), "know.extract") || !strings.Contains(buf.String(), `"decision":"deny"`) {
		t.Fatalf("ingest deny not audited: %s", buf.String())
	}
}

// TestRagRoundTrip_IngestThenSearch is the client-shape round trip: ingest a doc
// with an exact grant, then retrieve it, over one handler.
func TestRagRoundTrip_IngestThenSearch(t *testing.T) {
	store, err := newRagStore("", "backend.mesh", 40, 8, nil)
	if err != nil {
		t.Fatal(err)
	}
	h := ragHandler(store, idFunc("k1", "caller.mesh"), newACL([]string{"pubkey:k1"}), grantsFor("kb"), defaultRagCaps(), nil)

	// Ingest.
	rr := postJSON(h, "/v1/rag/ingest", ragIngestReq{Corpus: "kb", Docs: []ragWireDoc{
		{ID: "note.md", Text: "The widget throws error code E7788 when the cache is cold. Warm it first."},
	}})
	if rr.Code != http.StatusOK {
		t.Fatalf("ingest status = %d: %s", rr.Code, rr.Body)
	}
	var ing struct {
		Chunks int `json:"chunks"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &ing)
	if ing.Chunks == 0 {
		t.Fatal("ingest produced no chunks")
	}

	// Search by the exact identifier — the BM25 arm should recover it even though
	// the lexical embedder scores the rare token poorly.
	rr = postJSON(h, "/v1/rag/search", ragSearchReq{Corpus: "kb", Query: "E7788", K: 5})
	if rr.Code != http.StatusOK {
		t.Fatalf("search status = %d: %s", rr.Code, rr.Body)
	}
	var out struct {
		Count   int         `json:"count"`
		Results []ragResult `json:"results"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("bad json: %v", err)
	}
	if out.Count == 0 {
		t.Fatal("round-trip search returned nothing for an exact-token query")
	}
}
