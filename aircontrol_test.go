package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/xrey167/meshmcp/session"
)

// fakeAirControl is an in-memory airController for handler tests.
type fakeAirControl struct {
	list       []AirSession
	steers     []string // "backend/id/method" of accepted steers
	callers    []string // "pubKey/fqdn" seen by steer
	err        error    // returned by steer
	denyOnFqdn string   // if set, steer/sessions deny this caller fqdn on backend "fs"
}

func (f *fakeAirControl) sessions(pubKey, fqdn string) []AirSession {
	if f.denyOnFqdn != "" && fqdn == f.denyOnFqdn {
		var out []AirSession
		for _, s := range f.list {
			if s.Backend != "fs" {
				out = append(out, s)
			}
		}
		return out
	}
	return f.list
}
func (f *fakeAirControl) catalog(pubKey, fqdn string) AirCatalog {
	var eps []AirCatalogEntry
	for _, s := range f.list {
		if f.denyOnFqdn != "" && fqdn == f.denyOnFqdn && s.Backend == "fs" {
			continue
		}
		eps = append(eps, AirCatalogEntry{Name: s.Backend, Address: "100.64.0.2:9101", Transport: "stdio", Steerable: true})
	}
	return AirCatalog{Service: "meshmcp", Version: "test", Endpoints: eps}
}
func (f *fakeAirControl) steer(pubKey, fqdn, backend, id, method string, _ any) error {
	if f.denyOnFqdn != "" && fqdn == f.denyOnFqdn && backend == "fs" {
		return errBackendForbidden
	}
	if f.err != nil {
		return f.err
	}
	f.callers = append(f.callers, pubKey+"/"+fqdn)
	f.steers = append(f.steers, backend+"/"+id+"/"+method)
	return nil
}

func newTestHandler(c airController, allowCaller bool) http.Handler {
	id := func(*http.Request) (string, string) { return "key1", "caller.mesh" }
	// The Air endpoint is default-deny: allowing the caller requires an explicit
	// ACL entry for its key; the deny case uses an ACL that does not list it.
	allow := newACL([]string{"pubkey:someone-else"})
	if allowCaller {
		allow = newACL([]string{"pubkey:key1"})
	}
	return airControlHandler(c, id, allow, newACL(nil), nil)
}

func TestAirControlSessions(t *testing.T) {
	c := &fakeAirControl{list: []AirSession{{Backend: "fs", ID: "9f2a", Peer: "agent.mesh", AgeSec: 4}}}
	rr := httptest.NewRecorder()
	newTestHandler(c, true).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/sessions", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body)
	}
	var out struct {
		Sessions []AirSession `json:"sessions"`
		You      string       `json:"you"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("bad json: %v", err)
	}
	if len(out.Sessions) != 1 || out.Sessions[0].Backend != "fs" || out.Sessions[0].ID != "9f2a" {
		t.Fatalf("unexpected sessions: %+v", out.Sessions)
	}
	if out.You != "caller.mesh" {
		t.Fatalf("you = %q, want caller.mesh", out.You)
	}
}

func TestAirControlSteerRoutes(t *testing.T) {
	c := &fakeAirControl{}
	rr := httptest.NewRecorder()
	body := `{"backend":"fs","id":"9f2a","method":"notifications/air/steer","params":{"text":"focus"}}`
	newTestHandler(c, true).ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/v1/steer", strings.NewReader(body)))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body)
	}
	if len(c.steers) != 1 || c.steers[0] != "fs/9f2a/notifications/air/steer" {
		t.Fatalf("steer not routed: %v", c.steers)
	}
}

func TestAirControlSteerUnknownSession(t *testing.T) {
	c := &fakeAirControl{err: session.ErrNoSession}
	rr := httptest.NewRecorder()
	body := `{"backend":"fs","id":"nope","method":"notifications/air/steer"}`
	newTestHandler(c, true).ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/v1/steer", strings.NewReader(body)))
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rr.Code)
	}
}

func TestAirControlSteerUnknownBackend(t *testing.T) {
	c := &fakeAirControl{err: errNoBackend}
	rr := httptest.NewRecorder()
	body := `{"backend":"ghost","id":"9f2a","method":"notifications/air/steer"}`
	newTestHandler(c, true).ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/v1/steer", strings.NewReader(body)))
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rr.Code)
	}
}

func TestAirControlACLDeny(t *testing.T) {
	c := &fakeAirControl{}
	for _, path := range []string{"/v1/sessions", "/v1/steer"} {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"backend":"fs","id":"9f2a","method":"m"}`))
		newTestHandler(c, false).ServeHTTP(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("%s: status = %d, want 403", path, rr.Code)
		}
	}
	if len(c.steers) != 0 {
		t.Fatalf("denied caller still steered: %v", c.steers)
	}
}

// handlerWithIdentity builds a control handler with a chosen caller identity and
// an audit collector, so per-backend ACL and on-behalf attribution are testable.
func handlerWithIdentity(c airController, pubKey, fqdn string, audit func(airSteerAudit)) http.Handler {
	id := func(*http.Request) (string, string) { return pubKey, fqdn }
	// Trust the connecting peer as an on-behalf proxy so the on-behalf tests
	// that use this helper exercise attribution; the general allow is open.
	return airControlHandler(c, id, newACL(nil), newACL([]string{"pubkey:" + pubKey}), audit)
}

func TestAirControlPerBackendACL(t *testing.T) {
	// Caller reaches the endpoint (global Allow open) but is denied on backend fs.
	c := &fakeAirControl{
		list:       []AirSession{{Backend: "fs", ID: "9f2a"}, {Backend: "kg", ID: "1a2b"}},
		denyOnFqdn: "outsider.mesh",
	}
	h := handlerWithIdentity(c, "keyX", "outsider.mesh", nil)

	// sessions: fs rows filtered out, kg remains.
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/sessions", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("sessions status = %d, want 200", rr.Code)
	}
	var out struct {
		Sessions []AirSession `json:"sessions"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	if len(out.Sessions) != 1 || out.Sessions[0].Backend != "kg" {
		t.Fatalf("fs sessions not filtered for denied caller: %+v", out.Sessions)
	}

	// steer fs: 403 forbidden (backend ACL), not routed.
	rr = httptest.NewRecorder()
	body := `{"backend":"fs","id":"9f2a","method":"notifications/air/steer"}`
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/v1/steer", strings.NewReader(body)))
	if rr.Code != http.StatusForbidden {
		t.Fatalf("steer fs status = %d, want 403", rr.Code)
	}
}

func TestAirControlSteerMethodAllowlist(t *testing.T) {
	c := &fakeAirControl{}
	var recs []airSteerAudit
	h := handlerWithIdentity(c, "key1", "caller.mesh", func(r airSteerAudit) { recs = append(recs, r) })
	rr := httptest.NewRecorder()
	body := `{"backend":"fs","id":"9f2a","method":"notifications/evil"}`
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/v1/steer", strings.NewReader(body)))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("off-allowlist method = %d, want 400", rr.Code)
	}
	if len(c.steers) != 0 {
		t.Fatalf("off-allowlist method still steered: %v", c.steers)
	}
	if len(recs) != 1 || recs[0].OK {
		t.Fatalf("off-allowlist method not audited as deny: %+v", recs)
	}
}

func TestAirControlSteerOnBehalf(t *testing.T) {
	c := &fakeAirControl{}
	var recs []airSteerAudit
	// The connecting peer is ACL-allowed (global Allow open), so its attested
	// X-Air-On-Behalf header is honoured.
	h := handlerWithIdentity(c, "relaykey", "air-serve.mesh", func(r airSteerAudit) { recs = append(recs, r) })
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/steer", strings.NewReader(`{"backend":"fs","id":"9f2a","method":"notifications/air/steer"}`))
	req.Header.Set("X-Air-On-Behalf", "phone.mesh")
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body)
	}
	if len(recs) != 1 || recs[0].OnBehalf != "phone.mesh" {
		t.Fatalf("on-behalf not attributed: %+v", recs)
	}
	if !strings.Contains(rr.Body.String(), "phone.mesh") {
		t.Fatalf("response should attribute the human: %s", rr.Body)
	}
}

func TestAirControlSteerBadRequest(t *testing.T) {
	c := &fakeAirControl{}
	rr := httptest.NewRecorder()
	newTestHandler(c, true).ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/v1/steer", strings.NewReader(`{"backend":"fs"}`)))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rr.Code)
	}
	rr = httptest.NewRecorder()
	newTestHandler(c, true).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/steer", nil))
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET /v1/steer = %d, want 405", rr.Code)
	}
}

// TestAirControlSteerOnBehalfKey proves an attested X-Air-On-Behalf-Key is
// carried into the audit record alongside the attested FQDN — and that the key
// is never honoured without the FQDN header.
func TestAirControlSteerOnBehalfKey(t *testing.T) {
	c := &fakeAirControl{}
	var recs []airSteerAudit
	h := handlerWithIdentity(c, "relaykey", "air-serve.mesh", func(r airSteerAudit) { recs = append(recs, r) })

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/steer", strings.NewReader(`{"backend":"fs","id":"9f2a","method":"notifications/air/steer"}`))
	req.Header.Set("X-Air-On-Behalf", "phone.mesh")
	req.Header.Set("X-Air-On-Behalf-Key", "PHONEKEY")
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body)
	}
	if len(recs) != 1 || recs[0].OnBehalf != "phone.mesh" || recs[0].OnBehalfKey != "PHONEKEY" {
		t.Fatalf("attested key not attributed: %+v", recs)
	}

	// Key header alone (no FQDN) attests nothing.
	recs = nil
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/v1/steer", strings.NewReader(`{"backend":"fs","id":"9f2a","method":"notifications/air/steer"}`))
	req.Header.Set("X-Air-On-Behalf-Key", "PHONEKEY")
	h.ServeHTTP(rr, req)
	if len(recs) != 1 || recs[0].OnBehalf != "" || recs[0].OnBehalfKey != "" {
		t.Fatalf("key without fqdn must not attest: %+v", recs)
	}
}

// TestAirControlSessionsAudited proves a /v1/sessions read writes an audit
// record — allowed reads and ACL-denied attempts both.
func TestAirControlSessionsAudited(t *testing.T) {
	c := &fakeAirControl{list: []AirSession{{Backend: "fs", ID: "9f2a", Peer: "p.mesh", AgeSec: 3}}}
	var recs []airSteerAudit
	h := handlerWithIdentity(c, "callerkey", "caller.mesh", func(r airSteerAudit) { recs = append(recs, r) })

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/sessions", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if len(recs) != 1 || recs[0].Method != "air/sessions" || !recs[0].OK || recs[0].Peer != "caller.mesh" {
		t.Fatalf("sessions read not audited: %+v", recs)
	}
}

// TestAirControlOnBehalfRequiresProxyAllow proves the X-Air-On-Behalf header is
// honoured ONLY when the connecting peer is on the dedicated on-behalf proxy
// allow list — not merely on the general control allow — and that an empty
// proxy list fails closed (no attestation, attribution stays the caller).
func TestAirControlOnBehalfRequiresProxyAllow(t *testing.T) {
	steerBody := `{"backend":"fs","id":"9f2a","method":"notifications/air/steer"}`

	// Case 1: general allow open, but the connecting peer is NOT a listed proxy
	// (empty on-behalf list) → the header is ignored, receipt attributes the peer.
	c := &fakeAirControl{}
	var recs []airSteerAudit
	h := airControlHandler(c,
		func(*http.Request) (string, string) { return "relaykey", "relay.mesh" },
		newACL(nil), // general allow: open (any identified peer)
		newACL(nil), // on-behalf proxies: none → fail closed
		func(r airSteerAudit) { recs = append(recs, r) })
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/steer", strings.NewReader(steerBody))
	req.Header.Set("X-Air-On-Behalf", "victim.mesh")
	req.Header.Set("X-Air-On-Behalf-Key", "FORGED")
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body)
	}
	if len(recs) != 1 || recs[0].OnBehalf != "" || recs[0].OnBehalfKey != "" {
		t.Fatalf("unlisted proxy must not attest on-behalf: %+v", recs)
	}
	if recs[0].Peer != "relay.mesh" {
		t.Fatalf("attribution must stay the verified peer, got %q", recs[0].Peer)
	}

	// Case 2: the connecting peer IS a listed proxy → the header is honoured.
	recs = nil
	h = airControlHandler(c,
		func(*http.Request) (string, string) { return "relaykey", "relay.mesh" },
		newACL(nil),
		newACL([]string{"pubkey:relaykey"}), // this relay may attest
		func(r airSteerAudit) { recs = append(recs, r) })
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/v1/steer", strings.NewReader(steerBody))
	req.Header.Set("X-Air-On-Behalf", "phone.mesh")
	h.ServeHTTP(rr, req)
	if len(recs) != 1 || recs[0].OnBehalf != "phone.mesh" {
		t.Fatalf("listed proxy attestation not honoured: %+v", recs)
	}
}

// TestAirCatalogFiltersPerCaller proves the well-known Air catalog lists only
// the backends the caller's identity is permitted to reach (per-backend ACL),
// and refuses an unidentifiable peer entirely.
func TestAirCatalogFiltersPerCaller(t *testing.T) {
	c := &fakeAirControl{
		list:       []AirSession{{Backend: "fs"}, {Backend: "kg"}},
		denyOnFqdn: "outsider.mesh",
	}

	// A caller denied on fs sees only kg.
	h := handlerWithIdentity(c, "keyX", "outsider.mesh", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, airCatalogPath, nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("catalog status = %d, want 200", rr.Code)
	}
	var cat AirCatalog
	if err := json.Unmarshal(rr.Body.Bytes(), &cat); err != nil {
		t.Fatalf("bad catalog json: %v", err)
	}
	if len(cat.Endpoints) != 1 || cat.Endpoints[0].Name != "kg" {
		t.Fatalf("fs must be filtered for the denied caller: %+v", cat.Endpoints)
	}
	if cat.Service != "meshmcp" {
		t.Fatalf("catalog service = %q", cat.Service)
	}

	// An unidentifiable peer (no key, no fqdn) is refused.
	unid := airControlHandler(c, func(*http.Request) (string, string) { return "", "" },
		newACL(nil), newACL(nil), nil)
	rr = httptest.NewRecorder()
	unid.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, airCatalogPath, nil))
	if rr.Code != http.StatusForbidden {
		t.Fatalf("unidentified peer catalog = %d, want 403", rr.Code)
	}
}

// TestAirCatalogAudited proves a discovery read is recorded with the air/catalog
// method.
func TestAirCatalogAudited(t *testing.T) {
	c := &fakeAirControl{list: []AirSession{{Backend: "fs"}}}
	var recs []airSteerAudit
	h := handlerWithIdentity(c, "k1", "caller.mesh", func(r airSteerAudit) { recs = append(recs, r) })
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, airCatalogPath, nil))
	if len(recs) != 1 || recs[0].Method != "air/catalog" || !recs[0].OK {
		t.Fatalf("catalog read not audited: %+v", recs)
	}
}

// TestBuildCatalogBackends covers transport classification and addressing.
func TestBuildCatalogBackends(t *testing.T) {
	got := buildCatalogBackends([]*Backend{
		{Name: "fs", Port: 9101, Stdio: []string{"srv"}, Resumable: true},
		{Name: "web", Port: 9102, HTTP: "http://127.0.0.1:8080"},
	}, "100.64.0.2")
	if len(got) != 2 {
		t.Fatalf("want 2, got %d", len(got))
	}
	if got[0].transport != "stdio" || got[0].address != "100.64.0.2:9101" || !got[0].resumable {
		t.Fatalf("fs entry wrong: %+v", got[0])
	}
	if got[1].transport != "http" || got[1].address != "100.64.0.2:9102" {
		t.Fatalf("web entry wrong: %+v", got[1])
	}
}
