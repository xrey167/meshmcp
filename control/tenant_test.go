package control

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/xrey167/meshmcp/policy"
)

// The cross-tenant isolation matrix. Two tenants — acme (key KA) and globex (key
// KB), each admin WITHIN its own tenant — share one control plane. The tests
// prove cross-tenant read/write is absent BY CONSTRUCTION: a handler only ever
// sees the tenantID authorize derives from the transport key, and every store is
// addressed through it, so there is no request that operates on another tenant.

const mtACL = `
tenants:
  acme:
    grants:
      KA: [control.admin]
    enroll_groups: [nb-acme]
  globex:
    grants:
      KB: [control.admin]
    enroll_groups: [nb-globex]
`

// mtHarness is the shared multi-tenant substrate: one TenantSet + one
// TenantStores over temp roots, from which per-key servers are built. Servers
// share storage so isolation is testable across them.
type mtHarness struct {
	t         *testing.T
	tenants   *TenantSet
	stores    *TenantStores
	polRoot   string
	regRoot   string
	auditRoot string
	fallback  *captureAudit // no-tenant (Tenant:"") control-audit records land here

	mu        sync.Mutex
	gotGroups map[string][]string // tenantID -> groups its enroller was built with
}

func newMTHarness(t *testing.T) *mtHarness {
	t.Helper()
	ts, err := LoadTenantACL([]byte(mtACL))
	if err != nil {
		t.Fatalf("load tenant ACL: %v", err)
	}
	h := &mtHarness{
		t:         t,
		tenants:   ts,
		polRoot:   t.TempDir(),
		regRoot:   t.TempDir(),
		auditRoot: t.TempDir(),
		fallback:  &captureAudit{},
		gotGroups: map[string][]string{},
	}
	// Test enroller: records the groups it was built with (for attribution
	// assertions) and appends a real enrollment record into the tenant's shared
	// chain, so enrollment interleaves with control actions in one file.
	newEnroll := func(tid string, groups []string, audit *policy.AuditLog) (EnrollFunc, error) {
		h.mu.Lock()
		h.gotGroups[tid] = groups
		h.mu.Unlock()
		return func(req EnrollRequest) (EnrollResponse, error) {
			if audit != nil {
				_ = audit.Append(policy.AuditRecord{
					Backend: "control", Peer: req.Node, Method: "enroll",
					Decision: "allow", Reason: "issued for " + tid,
				})
			}
			return EnrollResponse{
				ManagementURL: "https://mgmt.example",
				SetupKey:      "SK-" + tid,
				Registry:      "/reg/" + tid,
				ControlNode:   "control-1",
			}, nil
		}, nil
	}
	h.stores = NewTenantStores(TenantStoresConfig{
		PolicyRoot:   h.polRoot,
		RegistryRoot: h.regRoot,
		AuditRoot:    h.auditRoot,
		Now:          func() string { return "T" },
		Fallback:     h.fallback,
		NewEnroll:    newEnroll,
		Groups:       ts.EnrollGroups,
	})
	t.Cleanup(func() { h.stores.Close() })
	return h
}

// serverFor builds a control server that identifies EVERY caller as key,
// sharing the harness's tenants + stores. A blank key simulates a caller in no
// tenant.
func (h *mtHarness) serverFor(key string) *httptest.Server {
	s := &Server{
		Tenants: h.tenants,
		Stores:  h.stores,
		Audit:   h.stores,
		Identify: func(string) (Identity, bool) {
			if key == "" {
				return Identity{}, false
			}
			return Identity{PubKey: key, FQDN: key + ".netbird.cloud"}, true
		},
	}
	ts := httptest.NewServer(s.Handler())
	h.t.Cleanup(ts.Close)
	return ts
}

// req issues a request and returns the status code and body.
func req(t *testing.T, ts *httptest.Server, method, path, body string) (int, string) {
	t.Helper()
	r, err := http.NewRequest(method, ts.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

const okPolicyRead = `default_allow: false
rules:
  - peers: ["*"]
    tools: ["read_*"]
    allow: true`

const okPolicyWrite = `default_allow: false
rules:
  - peers: ["*"]
    tools: ["write_*"]
    allow: true`

// readAuditFile returns the raw bytes of a tenant's audit chain (empty when the
// file does not exist yet).
func readAuditFile(t *testing.T, root, tenant string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, tenant+".jsonl"))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func auditRecords(t *testing.T, b []byte) []policy.AuditRecord {
	t.Helper()
	var out []policy.AuditRecord
	for _, line := range bytes.Split(bytes.TrimSpace(b), []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var r policy.AuditRecord
		if err := json.Unmarshal(line, &r); err != nil {
			t.Fatalf("bad audit line %q: %v", line, err)
		}
		out = append(out, r)
	}
	return out
}

// 1. Policy read isolation — KA PUTs a policy; KB cannot see it.
func TestTenantPolicyReadIsolation(t *testing.T) {
	h := newMTHarness(t)
	tsA, tsB := h.serverFor("KA"), h.serverFor("KB")

	if code, body := req(t, tsA, http.MethodPut, "/v1/policy/p", okPolicyRead); code != http.StatusOK {
		t.Fatalf("KA PUT policy: got %d %s", code, body)
	}
	if code, _ := req(t, tsB, http.MethodGet, "/v1/policy/p", ""); code != http.StatusNotFound {
		t.Fatalf("KB GET of A's policy must be 404 (absent from B's store), got %d", code)
	}
	// A still sees its own.
	if code, _ := req(t, tsA, http.MethodGet, "/v1/policy/p", ""); code != http.StatusOK {
		t.Fatalf("KA should read its own policy, got %d", code)
	}
}

// 2. Registry isolation — KA registers a service; B's listing excludes it.
func TestTenantRegistryIsolation(t *testing.T) {
	h := newMTHarness(t)
	tsA, tsB := h.serverFor("KA"), h.serverFor("KB")

	if code, _ := req(t, tsA, http.MethodPost, "/v1/registry", `{"name":"svc","addr":"100.64.0.2:9101"}`); code != http.StatusOK {
		t.Fatalf("KA register: got %d", code)
	}
	code, body := req(t, tsB, http.MethodGet, "/v1/registry", "")
	if code != http.StatusOK {
		t.Fatalf("KB list registry: got %d", code)
	}
	var m map[string][]string
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		t.Fatalf("decode B registry: %v (%s)", err, body)
	}
	if _, present := m["svc"]; present {
		t.Fatalf("B's registry must exclude A's svc, got %+v", m)
	}
	// A sees its own.
	_, bodyA := req(t, tsA, http.MethodGet, "/v1/registry", "")
	var ma map[string][]string
	json.Unmarshal([]byte(bodyA), &ma)
	if len(ma["svc"]) != 1 {
		t.Fatalf("A should see its own svc, got %+v", ma)
	}
}

// 3. RBAC root isolation — admin-of-A holds nothing in B (no cross-tenant
// super-role). The datum for KA-in-B does not exist in B's authorizer.
func TestTenantRBACRootIsolation(t *testing.T) {
	h := newMTHarness(t)
	// A key resolves only to its own tenant.
	if tid, ok := h.tenants.TenantFor("KA"); !ok || tid != "acme" {
		t.Fatalf("KA should resolve to acme, got %q %v", tid, ok)
	}
	if tid, ok := h.tenants.TenantFor("KB"); !ok || tid != "globex" {
		t.Fatalf("KB should resolve to globex, got %q %v", tid, ok)
	}
	// Admin within own tenant.
	if !h.tenants.Authorized("acme", "KA", RoleAdmin) {
		t.Fatal("KA must be admin in acme")
	}
	if !h.tenants.Authorized("globex", "KB", RoleAdmin) {
		t.Fatal("KB must be admin in globex")
	}
	// Nothing across the boundary — for EVERY role, not just admin.
	for _, r := range allRoles {
		if h.tenants.Authorized("globex", "KA", r) {
			t.Fatalf("KA (admin in acme) must hold NOTHING in globex, but held %s", r)
		}
		if h.tenants.Authorized("acme", "KB", r) {
			t.Fatalf("KB (admin in globex) must hold NOTHING in acme, but held %s", r)
		}
	}
}

// 4. Namespace collision safety — both tenants write policy "team"; the two are
// independent files and a PUT in A never mutates B's copy.
func TestTenantNamespaceCollisionSafety(t *testing.T) {
	h := newMTHarness(t)
	tsA, tsB := h.serverFor("KA"), h.serverFor("KB")

	if code, _ := req(t, tsA, http.MethodPut, "/v1/policy/team", okPolicyRead); code != http.StatusOK {
		t.Fatalf("KA PUT team: %d", code)
	}
	if code, _ := req(t, tsB, http.MethodPut, "/v1/policy/team", okPolicyWrite); code != http.StatusOK {
		t.Fatalf("KB PUT team: %d", code)
	}
	// Each reads back its OWN content.
	if _, a := req(t, tsA, http.MethodGet, "/v1/policy/team", ""); !strings.Contains(a, "read_*") {
		t.Fatalf("A's team must be A's content, got %s", a)
	}
	if _, b := req(t, tsB, http.MethodGet, "/v1/policy/team", ""); !strings.Contains(b, "write_*") {
		t.Fatalf("B's team must be B's content, got %s", b)
	}
	// The files are physically distinct.
	af, _ := os.ReadFile(filepath.Join(h.polRoot, "acme", "team.yaml"))
	bf, _ := os.ReadFile(filepath.Join(h.polRoot, "globex", "team.yaml"))
	if !bytes.Contains(af, []byte("read_*")) || !bytes.Contains(bf, []byte("write_*")) {
		t.Fatalf("collision: A=%s B=%s", af, bf)
	}
}

// 5. Audit chain isolation — A's actions land only in acme.jsonl; VerifyChain of
// each tenant's file needs no other tenant's records, and B's Seq/PrevHash are
// unaffected by A's activity.
func TestTenantAuditChainIsolation(t *testing.T) {
	h := newMTHarness(t)
	tsA, tsB := h.serverFor("KA"), h.serverFor("KB")

	// KA: two successful privileged actions -> two allow records in acme.jsonl.
	req(t, tsA, http.MethodPost, "/v1/registry", `{"name":"svc","addr":"100.64.0.2:9101"}`)
	req(t, tsA, http.MethodPut, "/v1/policy/p", okPolicyRead)
	// KB: one -> one record in globex.jsonl.
	req(t, tsB, http.MethodPost, "/v1/registry", `{"name":"svc","addr":"100.64.0.9:9101"}`)

	aRecs := auditRecords(t, readAuditFile(t, h.auditRoot, "acme"))
	bRecs := auditRecords(t, readAuditFile(t, h.auditRoot, "globex"))

	if res, _ := policy.VerifyChain(bytes.NewReader(readAuditFile(t, h.auditRoot, "acme"))); !res.OK || res.Count != 2 {
		t.Fatalf("acme chain must verify with 2 records, got %+v", res)
	}
	if res, _ := policy.VerifyChain(bytes.NewReader(readAuditFile(t, h.auditRoot, "globex"))); !res.OK || res.Count != 1 {
		t.Fatalf("globex chain must verify with 1 record, got %+v", res)
	}
	// No foreign records in either file.
	for _, r := range aRecs {
		if r.Peer != "KA" {
			t.Fatalf("acme chain has a non-KA record: %+v", r)
		}
	}
	for _, r := range bRecs {
		if r.Peer != "KB" {
			t.Fatalf("globex chain has a non-KB record: %+v", r)
		}
	}
	// Each chain is an independent genesis: B's seq is 1 despite A having 2.
	if bRecs[0].Seq != 1 {
		t.Fatalf("globex chain must start at seq 1 independently of acme, got %d", bRecs[0].Seq)
	}
	if aRecs[0].Seq != 1 || aRecs[1].Seq != 2 {
		t.Fatalf("acme chain seqs must be 1,2, got %d,%d", aRecs[0].Seq, aRecs[1].Seq)
	}
}

// 6. Deny-by-default — a key in no tenant is refused on every privileged route,
// deny-audited with an empty tenant (never entering any tenant's chain).
func TestTenantDenyByDefault(t *testing.T) {
	h := newMTHarness(t)
	ts := h.serverFor("KC") // KC is granted under no tenant

	routes := []struct{ method, path, body string }{
		{http.MethodPost, "/v1/enroll", `{"node":"x"}`},
		{http.MethodGet, "/v1/registry", ""},
		{http.MethodPost, "/v1/registry", `{"name":"n","addr":"a"}`},
		{http.MethodGet, "/v1/policy/p", ""},
		{http.MethodPut, "/v1/policy/p", okPolicyRead},
		{http.MethodGet, "/v1/policies", ""},
	}
	for _, r := range routes {
		if code, _ := req(t, ts, r.method, r.path, r.body); code != http.StatusForbidden {
			t.Fatalf("%s %s: no-tenant caller must be 403, got %d", r.method, r.path, code)
		}
	}
	// Every denial was audited to the fallback with an EMPTY tenant.
	var denials int
	for _, rec := range h.fallback.snapshot() {
		if rec.Result != "deny" {
			t.Fatalf("no-tenant record should be a deny, got %+v", rec)
		}
		if rec.Tenant != "" {
			t.Fatalf("no-tenant deny must carry empty tenant, got %q", rec.Tenant)
		}
		if rec.Actor != "KC" || rec.Reason != "caller belongs to no tenant" {
			t.Fatalf("unexpected no-tenant deny: %+v", rec)
		}
		denials++
	}
	if denials != len(routes) {
		t.Fatalf("expected %d no-tenant denials, got %d", len(routes), denials)
	}
	// No tenant chain files were created by a no-tenant caller.
	if b := readAuditFile(t, h.auditRoot, "acme"); b != nil {
		t.Fatalf("a no-tenant caller must not create a tenant chain, acme.jsonl exists: %s", b)
	}
}

// 7. Confused-deputy regression — a caller-supplied "tenant" field cannot
// redirect the operation. It is rejected (DisallowUnknownFields), and a genuine
// write lands in the CALLER's tenant, derived only from the transport key.
func TestTenantConfusedDeputy(t *testing.T) {
	h := newMTHarness(t)
	tsA, tsB := h.serverFor("KA"), h.serverFor("KB")

	// A body naming another tenant is rejected before any write (unknown field).
	if code, _ := req(t, tsA, http.MethodPost, "/v1/registry", `{"tenant":"globex","name":"x","addr":"y"}`); code != http.StatusBadRequest {
		t.Fatalf("body naming a tenant must be 400 (unknown field), got %d", code)
	}
	// A genuine write from KA lands in acme, NEVER globex.
	if code, _ := req(t, tsA, http.MethodPost, "/v1/registry", `{"name":"x","addr":"y"}`); code != http.StatusOK {
		t.Fatalf("KA register: %d", code)
	}
	_, aBody := req(t, tsA, http.MethodGet, "/v1/registry", "")
	_, bBody := req(t, tsB, http.MethodGet, "/v1/registry", "")
	if !strings.Contains(aBody, `"x"`) {
		t.Fatalf("KA's write must land in acme, got %s", aBody)
	}
	if strings.Contains(bBody, `"x"`) {
		t.Fatalf("KA's write must NOT appear in globex, got %s", bBody)
	}
}

// 8. Single-tenant back-compat — with no tenants configured (Tenants nil), the
// server behaves exactly as before: stores are the flat fields and audit records
// carry no tenant. Asserts equivalence to the pre-tenancy TestControl* outcomes.
func TestTenantSingleTenantBackCompat(t *testing.T) {
	s, aud, ts := newTestServerWith(t, "ADMIN-KEY", map[string][]Role{"ADMIN-KEY": {RoleAdmin}})
	defer ts.Close()

	if s.Tenants != nil || s.Stores != nil {
		t.Fatal("single-tenant server must have nil Tenants/Stores")
	}
	// Full round-trips succeed exactly as before.
	if code, _ := req(t, ts, http.MethodPost, "/v1/registry", `{"name":"fs","addr":"100.64.0.2:9101"}`); code != http.StatusOK {
		t.Fatalf("register: %d", code)
	}
	if code, _ := req(t, ts, http.MethodPut, "/v1/policy/team", okPolicyRead); code != http.StatusOK {
		t.Fatalf("put policy: %d", code)
	}
	if code, _ := req(t, ts, http.MethodGet, "/v1/policy/team", ""); code != http.StatusOK {
		t.Fatalf("get policy: %d", code)
	}
	// Every audit record carries an empty tenant (byte-identical to legacy: the
	// omitempty field is absent on the wire).
	recs := aud.snapshot()
	if len(recs) == 0 {
		t.Fatal("expected audit records")
	}
	for _, r := range recs {
		if r.Tenant != "" {
			t.Fatalf("single-tenant record must carry empty tenant, got %q", r.Tenant)
		}
	}
	// The empty tenant is omitted from the JSON entirely.
	b, _ := json.Marshal(recs[0])
	if bytes.Contains(b, []byte("tenant")) {
		t.Fatalf("single-tenant audit JSON must omit the tenant field, got %s", b)
	}
}

// 9. Enrollment attribution — KA's enroll uses A's enroller (A's groups) and is
// attributed in A's chain. Given the shared PAT, this asserts ATTRIBUTION and
// group-scoping, NOT management-plane account isolation.
func TestTenantEnrollmentAttribution(t *testing.T) {
	h := newMTHarness(t)
	tsA := h.serverFor("KA")

	code, body := req(t, tsA, http.MethodPost, "/v1/enroll", `{"node":"laptop-7"}`)
	if code != http.StatusOK {
		t.Fatalf("KA enroll: %d %s", code, body)
	}
	var er EnrollResponse
	json.Unmarshal([]byte(body), &er)
	if er.SetupKey != "SK-acme" {
		t.Fatalf("enroll must use acme's enroller, got key %q", er.SetupKey)
	}
	// The enroller was built with acme's groups.
	h.mu.Lock()
	g := h.gotGroups["acme"]
	h.mu.Unlock()
	if len(g) != 1 || g[0] != "nb-acme" {
		t.Fatalf("acme enroller must carry acme's groups, got %v", g)
	}
	// A's chain carries BOTH the authorize-allow (enroll.issue) and the
	// enrollment record; it verifies; globex has no such record.
	aRecs := auditRecords(t, readAuditFile(t, h.auditRoot, "acme"))
	var sawIssue, sawEnroll bool
	for _, r := range aRecs {
		if r.Peer != "KA" && r.Method != "enroll" {
			t.Fatalf("acme chain has a foreign record: %+v", r)
		}
		if r.Method == "enroll.issue" && r.Decision == "allow" {
			sawIssue = true
		}
		if r.Method == "enroll" && r.Decision == "allow" {
			sawEnroll = true
		}
	}
	if !sawIssue || !sawEnroll {
		t.Fatalf("acme chain must carry enroll.issue authorization AND the enrollment record, got %+v", aRecs)
	}
	if res, _ := policy.VerifyChain(bytes.NewReader(readAuditFile(t, h.auditRoot, "acme"))); !res.OK {
		t.Fatalf("acme chain must verify after enrollment: %+v", res)
	}
	if b := readAuditFile(t, h.auditRoot, "globex"); b != nil {
		t.Fatalf("globex must have no enrollment attribution, got %s", b)
	}
}

// TestLoadControlACLDetectsForm exercises the ACL loader's mutual-exclusivity and
// load-time invariants (operator input, never the request path).
func TestLoadControlACLDetectsForm(t *testing.T) {
	// Flat form.
	if acl, err := LoadControlACL([]byte("grants:\n  KEY: [control.admin]\n")); err != nil || acl.Flat == nil || acl.Tenants != nil {
		t.Fatalf("flat ACL should load as Flat: %v %+v", err, acl)
	}
	// Tenant form.
	acl, err := LoadControlACL([]byte(mtACL))
	if err != nil || acl.Tenants == nil || acl.Flat != nil {
		t.Fatalf("tenant ACL should load as Tenants: %v %+v", err, acl)
	}
	// Both forms at once is a config error.
	if _, err := LoadControlACL([]byte("grants:\n  K: [control.admin]\ntenants:\n  a:\n    grants:\n      K2: [control.admin]\n")); err == nil {
		t.Fatal("grants+tenants together must fail")
	}
	// A key in two tenants is a config error (ambiguous tenant).
	dup := "tenants:\n  a:\n    grants:\n      SHARED: [control.admin]\n  b:\n    grants:\n      SHARED: [control.admin]\n"
	if _, err := LoadControlACL([]byte(dup)); err == nil {
		t.Fatal("a key granted under two tenants must fail")
	}
	// An unsafe tenant id (path segment) is a config error.
	if _, err := LoadControlACL([]byte("tenants:\n  \"../evil\":\n    grants:\n      K: [control.admin]\n")); err == nil {
		t.Fatal("path-unsafe tenant id must fail")
	}
	// A tenant with no grants is a config error.
	if _, err := LoadControlACL([]byte("tenants:\n  empty:\n    grants: {}\n")); err == nil {
		t.Fatal("a tenant with no grants must fail")
	}
	// An unknown role fails (delegated to NewStaticAuthorizer).
	if _, err := LoadControlACL([]byte("tenants:\n  a:\n    grants:\n      K: [not.a.role]\n")); err == nil {
		t.Fatal("unknown role must fail")
	}
}

// TestValidTenantID mirrors TestValidPolicyName: a tenant id becomes a directory
// segment, so it enforces the same path-safety rules.
func TestValidTenantID(t *testing.T) {
	for _, bad := range []string{"", ".", "..", "../etc", "a/b", "a\\b", ".hidden", "acme.", "a..b", "x\x00", "team!", strings.Repeat("x", 200)} {
		if err := validTenantID(bad); err == nil {
			t.Fatalf("tenant id %q should be rejected", bad)
		}
	}
	for _, ok := range []string{"acme", "globex_2", "a-b.c", "Tenant1"} {
		if err := validTenantID(ok); err != nil {
			t.Fatalf("tenant id %q should be allowed: %v", ok, err)
		}
	}
}

// TestTenantStorageCollisionRejected proves the load-time guard that keeps
// "distinct tenants ⇒ distinct storage" true on the case-insensitive,
// trailing-dot-stripping filesystems this ships on (Windows, default macOS). Two
// tenant ids the OS would resolve to the SAME directory and audit file must be
// refused at load. Otherwise one tenant's admin (holding RoleAdmin only within
// its own exact-case id) would read and write the other's policy/registry and
// both would interleave into one audit chain — a cross-tenant merge the
// per-tenant RBAC authorizers, keyed on the exact-case id, cannot catch.
func TestTenantStorageCollisionRejected(t *testing.T) {
	// Case-variant collision: "acme" and "Acme" name the same dir/file on
	// Windows/macOS, so the pair must be rejected even though each id is
	// individually valid and the two authorizers are distinct.
	caseCollide := `
tenants:
  acme:
    grants:
      KA: [control.admin]
  Acme:
    grants:
      KB: [control.admin]
`
	if _, err := LoadControlACL([]byte(caseCollide)); err == nil {
		t.Fatal("case-variant tenant ids (acme / Acme) must be rejected: they share one storage partition on a case-insensitive filesystem")
	}

	// A lone mixed-case id collides with nothing and must still load.
	if _, err := LoadControlACL([]byte("tenants:\n  Acme:\n    grants:\n      KA: [control.admin]\n")); err != nil {
		t.Fatalf("a single mixed-case tenant id must load (it collides with nothing): %v", err)
	}
}
