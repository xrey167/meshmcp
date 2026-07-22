package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/xrey167/meshmcp/air/sqlguard"
	"github.com/xrey167/meshmcp/policy"
)

// fakeDBExecutor is an in-memory dbExecutor: it records whether (and with what)
// it was called, and returns canned rows — so the tests exercise the whole
// firewall (identity, guard, grant, caps, redaction, audit) without any database.
type fakeDBExecutor struct {
	cols       []sqlguard.Column
	rows       [][]any
	err        error
	called     int
	lastSQL    string
	lastParams []any
}

func (f *fakeDBExecutor) Exec(_ context.Context, _ string, sql string, params []any) (dbRows, error) {
	f.called++
	f.lastSQL = sql
	f.lastParams = params
	if f.err != nil {
		return dbRows{}, f.err
	}
	return dbRows{Columns: f.cols, Rows: f.rows}, nil
}

// testGrants builds grants from the given "id=db.table,..." specs, failing the
// test on a malformed spec.
func testGrants(t *testing.T, specs ...string) dbGrants {
	t.Helper()
	g, err := parseDBGrants(specs)
	if err != nil {
		t.Fatalf("parseDBGrants(%v): %v", specs, err)
	}
	return g
}

func getReq(h http.Handler, path string) *httptest.ResponseRecorder {
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, path, nil))
	return rr
}

func chainOK(t *testing.T, buf *bytes.Buffer) {
	t.Helper()
	if res, _ := policy.VerifyChain(bytes.NewReader(buf.Bytes())); !res.OK {
		t.Fatalf("audit chain broken: %+v", res)
	}
}

// TestAirDatabase_AllowedGrantedQueryForwardedAndAudited: an admitted identity
// with a covering table grant runs a SELECT that is forwarded to the executor and
// audited allow with the statement hash as provenance; the chain verifies.
func TestAirDatabase_AllowedGrantedQueryForwardedAndAudited(t *testing.T) {
	exec := &fakeDBExecutor{
		cols: []sqlguard.Column{{Name: "name"}, {Name: "revenue"}},
		rows: [][]any{{"Aria", 1240000}, {"Ben", 990000}},
	}
	audit, buf := newAuditBuf()
	h := databaseHandler(exec, idFunc("k1", "analyst.mesh"), newACL([]string{"pubkey:k1"}),
		testGrants(t, "pubkey:k1=analytics.customers"), dbServeConfig{}, audit)

	rr := postJSON(h, "/v1/database/query", sqlguard.Query{DB: "analytics", SQL: "SELECT name, revenue FROM customers WHERE region = ?", Params: []any{"EMEA"}})
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body)
	}
	if exec.called != 1 {
		t.Fatalf("executor called %d times, want 1", exec.called)
	}
	var res sqlguard.QueryResult
	if err := json.Unmarshal(rr.Body.Bytes(), &res); err != nil {
		t.Fatalf("bad json: %v", err)
	}
	if res.RowCount != 2 || len(res.Columns) != 2 {
		t.Fatalf("result = %+v, want 2 rows / 2 cols", res)
	}
	if res.QueryHash == "" {
		t.Fatal("result missing query hash")
	}
	if !strings.Contains(buf.String(), `"decision":"allow"`) || !strings.Contains(buf.String(), `"backend":"database"`) {
		t.Fatalf("query not audited as allow on backend database: %s", buf.String())
	}
	if !strings.Contains(buf.String(), "sql:"+res.QueryHash) {
		t.Fatalf("audit missing statement-hash provenance: %s", buf.String())
	}
	chainOK(t, buf)
}

// TestAirDatabase_UngrantedTableDenied: a query touching a table the caller was
// not granted is denied and audited, and never forwarded.
func TestAirDatabase_UngrantedTableDenied(t *testing.T) {
	exec := &fakeDBExecutor{}
	audit, buf := newAuditBuf()
	h := databaseHandler(exec, idFunc("k1", "analyst.mesh"), newACL([]string{"pubkey:k1"}),
		testGrants(t, "pubkey:k1=analytics.customers"), dbServeConfig{}, audit)

	rr := postJSON(h, "/v1/database/query", sqlguard.Query{DB: "analytics", SQL: "SELECT * FROM orders"})
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rr.Code)
	}
	if exec.called != 0 {
		t.Fatalf("ungranted query was forwarded (%d calls)", exec.called)
	}
	if !strings.Contains(buf.String(), `"decision":"deny"`) || !strings.Contains(buf.String(), "table not granted") {
		t.Fatalf("deny reason not audited: %s", buf.String())
	}
	chainOK(t, buf)
}

// TestAirDatabase_GuardRejectedNotForwarded: a stacked / non-SELECT statement is
// rejected by the guard, audited deny, and never reaches the executor.
func TestAirDatabase_GuardRejectedNotForwarded(t *testing.T) {
	exec := &fakeDBExecutor{}
	audit, buf := newAuditBuf()
	h := databaseHandler(exec, idFunc("k1", "analyst.mesh"), newACL([]string{"pubkey:k1"}),
		testGrants(t, "pubkey:k1=analytics.customers"), dbServeConfig{}, audit)

	rr := postJSON(h, "/v1/database/query", sqlguard.Query{DB: "analytics", SQL: "SELECT * FROM users; DROP TABLE customers"})
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403: %s", rr.Code, rr.Body)
	}
	if exec.called != 0 {
		t.Fatalf("guard-rejected query was forwarded (%d calls)", exec.called)
	}
	if !strings.Contains(buf.String(), `"decision":"deny"`) {
		t.Fatalf("guard rejection not audited: %s", buf.String())
	}
	chainOK(t, buf)
}

// TestAirDatabase_ACLAdmissionDeny: an identity off the admission ACL cannot reach
// the query surface at all.
func TestAirDatabase_ACLAdmissionDeny(t *testing.T) {
	exec := &fakeDBExecutor{}
	audit, buf := newAuditBuf()
	h := databaseHandler(exec, idFunc("stranger", "x.mesh"), newACL([]string{"pubkey:k1"}),
		testGrants(t, "pubkey:k1=analytics.customers"), dbServeConfig{}, audit)

	rr := postJSON(h, "/v1/database/query", sqlguard.Query{DB: "analytics", SQL: "SELECT * FROM customers"})
	if rr.Code != http.StatusForbidden {
		t.Fatalf("off-ACL caller must be denied, status = %d", rr.Code)
	}
	if exec.called != 0 {
		t.Fatalf("off-ACL query was forwarded")
	}
	if !strings.Contains(buf.String(), "endpoint ACL") {
		t.Fatalf("admission deny not audited: %s", buf.String())
	}
}

// TestAirDatabase_UnidentifiedPeerDenied: a peer with no resolvable identity is
// refused by the deny-by-default ACL.
func TestAirDatabase_UnidentifiedPeerDenied(t *testing.T) {
	exec := &fakeDBExecutor{}
	h := databaseHandler(exec, idFunc("", ""), newACL([]string{"pubkey:k1"}),
		testGrants(t, "pubkey:k1=analytics.customers"), dbServeConfig{}, nil)
	rr := postJSON(h, "/v1/database/query", sqlguard.Query{DB: "analytics", SQL: "SELECT * FROM customers"})
	if rr.Code != http.StatusForbidden {
		t.Fatalf("unidentified peer must be denied, status = %d", rr.Code)
	}
	if exec.called != 0 {
		t.Fatalf("unidentified query was forwarded")
	}
}

// TestAirDatabase_RowCapTruncates: the firewall caps rows at its ceiling and
// flags Truncated, never erroring.
func TestAirDatabase_RowCapTruncates(t *testing.T) {
	exec := &fakeDBExecutor{
		cols: []sqlguard.Column{{Name: "id"}},
		rows: [][]any{{1}, {2}, {3}, {4}, {5}},
	}
	h := databaseHandler(exec, idFunc("k1", "analyst.mesh"), newACL([]string{"pubkey:k1"}),
		testGrants(t, "pubkey:k1=analytics.customers"), dbServeConfig{MaxRows: 3}, nil)

	rr := postJSON(h, "/v1/database/query", sqlguard.Query{DB: "analytics", SQL: "SELECT id FROM customers"})
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body)
	}
	var res sqlguard.QueryResult
	_ = json.Unmarshal(rr.Body.Bytes(), &res)
	if res.RowCount != 3 || !res.Truncated {
		t.Fatalf("row cap: RowCount=%d Truncated=%v, want 3/true", res.RowCount, res.Truncated)
	}
}

// TestAirDatabase_RedactedColumnsMaskedAndPredicateForbidden: a redacted column is
// masked in results when selected, and forbidden when used in a predicate.
func TestAirDatabase_RedactedColumnsMaskedAndPredicateForbidden(t *testing.T) {
	exec := &fakeDBExecutor{
		cols: []sqlguard.Column{{Name: "name"}, {Name: "email"}},
		rows: [][]any{{"Aria", "aria@x.com"}},
	}
	cfg := dbServeConfig{Redact: []string{"email"}}
	h := databaseHandler(exec, idFunc("k1", "analyst.mesh"), newACL([]string{"pubkey:k1"}),
		testGrants(t, "pubkey:k1=analytics.customers"), cfg, nil)

	// Selected: comes back masked.
	rr := postJSON(h, "/v1/database/query", sqlguard.Query{DB: "analytics", SQL: "SELECT name, email FROM customers"})
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body)
	}
	var res sqlguard.QueryResult
	_ = json.Unmarshal(rr.Body.Bytes(), &res)
	if len(res.Redacted) != 1 || res.Redacted[0] != "email" {
		t.Fatalf("redacted names = %v, want [email]", res.Redacted)
	}
	if res.Rows[0][1] != "[redacted]" || res.Rows[0][0] != "Aria" {
		t.Fatalf("email not masked / name lost: %v", res.Rows[0])
	}

	// In a predicate: forbidden (real information-flow control), not forwarded.
	exec.called = 0
	rr = postJSON(h, "/v1/database/query", sqlguard.Query{DB: "analytics", SQL: "SELECT name FROM customers WHERE email = ?", Params: []any{"aria@x.com"}})
	if rr.Code != http.StatusForbidden {
		t.Fatalf("redacted column in predicate must be denied, status = %d", rr.Code)
	}
	if exec.called != 0 {
		t.Fatalf("predicate-forbidden query was forwarded")
	}
}

// TestAirDatabase_ParamsAreBoundNotInterpolated: an injection payload in a --param
// is passed to the executor as a bind value; the SQL text is untouched, so the
// payload can perform no injection.
func TestAirDatabase_ParamsAreBoundNotInterpolated(t *testing.T) {
	exec := &fakeDBExecutor{cols: []sqlguard.Column{{Name: "name"}}, rows: [][]any{}}
	h := databaseHandler(exec, idFunc("k1", "analyst.mesh"), newACL([]string{"pubkey:k1"}),
		testGrants(t, "pubkey:k1=analytics.customers"), dbServeConfig{}, nil)

	payload := "'; DROP TABLE customers; --"
	rr := postJSON(h, "/v1/database/query", sqlguard.Query{DB: "analytics", SQL: "SELECT name FROM customers WHERE region = ?", Params: []any{payload}})
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body)
	}
	if len(exec.lastParams) != 1 || exec.lastParams[0] != payload {
		t.Fatalf("param not bound through: %v", exec.lastParams)
	}
	if !strings.Contains(exec.lastSQL, "?") || strings.Contains(exec.lastSQL, "DROP") {
		t.Fatalf("SQL was interpolated with the payload: %q", exec.lastSQL)
	}
}

// TestAirDatabase_AuditTamperDetected: after a real query the chain verifies, and
// flipping a byte in the ledger makes VerifyChain report the break.
func TestAirDatabase_AuditTamperDetected(t *testing.T) {
	exec := &fakeDBExecutor{cols: []sqlguard.Column{{Name: "id"}}, rows: [][]any{{1}}}
	audit, buf := newAuditBuf()
	h := databaseHandler(exec, idFunc("k1", "analyst.mesh"), newACL([]string{"pubkey:k1"}),
		testGrants(t, "pubkey:k1=analytics.customers"), dbServeConfig{}, audit)
	postJSON(h, "/v1/database/query", sqlguard.Query{DB: "analytics", SQL: "SELECT id FROM customers"})
	chainOK(t, buf)

	tampered := append([]byte(nil), buf.Bytes()...)
	// Flip a byte inside the record's reason ("row(s)") to a different digit run.
	idx := bytes.Index(tampered, []byte("row(s)"))
	if idx < 0 {
		t.Fatalf("expected a row-count reason to tamper with: %s", buf.String())
	}
	tampered[idx] = 'X'
	if res, _ := policy.VerifyChain(bytes.NewReader(tampered)); res.OK {
		t.Fatalf("tampered ledger passed verification")
	}
}

// TestAirDatabase_FailClosedDeniesOnAuditWriteError: with a fail-closed ledger,
// an audit write failure denies the (already-validated) query rather than serving
// data unrecorded.
func TestAirDatabase_FailClosedDeniesOnAuditWriteError(t *testing.T) {
	exec := &fakeDBExecutor{cols: []sqlguard.Column{{Name: "id"}}, rows: [][]any{{1}}}
	audit := policy.NewAuditLog(errWriter{}, func() string { return "t" }).WithFailClosed(true)
	h := databaseHandler(exec, idFunc("k1", "analyst.mesh"), newACL([]string{"pubkey:k1"}),
		testGrants(t, "pubkey:k1=analytics.customers"), dbServeConfig{}, audit)

	rr := postJSON(h, "/v1/database/query", sqlguard.Query{DB: "analytics", SQL: "SELECT id FROM customers"})
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 (fail-closed): %s", rr.Code, rr.Body)
	}
	if strings.Contains(rr.Body.String(), `"rows"`) {
		t.Fatalf("fail-closed served result body: %s", rr.Body)
	}
}

// TestAirDatabase_TablesListPerIdentity: the discovery route returns exactly the
// db.table entries the caller's identity is granted.
func TestAirDatabase_TablesListPerIdentity(t *testing.T) {
	h := databaseHandler(&fakeDBExecutor{}, idFunc("k1", "analyst.mesh"), newACL([]string{"pubkey:k1"}),
		testGrants(t, "pubkey:k1=analytics.customers,analytics.orders"), dbServeConfig{}, nil)
	rr := getReq(h, "/v1/database/tables")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	var out struct {
		Tables []string `json:"tables"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	if len(out.Tables) != 2 {
		t.Fatalf("tables = %v, want 2 entries", out.Tables)
	}
}

// TestAirDatabaseServe_RequiresAllow: serve refuses to start without an --allow
// list (deny-by-default), before any mesh work.
func TestAirDatabaseServe_RequiresAllow(t *testing.T) {
	err := cmdAirDatabaseServe([]string{})
	if err == nil || !strings.Contains(err.Error(), "--allow") {
		t.Fatalf("serve without --allow: err = %v, want an --allow error", err)
	}
}

// TestParseDBGrants_RejectsMalformed: a grant with no '=' or a non-db.table entry
// is a hard error.
func TestParseDBGrants_RejectsMalformed(t *testing.T) {
	for _, spec := range []string{"noequals", "id=", "id=customers"} {
		if _, err := parseDBGrants([]string{spec}); err == nil {
			t.Errorf("parseDBGrants(%q) accepted a malformed grant", spec)
		}
	}
}
