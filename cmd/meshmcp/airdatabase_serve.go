package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"sort"

	"github.com/xrey167/meshmcp/air/sqlguard"
	"github.com/xrey167/meshmcp/policy"
)

// dbServeConfig holds the endpoint's result-shaping policy: the row/byte ceilings
// and the redacted columns. Caps are hard maxima the caller can only lower via
// --limit; redaction masks the listed columns in results AND forbids them in
// query predicates (see sqlguard.CheckRedaction).
type dbServeConfig struct {
	MaxRows  int
	MaxBytes int
	Redact   []string
}

// databaseHandler builds the governed query firewall over an executor seam.
// identify resolves the caller's (pubKey, fqdn) from the mesh transport; admit
// gates who may reach the endpoint at all (deny-by-default, an unidentifiable
// peer is refused); grants maps an identity to the db.table entries it may read;
// exec forwards a validated read to the database backend; audit records EVERY
// query — allowed, denied, or guard-rejected — on the shared hash-chained ledger.
//
// The gauntlet, first failure denies and is audited, and a denied query is NEVER
// forwarded to the executor:
//  1. endpoint ACL admission (reachability)
//  2. Query.Validate (well-formed, size-capped, no control-char smuggling)
//  3. sqlguard.Check (single read-only SELECT; no DDL/DML/CTE/stacking) → tables
//  4. sqlguard.CheckRedaction (no redacted column in a predicate)
//  5. per-identity table grant (every referenced table must be granted)
//  6. forward → cap rows/bytes → mask redacted columns → audit allow
func databaseHandler(exec dbExecutor, identify func(*http.Request) (pubKey, fqdn string), admit acl, grants dbGrants, cfg dbServeConfig, audit *policy.AuditLog) http.Handler {
	if cfg.MaxRows <= 0 {
		cfg.MaxRows = defaultDBMaxRows
	}
	if cfg.MaxBytes <= 0 {
		cfg.MaxBytes = defaultDBMaxBytes
	}
	mux := http.NewServeMux()

	mux.HandleFunc("/v1/database/query", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		pubKey, fqdn := identify(r)
		if !admit.allows(pubKey, fqdn) {
			dbAudit(audit, fqdn, pubKey, "", "deny", "endpoint ACL: caller not permitted", "")
			http.Error(w, "not permitted", http.StatusForbidden)
			return
		}
		var q sqlguard.Query
		if !decodeJSONBody(w, r, &q) {
			return
		}
		if err := q.Validate(); err != nil {
			dbAudit(audit, fqdn, pubKey, q.DB, "deny", "invalid request: "+err.Error(), q.Hash())
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		hash := q.Hash()

		// The SQL guard and the grant check run BEFORE the executor is touched; a
		// rejected query is audited and never forwarded.
		tables, err := sqlguard.Check(q.SQL)
		if err != nil {
			dbDeny(w, audit, fqdn, pubKey, q.DB, err.Error(), hash)
			return
		}
		if err := sqlguard.CheckRedaction(q.SQL, cfg.Redact); err != nil {
			dbDeny(w, audit, fqdn, pubKey, q.DB, err.Error(), hash)
			return
		}
		if ok, reason := grants.authorize(pubKey, fqdn, q.DB, tables); !ok {
			dbDeny(w, audit, fqdn, pubKey, q.DB, reason, hash)
			return
		}

		raw, err := exec.Exec(r.Context(), q.DB, q.SQL, q.Params)
		if err != nil {
			dbAudit(audit, fqdn, pubKey, q.DB, "deny", "executor error: "+err.Error(), hash)
			http.Error(w, "query backend error", http.StatusBadGateway)
			return
		}

		rows, truncated := sqlguard.ApplyCaps(raw.Rows, dbRowCap(q.Limit, cfg.MaxRows), cfg.MaxBytes)
		rows, redacted := sqlguard.ApplyRedaction(raw.Columns, rows, cfg.Redact)
		res := sqlguard.QueryResult{
			DB:        q.DB,
			Columns:   nonNilColumns(raw.Columns),
			Rows:      nonNilRows(rows),
			RowCount:  len(rows),
			Truncated: truncated,
			Redacted:  redacted,
			QueryHash: hash,
		}

		// Audit the allow BEFORE returning rows so audit is a control: if the ledger
		// cannot accept the record and the log is fail-closed, deny rather than serve
		// data unrecorded.
		reason := fmt.Sprintf("%d row(s)", res.RowCount)
		if truncated {
			reason += " (truncated)"
		}
		if err := dbAudit(audit, fqdn, pubKey, q.DB, "allow", reason, hash); err != nil && audit.FailClosed() {
			http.Error(w, "audit ledger unavailable", http.StatusServiceUnavailable)
			return
		}
		writeJSONResp(w, http.StatusOK, res)
	})

	// Discovery: the db.table entries the caller's identity may read — per-caller
	// filtered like air catalog. Reachability-gated (the endpoint ACL), so an
	// un-allowed or unidentifiable peer learns nothing.
	mux.HandleFunc("/v1/database/tables", func(w http.ResponseWriter, r *http.Request) {
		if !getOnly(w, r) {
			return
		}
		pubKey, fqdn := identify(r)
		if !admit.allows(pubKey, fqdn) {
			http.Error(w, "not permitted", http.StatusForbidden)
			return
		}
		entries := grants.entriesFor(pubKey, fqdn)
		sort.Strings(entries)
		writeJSONResp(w, http.StatusOK, map[string]any{"tables": dedupeStrings(entries), "you": fqdnOr(fqdn)})
	})

	return mux
}

const (
	defaultDBMaxRows  = 1000
	defaultDBMaxBytes = 1 << 20
)

// dbRowCap is the effective row ceiling for one query: the endpoint maximum,
// lowered (never raised) by a caller's --limit.
func dbRowCap(callerLimit, max int) int {
	if callerLimit > 0 && callerLimit < max {
		return callerLimit
	}
	return max
}

// dbDeny audits a guard/grant rejection and writes a 403. The reason is the guard
// or grant's own message, so the caller sees exactly why and the ledger records
// it. A rejected query is never forwarded to the executor.
func dbDeny(w http.ResponseWriter, audit *policy.AuditLog, fqdn, pubKey, db, reason, hash string) {
	dbAudit(audit, fqdn, pubKey, db, "deny", reason, hash)
	http.Error(w, reason, http.StatusForbidden)
}

// dbAudit appends one query record to the shared ledger. Backend "database" lets
// `air stream --backend database` filter to queries; the normalized-statement
// hash rides in Provenance so a receipt proves WHICH statement ran without storing
// the (possibly sensitive) bind values. A nil ledger is a no-op. The returned
// error lets the allow path fail closed.
func dbAudit(audit *policy.AuditLog, fqdn, pubKey, db, decision, reason, hash string) error {
	if audit == nil {
		return nil
	}
	rec := policy.AuditRecord{
		Backend:  "database",
		Peer:     fqdnOr(fqdn),
		PeerKey:  pubKey,
		Method:   "air/database/query",
		Tool:     db,
		Decision: decision,
		Reason:   reason,
		Rule:     -1,
	}
	if hash != "" {
		rec.Provenance = []string{"sql:" + hash}
	}
	return audit.Append(rec)
}

func nonNilColumns(c []sqlguard.Column) []sqlguard.Column {
	if c == nil {
		return []sqlguard.Column{}
	}
	return c
}

func nonNilRows(r [][]any) [][]any {
	if r == nil {
		return [][]any{}
	}
	return r
}

func dedupeStrings(s []string) []string {
	if len(s) == 0 {
		return []string{}
	}
	out := make([]string, 0, len(s))
	seen := map[string]bool{}
	for _, v := range s {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

// --- serve ----------------------------------------------------------------

func cmdAirDatabaseServe(args []string) error {
	fs := flag.NewFlagSet("air database serve", flag.ExitOnError)
	o := meshFlags(fs)
	port := fs.Int("port", 9150, "mesh port to serve the query firewall on")
	auditPath := fs.String("audit", "", "append every query (allow/deny) to this hash-chained JSONL ledger (strongly recommended)")
	failClosed := fs.Bool("fail-closed", false, "deny any query that cannot be written to the audit ledger (audit as a control)")
	maxRows := fs.Int("max-rows", defaultDBMaxRows, "hard ceiling on rows returned (a caller --limit may only lower it)")
	maxBytes := fs.Int("max-bytes", defaultDBMaxBytes, "hard ceiling on result bytes")
	allow := multiFlag{}
	fs.Var(&allow, "allow", "identity permitted to reach the endpoint (FQDN glob or pubkey:<key>); repeatable; REQUIRED")
	grantFlags := multiFlag{}
	fs.Var(&grantFlags, "grant", "table grant: id=db.table[,db.table...] (id is an FQDN glob or pubkey:<key>); repeatable")
	redactFlags := multiFlag{}
	fs.Var(&redactFlags, "redact", "column masked in results and forbidden in predicates (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	// Serving a database firewall is privileged: without an --allow list any mesh
	// peer could reach the query surface, so require it (the per-table grant then
	// decides what each reachable caller may actually read). Mirrors air rag/kg serve.
	if len(allow) == 0 {
		return errors.New("air database serve: --allow <id> is required (who may reach the endpoint); deny-by-default")
	}
	grants, err := parseDBGrants(grantFlags)
	if err != nil {
		return fmt.Errorf("air database serve: %w", err)
	}

	audit, closeAudit, err := openDBAudit(*auditPath, *failClosed)
	if err != nil {
		return fmt.Errorf("air database serve: %w", err)
	}
	defer closeAudit()
	if audit == nil {
		fmt.Fprintln(os.Stderr, amber("warning:")+" --audit not set; queries run un-recorded. Pass --audit <file> for a tamper-evident ledger.")
	}

	o.BlockInbound = false // we listen for callers on the mesh
	client, err := startMesh(o, os.Stderr)
	if err != nil {
		return err
	}
	defer stopMesh(client)

	// The production executor is a documented v1 stub: it refuses cleanly until a
	// concrete mesh database backend is wired behind the seam.
	exec := meshDBExecutor{backend: fmt.Sprintf(":%d", *port)}
	cfg := dbServeConfig{MaxRows: *maxRows, MaxBytes: *maxBytes, Redact: []string(redactFlags)}
	identify := func(r *http.Request) (string, string) { return peerIdentityStr(client, r.RemoteAddr) }
	h := databaseHandler(exec, identify, newACL(allow), grants, cfg, audit)

	ln, err := client.ListenTCP(fmt.Sprintf(":%d", *port))
	if err != nil {
		return fmt.Errorf("air database serve: listen on mesh port %d: %w", *port, err)
	}
	defer ln.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	go func() { <-ctx.Done(); ln.Close() }()

	fmt.Fprintf(os.Stderr, dim("air database firewall on mesh port ")+bold(fmt.Sprint(*port))+
		dim(" · SELECT-only · %d grant(s) · %d redacted · POST /v1/database/query · Ctrl-C to stop\n"),
		len(grants), len(redactFlags))
	if err := newLocalHTTPServer("", h).Serve(ln); err != nil && ctx.Err() == nil {
		return err
	}
	return nil
}

// openDBAudit opens (or continues) the hash-chained ledger at path, seeding from
// the existing tail so a restart extends the chain rather than resetting it.
// failClosed makes an unwritable ledger deny queries. A blank path yields a nil
// log (queries run un-recorded, with a startup warning). Redaction of the returned
// column names in serve output is not needed — this only opens the ledger.
func openDBAudit(path string, failClosed bool) (*policy.AuditLog, func(), error) {
	if path == "" {
		return nil, func() {}, nil
	}
	seq, lastHash, err := seedAuditFromExisting(path)
	if err != nil {
		return nil, func() {}, fmt.Errorf("audit ledger: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, func() {}, fmt.Errorf("open audit ledger %s: %w", path, err)
	}
	log := policy.NewAuditLog(f, nowRFC3339).WithFailClosed(failClosed)
	if seq > 0 {
		log.SeedFrom(seq, lastHash)
	}
	return log, func() { _ = f.Close() }, nil
}
