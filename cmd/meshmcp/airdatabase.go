package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/xrey167/meshmcp/air/sqlguard"
)

// Air · Database — the firewall between an agent and a database.
//
// `air database` is NOT an embedded database engine. It is a governance layer
// that sits between a mesh agent and a database reachable on the mesh: it resolves
// the caller's cryptographic identity, admits it deny-by-default behind an ACL,
// validates the SQL through the pure read-only guard (air/sqlguard), gates every
// referenced table against a per-identity grant, forwards the VALIDATED query to a
// pluggable executor seam, caps and redacts the result, and notarizes every query
// — allowed or denied — in the shared hash-chained audit ledger. It executes no
// SQL itself and adds no database driver dependency: in production the executor
// forwards to a database exposed on the mesh; in tests a fake returns canned rows.
//
//	meshmcp air database query <host:port> --db <name> [--param v] [--limit N] [--json] "SELECT ..."
//	meshmcp air database serve --allow <id> [--grant id=db.table,...] [--redact col] [--audit f] [--max-rows N] [--max-bytes N]
//	meshmcp air database ls    <host:port>                 (the db.table entries your identity may read)
func cmdAirDatabase(args []string) error {
	if len(args) == 0 {
		return databaseUsage()
	}
	switch args[0] {
	case "query", "q":
		return cmdAirDatabaseQuery(args[1:])
	case "serve":
		return cmdAirDatabaseServe(args[1:])
	case "ls", "tables":
		return cmdAirDatabaseLS(args[1:])
	case "-h", "--help", "help":
		return databaseUsage()
	default:
		return fmt.Errorf("meshmcp air database: unknown subcommand %q (want query | serve | ls)", args[0])
	}
}

func databaseUsage() error {
	fmt.Fprintln(os.Stderr, bold("meshmcp air database")+dim(" — the governed firewall between an agent and a database"))
	fmt.Fprintln(os.Stderr, "  "+bold("air database query")+" <host:port> --db <name> [--param v] [--limit N] [--json] \"SELECT ...\"")
	fmt.Fprintln(os.Stderr, "                     "+dim("ask a named database a read-only question (guarded, capped, redacted, audited)"))
	fmt.Fprintln(os.Stderr, "  "+bold("air database serve")+" --allow <id> [--grant id=db.table,...] [--redact col] [--audit f] [--max-rows N] [--max-bytes N]")
	fmt.Fprintln(os.Stderr, "                     "+dim("run the query firewall over the mesh (deny-by-default, SELECT-only, per-table grants)"))
	fmt.Fprintln(os.Stderr, "  "+bold("air database ls")+"    <host:port>                 "+dim("the db.table entries your identity may read"))
	fmt.Fprintln(os.Stderr, dim("  Read-only: only single SELECT statements are forwarded; every write/DDL, stacked or comment-hidden"))
	fmt.Fprintln(os.Stderr, dim("  statement is denied and recorded. Bind values ride as --param and are never interpolated into the SQL."))
	return nil
}

// dbExecutor is the seam the served firewall calls to actually run an ALREADY-
// VALIDATED, guard-approved read query against a database backend. The firewall
// decides WHETHER a query runs (identity, grant, guard, caps, redaction); the
// executor is only what runs it — a database exposed on the mesh in production, a
// fake in tests. It receives the SQL and its bound parameters separately, so a
// conforming executor MUST pass params as bind values, never string-interpolate
// them.
type dbExecutor interface {
	Exec(ctx context.Context, db, sql string, params []any) (dbRows, error)
}

// dbRows is the raw result an executor returns, before the firewall applies caps
// and redaction: the column headers and the rows as-read from the backend.
type dbRows struct {
	Columns []sqlguard.Column
	Rows    [][]any
}

// meshDBExecutor is the production executor seam — DEFERRED in v1. In production
// it would forward the validated statement to a database exposed on the mesh (a
// DB-as-MCP-tool / mesh DB endpoint) over the same governed transport the other
// Air verbs dial, and return its rows. Wiring that requires a concrete mesh
// database backend to target (and the corresponding bind-parameter contract),
// which cannot be exercised from here, so v1 ships the seam plus this documented
// stub that refuses cleanly. Tests inject a fake executor; a real deployment
// swaps this for the mesh-forwarding implementation.
type meshDBExecutor struct{ backend string }

func (m meshDBExecutor) Exec(context.Context, string, string, []any) (dbRows, error) {
	return dbRows{}, errors.New("air database: no mesh database backend wired (the production executor seam is a v1 stub; inject a real executor to forward validated reads)")
}

// dbGrant maps a caller identity pattern to the db.table entries it may read.
// Entries are "db.table" globs (e.g. "analytics.customers", "analytics.*"),
// matched case-insensitively. The operator sets grants (via --grant); nothing a
// caller sends can widen them — an identity with no matching grant reads nothing.
type dbGrant struct {
	pattern acl
	tables  []string // lowercased "db.table" glob entries
}

type dbGrants []dbGrant

// entriesFor returns the union of db.table entries granted to a caller across
// every matching pattern. Deny-by-default: an unidentifiable caller, or one no
// pattern matches, gets nothing.
func (g dbGrants) entriesFor(pubKey, fqdn string) []string {
	if pubKey == "" && fqdn == "" {
		return nil
	}
	var out []string
	for _, e := range g {
		if e.pattern.allows(pubKey, fqdn) {
			out = append(out, e.tables...)
		}
	}
	return out
}

// authorize reports whether the caller may run a query on db that references the
// given bare tables: the caller must hold at least one grant, and every
// referenced table (qualified as "db.table") must match a granted entry. It
// returns a stable deny reason for the audit ledger on refusal.
func (g dbGrants) authorize(pubKey, fqdn, db string, tables []string) (bool, string) {
	granted := g.entriesFor(pubKey, fqdn)
	if len(granted) == 0 {
		return false, "no table grant for your identity"
	}
	dbl := strings.ToLower(db)
	for _, t := range tables {
		q := dbl + "." + strings.ToLower(t)
		if !matchAnyGlob(granted, q) {
			return false, "table not granted: " + t
		}
	}
	return true, ""
}

// matchAnyGlob reports whether q matches any of the glob patterns.
func matchAnyGlob(patterns []string, q string) bool {
	for _, p := range patterns {
		if globMatch(p, q) {
			return true
		}
	}
	return false
}

// parseDBGrants turns --grant "id=db.table[,db.table...]" flags into the
// operator's identity→tables policy. A malformed entry is a hard error so a typo
// never silently widens or narrows access. Entries are lowercased for
// case-insensitive matching against a query's referenced tables.
func parseDBGrants(flags []string) (dbGrants, error) {
	var grants dbGrants
	for _, raw := range flags {
		id, list, ok := strings.Cut(raw, "=")
		if !ok || id == "" {
			return nil, fmt.Errorf("bad --grant %q: want id=db.table[,db.table...]", raw)
		}
		var tables []string
		for _, t := range strings.Split(list, ",") {
			if t = strings.ToLower(strings.TrimSpace(t)); t != "" {
				if !strings.Contains(t, ".") {
					return nil, fmt.Errorf("bad --grant %q: entry %q must be db.table", raw, t)
				}
				tables = append(tables, t)
			}
		}
		if len(tables) == 0 {
			return nil, fmt.Errorf("bad --grant %q: no db.table entries listed", raw)
		}
		grants = append(grants, dbGrant{pattern: newACL([]string{id}), tables: tables})
	}
	return grants, nil
}

// --- client: query --------------------------------------------------------

func cmdAirDatabaseQuery(args []string) error {
	fs := flag.NewFlagSet("air database query", flag.ExitOnError)
	o := meshFlags(fs)
	db := fs.String("db", "", "named database to query (required)")
	limit := fs.Int("limit", 0, "ask for at most N rows (the firewall clamps to its own cap)")
	asJSON := fs.Bool("json", false, "print the raw QueryResult JSON")
	params := multiFlag{}
	fs.Var(&params, "param", "positional bind value for a ? placeholder (repeatable, in order)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 2 {
		return errors.New(`usage: meshmcp air database query [flags] <host:port> --db <name> "SELECT ..."`)
	}
	if *db == "" {
		return errors.New("air database query: --db is required")
	}
	addr := fs.Arg(0)
	sql := strings.Join(fs.Args()[1:], " ")

	q := sqlguard.Query{DB: *db, SQL: sql, Limit: *limit, Params: stringsToAny(params)}
	if err := q.Validate(); err != nil {
		return fmt.Errorf("air database query: %w", err)
	}

	hc, cleanup, err := airControlHTTP(o, addr)
	if err != nil {
		return err
	}
	defer cleanup()

	body, _ := json.Marshal(q)
	resp, err := hc.Post("http://air-database/v1/database/query", "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("air database query: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("air database query: %s: %s", resp.Status, bytes.TrimSpace(raw))
	}
	if *asJSON {
		fmt.Println(string(bytes.TrimSpace(raw)))
		return nil
	}
	var res sqlguard.QueryResult
	if err := json.Unmarshal(raw, &res); err != nil {
		return fmt.Errorf("air database query: bad response: %w", err)
	}
	renderQueryResult(res)
	return nil
}

// renderQueryResult prints a QueryResult as an aligned table plus an honest
// footer noting any governance that shaped the answer (redaction, truncation).
func renderQueryResult(res sqlguard.QueryResult) {
	if len(res.Columns) == 0 || res.RowCount == 0 {
		fmt.Fprintln(os.Stderr, dim("no rows"))
		return
	}
	headers := make([]string, len(res.Columns))
	for i, c := range res.Columns {
		headers[i] = c.Name
	}
	var rows [][]cell
	for _, r := range res.Rows {
		row := make([]cell, len(headers))
		for i := range headers {
			if i < len(r) {
				row[i] = plain(fmt.Sprint(r[i]))
			} else {
				row[i] = plain("")
			}
		}
		rows = append(rows, row)
	}
	renderTable(os.Stdout, headers, rows)
	note := fmt.Sprintf("%d row(s)", res.RowCount)
	if len(res.Redacted) > 0 {
		note += amber(" · redacted " + strings.Join(res.Redacted, ", "))
	}
	if res.Truncated {
		note += amber(" · truncated (more rows exist)")
	}
	fmt.Fprintln(os.Stderr, dim(note))
}

// --- client: ls -----------------------------------------------------------

func cmdAirDatabaseLS(args []string) error {
	fs := flag.NewFlagSet("air database ls", flag.ExitOnError)
	o := meshFlags(fs)
	asJSON := fs.Bool("json", false, "print the raw JSON list")
	if err := fs.Parse(args); err != nil {
		return err
	}
	control, err := resolveControlPositional(fs.NArg(), fs.Arg(0), "usage: meshmcp air database ls [flags] <host:port>")
	if err != nil {
		return err
	}
	hc, cleanup, err := airControlHTTP(o, control)
	if err != nil {
		return err
	}
	defer cleanup()

	resp, err := hc.Get("http://air-database/v1/database/tables")
	if err != nil {
		return fmt.Errorf("air database ls: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("air database ls: %s: %s", resp.Status, bytes.TrimSpace(raw))
	}
	if *asJSON {
		fmt.Println(string(bytes.TrimSpace(raw)))
		return nil
	}
	var out struct {
		Tables []string `json:"tables"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return fmt.Errorf("air database ls: bad response: %w", err)
	}
	if len(out.Tables) == 0 {
		fmt.Fprintln(os.Stderr, dim("no tables granted to your identity"))
		return nil
	}
	for _, t := range out.Tables {
		fmt.Println(t)
	}
	return nil
}

// stringsToAny widens a []string of CLI --param values to []any bind arguments.
func stringsToAny(s []string) []any {
	if len(s) == 0 {
		return nil
	}
	out := make([]any, len(s))
	for i, v := range s {
		out[i] = v
	}
	return out
}
