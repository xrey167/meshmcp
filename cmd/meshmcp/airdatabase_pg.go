package main

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	_ "github.com/jackc/pgx/v5/stdlib" // registers the "pgx" database/sql driver

	"github.com/xrey167/meshmcp/air/sqlguard"
)

// pgDBExecutor forwards ALREADY-VALIDATED read statements to named PostgreSQL
// databases. It fills the meshDBExecutor seam: authorization, read-only
// validation, grants, caps, and redaction all happened upstream in the
// firewall; this only runs the statement — with params always bound, never
// interpolated. An unknown db name fails closed.
type pgDBExecutor struct {
	dbs map[string]*sql.DB
}

// newPGDBExecutor opens one pool per "name=postgres://..." spec. Specs are
// operator config; errors never echo the DSN (it may carry credentials).
func newPGDBExecutor(specs []string) (*pgDBExecutor, error) {
	e := &pgDBExecutor{dbs: map[string]*sql.DB{}}
	for _, spec := range specs {
		name, dsn, ok := strings.Cut(spec, "=")
		name = strings.TrimSpace(name)
		if !ok || name == "" || strings.TrimSpace(dsn) == "" {
			e.Close()
			return nil, fmt.Errorf("--db must be name=postgres://... (got %q for the name part)", name)
		}
		if !isPostgresDSN(strings.TrimSpace(dsn)) {
			e.Close()
			return nil, fmt.Errorf("--db %s: only postgres:// / postgresql:// DSNs are supported", name)
		}
		if _, dup := e.dbs[name]; dup {
			e.Close()
			return nil, fmt.Errorf("--db %s: duplicate database name", name)
		}
		db, err := sql.Open("pgx", strings.TrimSpace(dsn))
		if err != nil {
			e.Close()
			return nil, fmt.Errorf("--db %s: %w", name, err)
		}
		e.dbs[name] = db
	}
	return e, nil
}

func (e *pgDBExecutor) Close() {
	for _, db := range e.dbs {
		_ = db.Close()
	}
}

func (e *pgDBExecutor) names() []string {
	out := make([]string, 0, len(e.dbs))
	for name := range e.dbs {
		out = append(out, name)
	}
	return out
}

func (e *pgDBExecutor) Exec(ctx context.Context, dbName, sqlText string, params []any) (dbRows, error) {
	db, ok := e.dbs[dbName]
	if !ok {
		// Fail closed without echoing the caller's db string back verbatim in a
		// position where it could be confused with configuration.
		return dbRows{}, fmt.Errorf("air database: no configured database matches the requested name")
	}
	rewritten, err := pgQuestionToDollar(sqlText)
	if err != nil {
		return dbRows{}, fmt.Errorf("air database: %w", err)
	}
	rows, err := db.QueryContext(ctx, rewritten, params...)
	if err != nil {
		return dbRows{}, fmt.Errorf("air database: query: %w", err)
	}
	defer rows.Close()

	cols, err := rows.Columns()
	if err != nil {
		return dbRows{}, fmt.Errorf("air database: columns: %w", err)
	}
	out := dbRows{Columns: make([]sqlguard.Column, len(cols))}
	types, _ := rows.ColumnTypes()
	for i, c := range cols {
		out.Columns[i] = sqlguard.Column{Name: c}
		if types != nil && i < len(types) {
			out.Columns[i].Type = strings.ToLower(types[i].DatabaseTypeName())
		}
	}
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return dbRows{}, fmt.Errorf("air database: scan: %w", err)
		}
		for i, v := range vals {
			if b, isBytes := v.([]byte); isBytes {
				vals[i] = string(b)
			}
		}
		out.Rows = append(out.Rows, vals)
	}
	if err := rows.Err(); err != nil {
		return dbRows{}, fmt.Errorf("air database: rows: %w", err)
	}
	return out, nil
}

// pgQuestionToDollar rewrites the wire contract's positional '?' placeholders
// to PostgreSQL's $1..$n. It walks the raw statement with the same lexical
// rules sqlguard tokenizes by, so a '?' inside a string literal, a quoted
// identifier, or a comment is never touched. The statement was already
// validated; this pass only re-spells placeholders.
func pgQuestionToDollar(sqlText string) (string, error) {
	var b strings.Builder
	b.Grow(len(sqlText) + 8)
	n := 0
	for i := 0; i < len(sqlText); {
		c := sqlText[i]
		switch {
		case c == '?':
			n++
			fmt.Fprintf(&b, "$%d", n)
			i++
		case c == '\'' || c == '"' || c == '`':
			// Quoted region: copy verbatim through the closing quote, honoring
			// doubled-quote escapes ('' / "" / ``).
			j := i + 1
			for j < len(sqlText) {
				if sqlText[j] == c {
					if j+1 < len(sqlText) && sqlText[j+1] == c {
						j += 2
						continue
					}
					j++
					break
				}
				j++
			}
			if j > len(sqlText) {
				j = len(sqlText)
			}
			b.WriteString(sqlText[i:j])
			i = j
		case c == '[':
			// Bracketed identifier: copy through ']'.
			j := strings.IndexByte(sqlText[i:], ']')
			if j < 0 {
				b.WriteString(sqlText[i:])
				i = len(sqlText)
				break
			}
			b.WriteString(sqlText[i : i+j+1])
			i += j + 1
		case c == '-' && i+1 < len(sqlText) && sqlText[i+1] == '-':
			// Line comment: copy through end of line.
			j := strings.IndexByte(sqlText[i:], '\n')
			if j < 0 {
				b.WriteString(sqlText[i:])
				i = len(sqlText)
				break
			}
			b.WriteString(sqlText[i : i+j+1])
			i += j + 1
		case c == '/' && i+1 < len(sqlText) && sqlText[i+1] == '*':
			// Block comment: copy through '*/' (or end of input, matching the
			// tokenizer's trailing-comment behavior).
			j := strings.Index(sqlText[i:], "*/")
			if j < 0 {
				b.WriteString(sqlText[i:])
				i = len(sqlText)
				break
			}
			b.WriteString(sqlText[i : i+j+2])
			i += j + 2
		default:
			b.WriteByte(c)
			i++
		}
	}
	return b.String(), nil
}
