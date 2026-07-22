package sqlguard

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// Query is one governed database request delivered between mesh identities. It
// rides the Air control surface (HTTP-over-mesh); the served gateway resolves the
// caller's WireGuard identity from the transport, never from this struct — ID is
// a caller correlation label only, audited, never trusted for authorization.
//
// Params carry the positional bind values for the statement's placeholders. They
// are forwarded to the database backend as bound parameters and are NEVER
// interpolated into the SQL text, so an injection payload in a Param is inert.
type Query struct {
	DB     string `json:"db"`               // named database (required)
	SQL    string `json:"sql"`              // parameterized read statement (required)
	Params []any  `json:"params,omitempty"` // positional bind values for ? placeholders
	Limit  int    `json:"limit,omitempty"`  // caller-requested row cap (clamped by the gateway)
	ID     string `json:"id,omitempty"`     // caller correlation id (audited, not trusted)
}

// Column is a result column's name and, optionally, its declared type.
type Column struct {
	Name string `json:"name"`
	Type string `json:"type,omitempty"`
}

// QueryResult is what the gateway returns: columns, rows, and a truthful account
// of the governance that shaped the answer (capped, redacted). QueryHash is the
// sha256 of the normalized DB+SQL — the audit key that ties a receipt to the
// exact statement without storing the (possibly sensitive) bind values.
type QueryResult struct {
	DB        string   `json:"db"`
	Columns   []Column `json:"columns"`
	Rows      [][]any  `json:"rows"`
	RowCount  int      `json:"row_count"`
	Truncated bool     `json:"truncated,omitempty"` // hit a row/byte cap — more rows exist
	Redacted  []string `json:"redacted,omitempty"`  // columns whose values were masked
	QueryHash string   `json:"query_hash"`
}

// maxSQLBytes bounds a submitted statement so one request cannot force an
// unbounded tokenizer pass; well under any audit line cap.
const maxSQLBytes = 64 << 10

// ErrControlChars is returned by Validate for a statement carrying a NUL or other
// control character — a smuggling vector the guard refuses before tokenizing.
var ErrControlChars = errors.New("sqlguard: sql contains control characters")

// Validate checks the request is well-formed BEFORE any guard analysis: DB and
// SQL are present, SQL is within the size cap, and SQL carries no control-char
// smuggling (NUL, ESC, …; ordinary tab/newline/CR in whitespace are allowed).
func (q Query) Validate() error {
	if strings.TrimSpace(q.DB) == "" {
		return errors.New("sqlguard: db is required")
	}
	if strings.TrimSpace(q.SQL) == "" {
		return errors.New("sqlguard: sql is required")
	}
	if len(q.SQL) > maxSQLBytes {
		return fmt.Errorf("sqlguard: sql exceeds %d bytes", maxSQLBytes)
	}
	for _, r := range q.SQL {
		if r == '\t' || r == '\n' || r == '\r' {
			continue
		}
		if r < 0x20 || r == 0x7f {
			return ErrControlChars
		}
	}
	return nil
}

// NormalizeSQL collapses every run of whitespace to a single space and trims a
// trailing semicolon, producing a stable key for the query hash so that
// statements differing only in formatting hash identically.
func NormalizeSQL(sql string) string {
	return strings.TrimRight(strings.Join(strings.Fields(sql), " "), "; \t\n\r")
}

// Hash returns the sha256 of the normalized DB+SQL — the audit provenance key.
func (q Query) Hash() string {
	sum := sha256.Sum256([]byte(q.DB + "\n" + NormalizeSQL(q.SQL)))
	return hex.EncodeToString(sum[:])
}

// ApplyCaps enforces the result ceilings by STOPPING the scan at the cap rather
// than rewriting the SQL: it keeps at most maxRows rows and stops once the
// running byte estimate would exceed maxBytes (always keeping at least one row so
// a single wide row is not silently dropped). It returns the kept rows and
// whether more existed — the honest Truncated flag, never an error. A non-positive
// cap means "unbounded" for that dimension.
func ApplyCaps(rows [][]any, maxRows, maxBytes int) (out [][]any, truncated bool) {
	out = make([][]any, 0, len(rows))
	bytesUsed := 0
	for _, row := range rows {
		if maxRows > 0 && len(out) >= maxRows {
			return out, true
		}
		sz := rowBytes(row)
		if maxBytes > 0 && len(out) > 0 && bytesUsed+sz > maxBytes {
			return out, true
		}
		bytesUsed += sz
		out = append(out, row)
	}
	return out, false
}

// rowBytes is a cheap upper-ish estimate of a row's serialized size, summing the
// printed length of each cell. It need not be exact — it only bounds how much a
// single answer can stream, so an approximation that never undercounts wildly is
// enough.
func rowBytes(row []any) int {
	total := 0
	for _, v := range row {
		if v == nil {
			total += 4
			continue
		}
		total += len(fmt.Sprint(v)) + 1
	}
	return total
}

// ApplyRedaction masks the values of any result column whose name matches redact
// (case-insensitively, on the bare column name), returning NEW rows (the input is
// never mutated) and the sorted names of the columns actually masked. This is the
// display half of the redaction model; CheckRedaction is the control half that
// forbids the same columns in predicates so a masked value cannot be inferred.
func ApplyRedaction(cols []Column, rows [][]any, redact []string) (out [][]any, redacted []string) {
	if len(redact) == 0 || len(cols) == 0 {
		return rows, nil
	}
	set := make(map[string]bool, len(redact))
	for _, c := range redact {
		if c = strings.ToLower(strings.TrimSpace(c)); c != "" {
			set[c] = true
		}
	}
	maskCol := make([]bool, len(cols))
	seen := map[string]bool{}
	for i, c := range cols {
		if set[strings.ToLower(c.Name)] {
			maskCol[i] = true
			if !seen[c.Name] {
				seen[c.Name] = true
				redacted = append(redacted, c.Name)
			}
		}
	}
	if len(redacted) == 0 {
		return rows, nil
	}
	out = make([][]any, len(rows))
	for r, row := range rows {
		nr := make([]any, len(row))
		copy(nr, row)
		for i := range nr {
			if i < len(maskCol) && maskCol[i] {
				nr[i] = redactedValue
			}
		}
		out[r] = nr
	}
	sortStrings(redacted)
	return out, redacted
}

// redactedValue is the placeholder a masked cell carries on the wire.
const redactedValue = "[redacted]"

// sortStrings is a tiny insertion sort (no import of sort for one small slice)
// giving the reported redacted-column names a stable order.
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}
