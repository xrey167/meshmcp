package sqlguard

import (
	"errors"
	"strings"
)

// Guard errors. They are sentinel values so the governed surface can audit a
// stable, greppable reason for every denial (and a caller sees one dignified
// line, never a driver's internals).
var (
	errUnterminatedString = errors.New("sqlguard: unterminated string literal")
	errUnterminatedIdent  = errors.New("sqlguard: unterminated quoted identifier")

	// ErrEmpty is returned for a statement with no tokens (blank or comment-only).
	ErrEmpty = errors.New("sqlguard: empty statement")
	// ErrMultipleStatements is returned when a second, non-empty statement follows
	// a semicolon — the statement-stacking bypass (a `SELECT 1; DROP TABLE t`).
	ErrMultipleStatements = errors.New("sqlguard: only a single statement is allowed")
	// ErrNotSelect is returned when the statement does not begin with SELECT. This
	// is also what rejects a WITH-prefixed statement, see the note on writable CTEs.
	ErrNotSelect = errors.New("sqlguard: only read-only SELECT statements are allowed")
	// ErrForbiddenKeyword is returned when a mutating/DDL keyword appears anywhere
	// in the statement — the defense that catches DML a comment or the projection
	// tried to smuggle past the leading-keyword check.
	ErrForbiddenKeyword = errors.New("sqlguard: statement contains a forbidden (write/DDL) keyword")
	// ErrRedactedInPredicate is returned when a redacted column is referenced
	// anywhere after the top-level FROM (WHERE/JOIN/GROUP/ORDER/HAVING, or inside a
	// subquery), which would let a caller infer a masked value.
	ErrRedactedInPredicate = errors.New("sqlguard: a redacted column may appear only in the top-level projection")
	// ErrRedactedNotBare is returned when a redacted column appears in the
	// projection in any form other than a bare (optionally schema-qualified)
	// column reference — aliased (`ssn AS x`), wrapped in a function or expression
	// (`lower(ssn)`, `ssn || ''`), or inside a projected subquery. Result-side
	// masking (ApplyRedaction) keys on the OUTPUT column name, so any of those
	// forms renames the column and would return the masked value in clear.
	ErrRedactedNotBare = errors.New("sqlguard: a redacted column may be projected only as a bare column, not aliased or wrapped in an expression")
)

// forbiddenKeywords are the reserved words a read-only guard rejects anywhere in
// the token stream. The leading-keyword check already requires SELECT, but a
// second layer that scans the WHOLE statement is what defeats comment-hidden or
// otherwise-positioned DML (`SELECT 1 --\nDROP TABLE t` tokenizes to a stream
// that still contains the DROP word). WITH is rejected outright: a writable CTE
// — `WITH x AS (DELETE ... RETURNING *) SELECT * FROM x` — reads as a SELECT to a
// naive prefix check but performs a write, so no WITH-prefixed statement is
// admitted in v1. Read-only set operators (UNION/INTERSECT/EXCEPT) are NOT here:
// they compose SELECTs, and every arm's tables are still extracted and gated.
var forbiddenKeywords = map[string]bool{
	"insert": true, "update": true, "delete": true, "drop": true,
	"alter": true, "create": true, "truncate": true, "replace": true,
	"merge": true, "upsert": true, "attach": true, "detach": true,
	"pragma": true, "vacuum": true, "reindex": true, "analyze": true,
	"grant": true, "revoke": true, "commit": true, "rollback": true,
	"begin": true, "savepoint": true, "set": true, "call": true,
	"exec": true, "execute": true, "do": true, "copy": true,
	"load": true, "with": true, "into": true, "returning": true,
}

// clauseBoundary marks the keywords that end a FROM item list, so table
// extraction knows where the table references stop and the predicate begins.
var clauseBoundary = map[string]bool{
	"where": true, "group": true, "order": true, "having": true,
	"limit": true, "offset": true, "union": true, "intersect": true,
	"except": true, "window": true, "for": true, "fetch": true,
	"join": true, "inner": true, "left": true, "right": true,
	"full": true, "cross": true, "outer": true, "natural": true,
	"on": true, "using": true,
}

var joinKeyword = map[string]bool{"join": true}

// Check runs the full read-only gauntlet over sql and, on success, returns the
// tables the statement references (each the bare table name, to be qualified by
// the caller's --db and gated against its grant). The first failing rule wins and
// is returned as a sentinel error the caller audits.
//
// Order: tokenize (real lexer) → reject empty → reject stacked statements →
// require a leading SELECT → reject any forbidden keyword anywhere → extract
// referenced tables. Redaction-scope enforcement is a separate call (CheckRedaction)
// because the redact set is per-endpoint policy the guard core does not own.
func Check(sql string) (tables []string, err error) {
	toks, err := Tokenize(sql)
	if err != nil {
		return nil, err
	}
	stmts := splitStatements(toks)
	if len(stmts) == 0 {
		return nil, ErrEmpty
	}
	if len(stmts) > 1 {
		return nil, ErrMultipleStatements
	}
	stmt := stmts[0]
	if first, ok := firstWord(stmt); !ok || !strings.EqualFold(first, "select") {
		return nil, ErrNotSelect
	}
	for _, t := range stmt {
		if t.Kind == TokenWord && forbiddenKeywords[strings.ToLower(t.Text)] {
			return nil, ErrForbiddenKeyword
		}
	}
	return referencedTables(stmt), nil
}

// CheckRedaction rejects a statement that would let an authorized reader recover a
// redacted column's value. Combined with masking the same columns in RESULTS
// (ApplyRedaction), this makes redaction real information-flow control: a caller
// may SELECT a redacted column (and receive [redacted]) but may not otherwise
// touch it. Two channels are closed:
//
//   - Predicate channel: a redacted column referenced anywhere after the top-level
//     FROM (WHERE/JOIN/GROUP/ORDER/HAVING, or inside a subquery there) could infer
//     the masked value, and is rejected (ErrRedactedInPredicate).
//   - Projection channel: result-side masking keys on the OUTPUT column name, so a
//     redacted column may be projected ONLY as a bare (optionally schema-qualified)
//     column reference whose output name is the redacted name. Aliasing it
//     (`ssn AS x`), wrapping it in a function or expression (`lower(ssn)`,
//     `ssn || ''`, `CASE WHEN ssn=? ...`), or hiding it in a projected subquery all
//     rename the output column so ApplyRedaction would not mask it — these are
//     rejected (ErrRedactedNotBare). Without this the guard's masking is trivially
//     defeated by `SELECT ssn AS x FROM t`.
//
// The "top-level FROM" is the first FROM at parenthesis depth 0; a FROM nested in a
// projected subquery does not end the projection (its redacted references are
// caught by the projection scan). redact entries are matched case-insensitively on
// the bare column name.
func CheckRedaction(sql string, redact []string) error {
	if len(redact) == 0 {
		return nil
	}
	toks, err := Tokenize(sql)
	if err != nil {
		return err
	}
	set := make(map[string]bool, len(redact))
	for _, c := range redact {
		if c = strings.ToLower(strings.TrimSpace(c)); c != "" {
			set[c] = true
		}
	}
	if len(set) == 0 {
		return nil
	}
	// Locate the leading SELECT and the top-level (depth-0) FROM that ends the
	// projection. A leading '(' (a parenthesized SELECT) is tolerated by scanning
	// for the SELECT word itself.
	selIdx := -1
	for i, t := range toks {
		if t.Kind == TokenWord && strings.EqualFold(t.Text, "select") {
			selIdx = i
			break
		}
	}
	if selIdx < 0 {
		return nil // not a SELECT — Check rejects these before this call
	}
	depth := 0
	fromIdx := -1
	for i := selIdx + 1; i < len(toks); i++ {
		t := toks[i]
		switch {
		case t.Kind == TokenPunct && t.Text == "(":
			depth++
		case t.Kind == TokenPunct && t.Text == ")":
			if depth > 0 {
				depth--
			}
		case depth == 0 && t.Kind == TokenWord && strings.EqualFold(t.Text, "from"):
			fromIdx = i
		}
		if fromIdx >= 0 {
			break
		}
	}
	// Predicate channel: anything after the top-level FROM.
	projEnd := len(toks)
	if fromIdx >= 0 {
		projEnd = fromIdx
		for _, t := range toks[fromIdx+1:] {
			if (t.Kind == TokenWord || t.Kind == TokenQuotedIdent) && set[strings.ToLower(t.Text)] {
				return ErrRedactedInPredicate
			}
		}
	}
	// Projection channel: [selIdx+1, projEnd). A redacted column may appear only as
	// a bare column reference the result-side masking can still match by name.
	proj := stripSelectQualifier(toks[selIdx+1 : projEnd])
	for _, item := range splitTopLevelCommas(proj) {
		if itemReferencesRedacted(item, set) && !itemIsBareRedactedRef(item, set) {
			return ErrRedactedNotBare
		}
	}
	return nil
}

// stripSelectQualifier drops a leading DISTINCT / ALL (and a `DISTINCT ON (...)`
// group) from a projection token list so the select-items that follow can be
// examined on their own.
func stripSelectQualifier(proj []Token) []Token {
	if len(proj) == 0 || proj[0].Kind != TokenWord {
		return proj
	}
	if !strings.EqualFold(proj[0].Text, "distinct") && !strings.EqualFold(proj[0].Text, "all") {
		return proj
	}
	i := 1
	if i < len(proj) && proj[i].Kind == TokenWord && strings.EqualFold(proj[i].Text, "on") {
		i++
		if i < len(proj) && proj[i].Kind == TokenPunct && proj[i].Text == "(" {
			i = skipParens(proj, i) + 1
		}
	}
	return proj[i:]
}

// splitTopLevelCommas splits a projection into select-items on parenthesis-depth-0
// commas (commas inside a function call or subquery are not item separators).
func splitTopLevelCommas(proj []Token) [][]Token {
	var items [][]Token
	var cur []Token
	depth := 0
	for _, t := range proj {
		switch {
		case t.Kind == TokenPunct && t.Text == "(":
			depth++
		case t.Kind == TokenPunct && t.Text == ")":
			if depth > 0 {
				depth--
			}
		case depth == 0 && t.Kind == TokenPunct && t.Text == ",":
			items = append(items, cur)
			cur = nil
			continue
		}
		cur = append(cur, t)
	}
	if len(cur) > 0 {
		items = append(items, cur)
	}
	return items
}

// itemReferencesRedacted reports whether any word/quoted-identifier token in the
// select-item names a redacted column.
func itemReferencesRedacted(item []Token, set map[string]bool) bool {
	for _, t := range item {
		if (t.Kind == TokenWord || t.Kind == TokenQuotedIdent) && set[strings.ToLower(t.Text)] {
			return true
		}
	}
	return false
}

// itemIsBareRedactedRef reports whether the select-item is a bare, optionally
// schema-qualified column reference — word ('.' word)* — whose FINAL component is a
// redacted column. That is the only projection form where ApplyRedaction's
// output-name masking still masks the value; any alias, function, operator, or
// subquery renames the output column and must be rejected.
func itemIsBareRedactedRef(item []Token, set map[string]bool) bool {
	if len(item) == 0 || len(item)%2 == 0 {
		return false // must be word ('.' word)* → an odd number of tokens
	}
	for i, t := range item {
		if i%2 == 0 {
			if t.Kind != TokenWord && t.Kind != TokenQuotedIdent {
				return false
			}
		} else if t.Kind != TokenPunct || t.Text != "." {
			return false
		}
	}
	last := item[len(item)-1]
	return set[strings.ToLower(last.Text)]
}

// splitStatements groups tokens by top-level semicolons, dropping empty groups
// (so a single trailing ';' does not read as a second, empty statement).
func splitStatements(toks []Token) [][]Token {
	var out [][]Token
	var cur []Token
	for _, t := range toks {
		if t.Kind == TokenSemicolon {
			if len(cur) > 0 {
				out = append(out, cur)
			}
			cur = nil
			continue
		}
		cur = append(cur, t)
	}
	if len(cur) > 0 {
		out = append(out, cur)
	}
	return out
}

// firstWord returns the first Word token's text, used for the leading-keyword
// check. A leading '(' (a parenthesized SELECT) is skipped so `(SELECT …)` is
// still recognized as read-only.
func firstWord(stmt []Token) (string, bool) {
	for _, t := range stmt {
		if t.Kind == TokenPunct && t.Text == "(" {
			continue
		}
		if t.Kind == TokenWord {
			return t.Text, true
		}
		return "", false
	}
	return "", false
}

// referencedTables extracts every table introduced by a FROM or JOIN anywhere in
// the statement. Because the guard has already ensured a single SELECT with no
// CTE, every table the query reads is introduced by one of these clauses, so a
// global scan is sound in the direction that matters: it never misses a table
// (missing one would let it past the grant unchecked). It may OVER-collect —
// e.g. the column in `EXTRACT(YEAR FROM col)` — which only over-denies. Names are
// de-duplicated; a schema-qualified name contributes its final component.
func referencedTables(stmt []Token) []string {
	var tables []string
	seen := map[string]bool{}
	add := func(name string) {
		if name == "" || seen[name] {
			return
		}
		seen[name] = true
		tables = append(tables, name)
	}
	// The outer index visits EVERY token, so a FROM/JOIN nested in a subquery is
	// reached on its own iteration. The from-list collection below uses a separate
	// local cursor and never advances i, which is what makes the scan catch inner
	// clauses that its own skipParens jumps over at the local level.
	for i := 0; i < len(stmt); i++ {
		t := stmt[i]
		if t.Kind != TokenWord {
			continue
		}
		switch {
		case strings.EqualFold(t.Text, "from"):
			collectFromList(stmt, i+1, add)
		case joinKeyword[strings.ToLower(t.Text)]:
			if name, _, ok := tableRef(stmt, i+1); ok {
				add(name)
			}
		}
	}
	return tables
}

// collectFromList reads the comma-separated table items after a FROM, stopping at
// the first clause boundary (WHERE/JOIN/…), an unbalanced ')' (the close of an
// enclosing subquery), or statement end. Each item's leading table reference is
// recorded; aliases and everything up to the next comma are skipped. A
// parenthesized subquery item contributes no name here — its own inner FROM/JOIN
// are picked up by the caller's global scan on their own iterations.
func collectFromList(stmt []Token, start int, add func(string)) {
	i := start
	expectTable := true
	for i < len(stmt) {
		t := stmt[i]
		if t.Kind == TokenWord && clauseBoundary[strings.ToLower(t.Text)] {
			return
		}
		if t.Kind == TokenPunct && t.Text == ")" {
			return // closes the subquery/group this FROM lives in
		}
		if expectTable {
			if t.Kind == TokenPunct && t.Text == "(" {
				i = skipParens(stmt, i) + 1
				expectTable = false
				continue
			}
			if name, next, ok := tableRef(stmt, i); ok {
				add(name)
				i = next + 1
				expectTable = false
				continue
			}
		} else if t.Kind == TokenPunct && t.Text == "," {
			expectTable = true
		}
		i++
	}
}

// tableRef reads a (possibly schema-qualified) table name starting at index i,
// returning the bare table name and the index of its last token. It returns
// ok=false when index i is not a name token.
func tableRef(stmt []Token, i int) (name string, last int, ok bool) {
	if i >= len(stmt) || (stmt[i].Kind != TokenWord && stmt[i].Kind != TokenQuotedIdent) {
		return "", 0, false
	}
	name, last = stmt[i].Text, i
	// Walk dotted qualification (schema.table, db.schema.table) to the final part.
	for last+2 < len(stmt) && stmt[last+1].Kind == TokenPunct && stmt[last+1].Text == "." &&
		(stmt[last+2].Kind == TokenWord || stmt[last+2].Kind == TokenQuotedIdent) {
		name = stmt[last+2].Text
		last += 2
	}
	return name, last, true
}

// skipParens returns the index of the matching ')' for the '(' at open, or the
// last index if unbalanced (the guard is scanning, not validating grammar).
func skipParens(stmt []Token, open int) int {
	depth := 0
	for i := open; i < len(stmt); i++ {
		if stmt[i].Kind == TokenPunct && stmt[i].Text == "(" {
			depth++
		} else if stmt[i].Kind == TokenPunct && stmt[i].Text == ")" {
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return len(stmt) - 1
}
