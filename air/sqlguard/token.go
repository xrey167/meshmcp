// Package sqlguard is the pure, mesh-independent SQL-safety core of the Air
// `database` verb: a dialect-aware tokenizer and a read-only statement guard
// that decide whether an agent's SQL may be forwarded to a database on the mesh.
//
// It executes no SQL and opens no driver — it only classifies a statement and,
// when the statement is a safe single read, reports the tables it touches so the
// governed surface (cmd/meshmcp) can gate them against a per-identity grant. All
// value binding, capping and redaction of RESULTS is likewise pure here; the
// forwarding, identity resolution and audit live in the main package around it.
//
// The design bias is a firewall's: it is conservative. It accepts only a single
// SELECT with no writable-CTE surface, and it over-approximates the tables a
// query references (it may deny a legitimate query, but it must never let an
// unlisted table through unchecked). The load-bearing rule is that classification
// runs on a REAL tokenizer — comments, string literals with ” escapes, quoted
// identifiers and semicolons-inside-strings are all handled before any keyword is
// inspected — so the comment-hidden-DML and statement-stacking bypasses that
// defeat naive string matching cannot reach the guard.
package sqlguard

// TokenKind classifies one lexical token. Comments and whitespace are dropped
// during tokenizing, so they never appear as tokens — a comment can therefore
// never hide a keyword from the guard, because the keyword after it becomes an
// ordinary Word token in its own right.
type TokenKind int

const (
	// TokenWord is an unquoted identifier or keyword (letters, digits, '_', '$').
	TokenWord TokenKind = iota
	// TokenString is a single-quoted string literal, with '' read as an escaped
	// quote. Its Text is the raw inner bytes; the guard treats it as opaque, so a
	// ';' or the word "drop" inside a string is never a separator or a keyword.
	TokenString
	// TokenQuotedIdent is a delimited identifier: "ansi", `mysql`, or [sqlserver].
	// Also opaque to the keyword scan — a column literally named "from" or a
	// bracketed [drop table] is a name, not a clause boundary or a DDL verb.
	TokenQuotedIdent
	// TokenNumber is a numeric literal.
	TokenNumber
	// TokenPunct is a single punctuation/operator byte (',', '(', '.', '=', '?', …).
	TokenPunct
	// TokenSemicolon is a statement separator seen OUTSIDE any string/comment —
	// the only thing that splits one submitted text into multiple statements.
	TokenSemicolon
)

// Token is one lexical unit. Text holds the token's bytes as written (for a
// string/quoted identifier, the inner content with escapes preserved).
type Token struct {
	Kind TokenKind
	Text string
}

// Tokenize splits sql into tokens, dropping whitespace and comments. It returns
// an error only on an unterminated string or quoted identifier — an obvious
// malformation the guard should reject rather than guess at. A never-closed
// block comment is treated as running to end of input (it hides nothing that
// could then execute), matching how SQL engines discard trailing comments.
func Tokenize(sql string) ([]Token, error) {
	var toks []Token
	i, n := 0, len(sql)
	for i < n {
		c := sql[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v':
			i++
		case c == '-' && i+1 < n && sql[i+1] == '-':
			// Line comment: skip to end of line (or input). The bytes after it
			// remain real SQL and will tokenize normally on the next iteration —
			// this is exactly what stops `SELECT 1 --\nDROP` from smuggling DROP.
			i += 2
			for i < n && sql[i] != '\n' {
				i++
			}
		case c == '/' && i+1 < n && sql[i+1] == '*':
			i += 2
			for i+1 < n && !(sql[i] == '*' && sql[i+1] == '/') {
				i++
			}
			if i+1 < n {
				i += 2 // consume the closing */
			} else {
				i = n // unterminated: discard to end
			}
		case c == '\'':
			tok, next, err := scanQuoted(sql, i, '\'')
			if err != nil {
				return nil, err
			}
			toks = append(toks, Token{Kind: TokenString, Text: tok})
			i = next
		case c == '"':
			tok, next, err := scanQuoted(sql, i, '"')
			if err != nil {
				return nil, err
			}
			toks = append(toks, Token{Kind: TokenQuotedIdent, Text: tok})
			i = next
		case c == '`':
			tok, next, err := scanQuoted(sql, i, '`')
			if err != nil {
				return nil, err
			}
			toks = append(toks, Token{Kind: TokenQuotedIdent, Text: tok})
			i = next
		case c == '[':
			// SQL Server bracket identifier: runs to the first ']' (no doubling).
			j := i + 1
			for j < n && sql[j] != ']' {
				j++
			}
			if j >= n {
				return nil, errUnterminatedIdent
			}
			toks = append(toks, Token{Kind: TokenQuotedIdent, Text: sql[i+1 : j]})
			i = j + 1
		case c == ';':
			toks = append(toks, Token{Kind: TokenSemicolon, Text: ";"})
			i++
		case isWordStart(c):
			j := i + 1
			for j < n && isWordPart(sql[j]) {
				j++
			}
			toks = append(toks, Token{Kind: TokenWord, Text: sql[i:j]})
			i = j
		case c >= '0' && c <= '9':
			j := i + 1
			for j < n && (sql[j] >= '0' && sql[j] <= '9' || sql[j] == '.' || sql[j] == 'e' || sql[j] == 'E' || sql[j] == '+' || sql[j] == '-' && (sql[j-1] == 'e' || sql[j-1] == 'E')) {
				j++
			}
			toks = append(toks, Token{Kind: TokenNumber, Text: sql[i:j]})
			i = j
		default:
			toks = append(toks, Token{Kind: TokenPunct, Text: string(c)})
			i++
		}
	}
	return toks, nil
}

// scanQuoted reads a quote-delimited run starting at the opening quote sql[start],
// treating a doubled quote (e.g. ” inside a string, or "" inside an identifier)
// as one escaped literal quote rather than a close. It returns the inner text
// (escapes preserved as written) and the index just past the closing quote.
func scanQuoted(sql string, start int, q byte) (text string, next int, err error) {
	n := len(sql)
	j := start + 1
	for j < n {
		if sql[j] == q {
			if j+1 < n && sql[j+1] == q { // doubled quote = escaped, not a close
				j += 2
				continue
			}
			return sql[start+1 : j], j + 1, nil
		}
		j++
	}
	if q == '\'' {
		return "", 0, errUnterminatedString
	}
	return "", 0, errUnterminatedIdent
}

func isWordStart(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '_' || c >= 0x80
}

func isWordPart(c byte) bool {
	return isWordStart(c) || c >= '0' && c <= '9' || c == '$'
}
