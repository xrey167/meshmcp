package sqlguard

import "testing"

// kinds projects a token slice onto its kinds, for compact assertions.
func texts(toks []Token) []string {
	out := make([]string, len(toks))
	for i, t := range toks {
		out[i] = t.Text
	}
	return out
}

func TestTokenize_DropsCommentsAndWhitespace(t *testing.T) {
	toks, err := Tokenize("SELECT 1 -- a line comment\n , 2 /* block */ , 3")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := texts(toks)
	want := []string{"SELECT", "1", ",", "2", ",", "3"}
	if len(got) != len(want) {
		t.Fatalf("token count = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("token[%d] = %q, want %q (all: %v)", i, got[i], want[i], got)
		}
	}
}

func TestTokenize_CommentHiddenDMLBecomesRealTokens(t *testing.T) {
	// The `--` runs only to the newline; the DROP on the next line is real SQL and
	// MUST surface as its own Word token so the guard can reject it.
	toks, err := Tokenize("SELECT 1 --\nDROP TABLE t")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var sawDrop bool
	for _, tk := range toks {
		if tk.Kind == TokenWord && tk.Text == "DROP" {
			sawDrop = true
		}
	}
	if !sawDrop {
		t.Fatalf("expected DROP to surface as a token, got %v", texts(toks))
	}
}

func TestTokenize_SemicolonInsideStringIsNotASeparator(t *testing.T) {
	toks, err := Tokenize("SELECT ';drop table t'")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(toks) != 2 {
		t.Fatalf("want SELECT + one string token, got %v", texts(toks))
	}
	if toks[1].Kind != TokenString || toks[1].Text != ";drop table t" {
		t.Fatalf("string token = %+v, want opaque \";drop table t\"", toks[1])
	}
	for _, tk := range toks {
		if tk.Kind == TokenSemicolon {
			t.Fatalf("semicolon inside string wrongly tokenized as a separator")
		}
	}
}

func TestTokenize_EscapedSingleQuote(t *testing.T) {
	toks, err := Tokenize("SELECT 'it''s fine'")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(toks) != 2 || toks[1].Kind != TokenString || toks[1].Text != "it''s fine" {
		t.Fatalf("escaped-quote string mis-tokenized: %v", texts(toks))
	}
}

func TestTokenize_QuotedIdentifiersAreOpaque(t *testing.T) {
	// A column literally named "from" and a bracketed [drop table] must be
	// identifiers, never the FROM keyword or a DDL verb.
	toks, err := Tokenize(`SELECT "from", ` + "`select`" + `, [drop table] FROM t`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var quoted int
	for _, tk := range toks {
		if tk.Kind == TokenQuotedIdent {
			quoted++
		}
	}
	if quoted != 3 {
		t.Fatalf("want 3 quoted identifiers, got %d (%v)", quoted, texts(toks))
	}
}

func TestTokenize_StackedSemicolonSeparates(t *testing.T) {
	toks, err := Tokenize("SELECT 1; SELECT 2")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var semis int
	for _, tk := range toks {
		if tk.Kind == TokenSemicolon {
			semis++
		}
	}
	if semis != 1 {
		t.Fatalf("want one semicolon separator, got %d", semis)
	}
}

func TestTokenize_UnterminatedStringErrors(t *testing.T) {
	if _, err := Tokenize("SELECT 'oops"); err == nil {
		t.Fatalf("expected an unterminated-string error")
	}
}

func TestTokenize_UnterminatedIdentErrors(t *testing.T) {
	if _, err := Tokenize(`SELECT "oops`); err == nil {
		t.Fatalf("expected an unterminated-identifier error")
	}
}
