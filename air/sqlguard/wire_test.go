package sqlguard

import (
	"errors"
	"reflect"
	"testing"
)

func TestQueryValidate_RejectsEmptyAndControlChars(t *testing.T) {
	if err := (Query{DB: "", SQL: "SELECT 1"}).Validate(); err == nil {
		t.Errorf("empty db accepted")
	}
	if err := (Query{DB: "a", SQL: "   "}).Validate(); err == nil {
		t.Errorf("blank sql accepted")
	}
	if err := (Query{DB: "a", SQL: "SELECT 1\x00 DROP"}).Validate(); !errors.Is(err, ErrControlChars) {
		t.Errorf("NUL smuggling: err = %v, want ErrControlChars", err)
	}
	if err := (Query{DB: "a", SQL: "SELECT\t1\nFROM t"}).Validate(); err != nil {
		t.Errorf("ordinary whitespace rejected: %v", err)
	}
}

func TestQueryHash_StableAcrossFormatting(t *testing.T) {
	a := Query{DB: "analytics", SQL: "SELECT  a,\n b   FROM t ;"}
	b := Query{DB: "analytics", SQL: "SELECT a, b FROM t"}
	if a.Hash() != b.Hash() {
		t.Fatalf("normalized-equivalent statements hashed differently:\n %s\n %s", a.Hash(), b.Hash())
	}
	c := Query{DB: "other", SQL: "SELECT a, b FROM t"}
	if a.Hash() == c.Hash() {
		t.Fatalf("different db must change the hash")
	}
}

func TestApplyCaps_TruncatesAtRowCap(t *testing.T) {
	rows := [][]any{{1}, {2}, {3}, {4}, {5}}
	out, trunc := ApplyCaps(rows, 3, 0)
	if len(out) != 3 || !trunc {
		t.Fatalf("row cap: got %d rows trunc=%v, want 3 rows trunc=true", len(out), trunc)
	}
}

func TestApplyCaps_TruncatesAtByteCap(t *testing.T) {
	rows := [][]any{
		{"aaaaaaaaaa"}, {"bbbbbbbbbb"}, {"cccccccccc"},
	}
	// First row (~11 bytes) fits; the second would exceed a tiny byte budget.
	out, trunc := ApplyCaps(rows, 0, 12)
	if len(out) != 1 || !trunc {
		t.Fatalf("byte cap: got %d rows trunc=%v, want 1 row trunc=true", len(out), trunc)
	}
}

func TestApplyCaps_UnderCapNotTruncated(t *testing.T) {
	rows := [][]any{{1}, {2}}
	out, trunc := ApplyCaps(rows, 10, 1<<20)
	if len(out) != 2 || trunc {
		t.Fatalf("under cap wrongly truncated: %d rows trunc=%v", len(out), trunc)
	}
}

func TestApplyRedaction_MasksAndReportsAndDoesNotMutate(t *testing.T) {
	cols := []Column{{Name: "name"}, {Name: "email"}, {Name: "SSN"}}
	rows := [][]any{{"Aria", "a@x.com", "111"}, {"Ben", "b@x.com", "222"}}
	out, redacted := ApplyRedaction(cols, rows, []string{"email", "ssn"})

	// Names keep their original case and sort in byte order ('S' < 'e' in ASCII).
	if !reflect.DeepEqual(redacted, []string{"SSN", "email"}) {
		t.Fatalf("redacted names = %v, want [SSN email]", redacted)
	}
	for _, r := range out {
		if r[1] != "[redacted]" || r[2] != "[redacted]" {
			t.Fatalf("email/ssn not masked: %v", r)
		}
		if r[0] == "[redacted]" {
			t.Fatalf("name wrongly masked: %v", r)
		}
	}
	// Original input rows must be untouched (immutability).
	if rows[0][1] != "a@x.com" {
		t.Fatalf("input row mutated: %v", rows[0])
	}
}

func TestApplyRedaction_NoMatchReturnsInput(t *testing.T) {
	cols := []Column{{Name: "name"}}
	rows := [][]any{{"Aria"}}
	out, redacted := ApplyRedaction(cols, rows, []string{"email"})
	if redacted != nil {
		t.Fatalf("unexpected redacted names: %v", redacted)
	}
	if !reflect.DeepEqual(out, rows) {
		t.Fatalf("rows changed with no matching column")
	}
}
