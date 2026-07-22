package sqlguard

import (
	"errors"
	"reflect"
	"sort"
	"testing"
)

func TestCheck_AllowsPlainSelect(t *testing.T) {
	tables, err := Check("SELECT name, revenue FROM customers WHERE region = ?")
	if err != nil {
		t.Fatalf("plain SELECT rejected: %v", err)
	}
	if !reflect.DeepEqual(tables, []string{"customers"}) {
		t.Fatalf("tables = %v, want [customers]", tables)
	}
}

func TestCheck_AllowsParenthesizedSelect(t *testing.T) {
	if _, err := Check("(SELECT 1)"); err != nil {
		t.Fatalf("parenthesized SELECT rejected: %v", err)
	}
}

func TestCheck_RejectsMutationsAndDDL(t *testing.T) {
	cases := map[string]string{
		"insert": "INSERT INTO t (a) VALUES (1)",
		"update": "UPDATE t SET a = 1",
		"delete": "DELETE FROM t",
		"drop":   "DROP TABLE t",
		"alter":  "ALTER TABLE t ADD COLUMN c int",
		"create": "CREATE TABLE t (a int)",
		"attach": "ATTACH DATABASE 'x' AS y",
		"pragma": "PRAGMA table_info(t)",
		"set":    "SET x = 1",
	}
	for name, sql := range cases {
		if _, err := Check(sql); err == nil {
			t.Errorf("%s: expected rejection, got allow", name)
		}
	}
}

func TestCheck_RejectsLeadingNonSelect(t *testing.T) {
	if _, err := Check("EXPLAIN SELECT 1"); !errors.Is(err, ErrNotSelect) {
		t.Fatalf("EXPLAIN: err = %v, want ErrNotSelect", err)
	}
}

func TestCheck_RejectsWritableCTE(t *testing.T) {
	// A WITH-prefixed statement is refused outright: the classic writable-CTE
	// bypass reads as a SELECT to a prefix check but performs a write.
	sql := "WITH x AS (DELETE FROM t RETURNING *) SELECT * FROM x"
	if _, err := Check(sql); err == nil {
		t.Fatalf("writable CTE not rejected")
	}
	// Even a read-only WITH is rejected in v1 (documented), because the first word
	// is not SELECT.
	if _, err := Check("WITH x AS (SELECT 1) SELECT * FROM x"); !errors.Is(err, ErrNotSelect) {
		t.Fatalf("read-only WITH: err = %v, want ErrNotSelect", err)
	}
}

func TestCheck_RejectsStackedStatements(t *testing.T) {
	if _, err := Check("SELECT * FROM users; DROP TABLE customers"); !errors.Is(err, ErrMultipleStatements) {
		t.Fatalf("stacked: err = %v, want ErrMultipleStatements", err)
	}
}

func TestCheck_TrailingSemicolonIsSingleStatement(t *testing.T) {
	if _, err := Check("SELECT 1 FROM t;"); err != nil {
		t.Fatalf("trailing semicolon rejected: %v", err)
	}
}

func TestCheck_RejectsCommentHiddenDML(t *testing.T) {
	for _, sql := range []string{
		"SELECT 1 --\nDROP TABLE t",
		"SELECT 1 /* */ DROP TABLE t",
	} {
		if _, err := Check(sql); !errors.Is(err, ErrForbiddenKeyword) {
			t.Errorf("%q: err = %v, want ErrForbiddenKeyword", sql, err)
		}
	}
}

func TestCheck_SemicolonInStringIsSafeSelect(t *testing.T) {
	tables, err := Check("SELECT ';drop' AS note FROM t")
	if err != nil {
		t.Fatalf("string with ;drop rejected: %v", err)
	}
	if !reflect.DeepEqual(tables, []string{"t"}) {
		t.Fatalf("tables = %v, want [t]", tables)
	}
}

func TestCheck_EmptyRejected(t *testing.T) {
	if _, err := Check("   -- just a comment\n"); !errors.Is(err, ErrEmpty) {
		t.Fatalf("empty: err = %v, want ErrEmpty", err)
	}
}

func TestReferencedTables_JoinsCommaListsAndAliases(t *testing.T) {
	sql := "SELECT c.name, o.total FROM customers c, regions AS r " +
		"JOIN orders o ON o.cust = c.id LEFT JOIN shipments s ON s.oid = o.id " +
		"WHERE r.id = ?"
	tables, err := Check(sql)
	if err != nil {
		t.Fatalf("unexpected rejection: %v", err)
	}
	sort.Strings(tables)
	want := []string{"customers", "orders", "regions", "shipments"}
	if !reflect.DeepEqual(tables, want) {
		t.Fatalf("tables = %v, want %v", tables, want)
	}
}

func TestReferencedTables_SchemaQualifiedTakesFinalComponent(t *testing.T) {
	tables, err := Check("SELECT * FROM sales.customers WHERE id = ?")
	if err != nil {
		t.Fatalf("unexpected rejection: %v", err)
	}
	if !reflect.DeepEqual(tables, []string{"customers"}) {
		t.Fatalf("tables = %v, want [customers]", tables)
	}
}

func TestReferencedTables_SubqueryTablesAreCaught(t *testing.T) {
	// The inner FROM is found by the global scan; the outer FROM's item is a
	// parenthesized subquery contributing no name of its own.
	tables, err := Check("SELECT * FROM (SELECT id FROM orders) x WHERE x.id = ?")
	if err != nil {
		t.Fatalf("unexpected rejection: %v", err)
	}
	if !reflect.DeepEqual(tables, []string{"orders"}) {
		t.Fatalf("tables = %v, want [orders]", tables)
	}
}

func TestCheckRedaction_ForbidsRedactedColumnInPredicate(t *testing.T) {
	redact := []string{"ssn", "email"}
	// Allowed: redacted column only in the projection.
	if err := CheckRedaction("SELECT ssn, name FROM customers WHERE region = ?", redact); err != nil {
		t.Fatalf("projection-only redacted column rejected: %v", err)
	}
	// Rejected: redacted column in WHERE.
	if err := CheckRedaction("SELECT name FROM customers WHERE ssn = ?", redact); !errors.Is(err, ErrRedactedInPredicate) {
		t.Fatalf("WHERE ssn: err = %v, want ErrRedactedInPredicate", err)
	}
	// Rejected: redacted column in ORDER BY.
	if err := CheckRedaction("SELECT name FROM customers ORDER BY email", redact); !errors.Is(err, ErrRedactedInPredicate) {
		t.Fatalf("ORDER BY email: err = %v, want ErrRedactedInPredicate", err)
	}
	// Rejected: redacted column surfaced through a subquery after FROM.
	if err := CheckRedaction("SELECT x.n FROM (SELECT ssn AS n FROM customers) x", redact); !errors.Is(err, ErrRedactedInPredicate) {
		t.Fatalf("subquery ssn: err = %v, want ErrRedactedInPredicate", err)
	}
}

func TestCheckRedaction_NoRedactSetIsNoop(t *testing.T) {
	if err := CheckRedaction("SELECT ssn FROM t WHERE ssn = ?", nil); err != nil {
		t.Fatalf("empty redact set should be a no-op, got %v", err)
	}
}
