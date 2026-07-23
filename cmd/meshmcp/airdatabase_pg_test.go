package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestPGQuestionToDollar(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"select * from t where a = ?", "select * from t where a = $1"},
		{"select * from t where a = ? and b = ?", "select * from t where a = $1 and b = $2"},
		{"select '?' from t where a = ?", "select '?' from t where a = $1"},
		{"select 'it''s ?' from t", "select 'it''s ?' from t"},
		{`select "col?umn" from t where a = ?`, `select "col?umn" from t where a = $1`},
		{"select `q?` from t", "select `q?` from t"},
		{"select [w?] from t", "select [w?] from t"},
		{"select a from t -- trailing ? comment\n where b = ?", "select a from t -- trailing ? comment\n where b = $1"},
		{"select a /* block ? */ from t where b = ?", "select a /* block ? */ from t where b = $1"},
		{"select a from t -- comment to EOF ?", "select a from t -- comment to EOF ?"},
		{"select a /* unterminated ?", "select a /* unterminated ?"},
		{"select 'unterminated ?", "select 'unterminated ?"},
	} {
		got, err := pgQuestionToDollar(tc.in)
		if err != nil {
			t.Fatalf("%q: %v", tc.in, err)
		}
		if got != tc.want {
			t.Errorf("%q:\n got %q\nwant %q", tc.in, got, tc.want)
		}
	}
}

func TestNewPGDBExecutorSpecValidation(t *testing.T) {
	secret := "postgres://user:HUNTER2SECRET@db/x"
	for _, bad := range []string{
		"nodsn",
		"name=mysql://db/x",
		"=postgres://db/x",
		"name=",
	} {
		if _, err := newPGDBExecutor([]string{bad}); err == nil {
			t.Errorf("spec %q must be rejected", bad)
		}
	}
	if _, err := newPGDBExecutor([]string{"a=" + secret, "a=" + secret}); err == nil {
		t.Fatal("duplicate name must be rejected")
	} else if strings.Contains(err.Error(), "HUNTER2SECRET") {
		t.Fatalf("spec error echoed the DSN credential: %v", err)
	}
}

func TestPGDBExecutorUnknownDBFailsClosed(t *testing.T) {
	e := &pgDBExecutor{dbs: nil}
	if _, err := e.Exec(context.Background(), "nope", "select 1", nil); err == nil {
		t.Fatal("unknown db must fail closed")
	}
}

// TestPGDBExecutorLive proves the executor end to end against a live
// PostgreSQL: bound '?' params, []byte -> string conversion, and column names.
func TestPGDBExecutorLive(t *testing.T) {
	dsn := os.Getenv("MESHMCP_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("MESHMCP_TEST_PG_DSN not set; skipping PostgreSQL integration test")
	}
	e, err := newPGDBExecutor([]string{"analytics=" + dsn})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()

	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	table := "airdb_" + hex.EncodeToString(b[:])
	db := e.dbs["analytics"]
	if _, err := db.Exec("CREATE TABLE " + table + " (id INT, name TEXT)"); err != nil {
		t.Fatal(err)
	}
	defer db.Exec("DROP TABLE IF EXISTS " + table)
	if _, err := db.Exec("INSERT INTO " + table + " VALUES (1,'alice'),(2,'bob'),(3,'eve')"); err != nil {
		t.Fatal(err)
	}

	rows, err := e.Exec(context.Background(),
		"analytics", fmt.Sprintf("select id, name from %s where id > ? order by id", table), []any{1})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows.Columns) != 2 || rows.Columns[0].Name != "id" || rows.Columns[1].Name != "name" {
		t.Fatalf("columns = %v", rows.Columns)
	}
	if len(rows.Rows) != 2 {
		t.Fatalf("rows = %v", rows.Rows)
	}
	if name, ok := rows.Rows[0][1].(string); !ok || name != "bob" {
		t.Fatalf("first filtered row = %v (name must arrive as a string)", rows.Rows[0])
	}

	// The bind contract: an injection payload in a param is inert.
	rows, err = e.Exec(context.Background(),
		"analytics", fmt.Sprintf("select id from %s where name = ?", table), []any{"x' OR '1'='1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows.Rows) != 0 {
		t.Fatalf("injection payload in a bind param matched rows: %v", rows.Rows)
	}
}
