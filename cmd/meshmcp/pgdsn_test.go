package main

import "testing"

func TestSessionStoreIsPostgresDSN(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"postgres://u:p@localhost:5432/mesh", true},
		{"postgresql://localhost/mesh", true},
		{"/var/lib/meshmcp/sessions", false},
		{"C:\\sessions", false},
		{"./sessions", false},
		{"postgres", false},
		{"", false},
	}
	for _, c := range cases {
		if got := isPostgresDSN(c.in); got != c.want {
			t.Errorf("isPostgresDSN(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestSessionStoreRedactDSN(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"postgres://user:secret@db:5432/mesh?sslmode=require", "postgres://user:xxxxx@db:5432/mesh?sslmode=require"},
		{"postgres://db:5432/mesh", "postgres://db:5432/mesh"},
		{"postgres://user@db/mesh", "postgres://user@db/mesh"},
		{"postgres://user:secret@bad host/mesh", "(unparseable postgres dsn)"},
		// Credentials in query parameters (also accepted by pgx) are masked.
		{"postgres://db:5432/mesh?user=app&password=hunter2", "postgres://db:5432/mesh?password=xxxxx&user=app"},
		{"postgres://db/mesh?sslpassword=s3cret&sslmode=require", "postgres://db/mesh?sslmode=require&sslpassword=xxxxx"},
	}
	for _, c := range cases {
		if got := redactDSN(c.in); got != c.want {
			t.Errorf("redactDSN(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
