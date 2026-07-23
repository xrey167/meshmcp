package main

import (
	"net/url"
	"strings"
)

// isPostgresDSN reports whether a session_store value selects the
// PostgreSQL-backed store rather than a FileStore directory. Plain paths
// never carry a URL scheme, so existing configs are unaffected.
func isPostgresDSN(s string) bool {
	return strings.HasPrefix(s, "postgres://") || strings.HasPrefix(s, "postgresql://")
}

// redactDSN returns the DSN with any userinfo password AND any credential
// query parameters masked (pgx also accepts password/sslpassword as URL query
// keywords), safe for logs and doctor output. An unparseable DSN is not
// echoed at all.
func redactDSN(dsn string) string {
	u, err := url.Parse(dsn)
	if err != nil {
		return "(unparseable postgres dsn)"
	}
	q := u.Query()
	masked := false
	for _, k := range []string{"password", "sslpassword"} {
		if q.Has(k) {
			q.Set(k, "xxxxx")
			masked = true
		}
	}
	if masked {
		u.RawQuery = q.Encode()
	}
	return u.Redacted()
}
