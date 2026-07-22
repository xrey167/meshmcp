package main

import (
	"strings"
	"testing"
)

// TestRemoteBackend_TokenErrorBodyNeverLeaksNonStandardCode covers the
// secret-exposure fix in tokenErrorFromBody: a hostile or compromised
// authorization server can put arbitrary text in the token response's "error"
// field. Only a whitelisted RFC 6749 §5.2 code may reach the (logged) error
// string; anything else — including a standard code with a secret appended —
// must be dropped so it cannot land request material in local logs.
func TestRemoteBackend_TokenErrorBodyNeverLeaksNonStandardCode(t *testing.T) {
	rc := &remoteClient{name: "acme-remote"}

	// A standard code passes through verbatim.
	if err := rc.tokenErrorFromBody(400, []byte(`{"error":"invalid_grant"}`)); !strings.Contains(err.Error(), "invalid_grant") {
		t.Fatalf("standard error code must be surfaced, got %v", err)
	}

	// A code with a secret appended is not a whitelisted value, so the whole
	// field is dropped — the secret must never appear.
	injected := `{"error":"invalid_client: client_secret s3cr3t-value rejected"}`
	err := rc.tokenErrorFromBody(401, []byte(injected))
	if strings.Contains(err.Error(), "s3cr3t-value") {
		t.Fatalf("secret leaked into error string: %v", err)
	}
	if strings.Contains(err.Error(), "client_secret") {
		t.Fatalf("reflected request material leaked into error string: %v", err)
	}

	// A free-form / non-standard code is likewise dropped.
	err = rc.tokenErrorFromBody(400, []byte(`{"error":"see https://evil.example/leak?refresh_token=abc123"}`))
	if strings.Contains(err.Error(), "abc123") || strings.Contains(err.Error(), "evil.example") {
		t.Fatalf("non-standard error value leaked into error string: %v", err)
	}
	if !strings.Contains(err.Error(), "status 400") {
		t.Fatalf("dropped-code path should fall back to the plain status message, got %v", err)
	}
}
