package policy

import (
	"os"
	"testing"
	"time"
)

// TestFileCosignFailsClosedOnMalformedRecord proves a corrupt or hand-crafted
// approval file no longer authorizes a call (S35): Approved fails closed on a
// malformed record, a key mismatch, and an unparseable timestamp.
func TestFileCosignFailsClosedOnMalformedRecord(t *testing.T) {
	dir := t.TempDir()
	key := CosignKey("bot.mesh", "wire")

	// A valid grant is approved.
	if err := Grant(dir, "bot.mesh", "wire", "op", time.Now()); err != nil {
		t.Fatal(err)
	}
	fc := &FileCosign{Dir: dir}
	if !fc.Approved(key) {
		t.Fatal("valid grant should be approved")
	}

	// Overwrite with garbage → fail closed.
	if err := os.WriteFile(cosignFile(dir, key), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if fc.Approved(key) {
		t.Fatal("malformed approval must fail closed")
	}

	// A well-formed record for a DIFFERENT key must not authorize this key.
	if err := os.WriteFile(cosignFile(dir, key), []byte(`{"key":"other|tool","granted_at":"2026-01-01T00:00:00Z"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if fc.Approved(key) {
		t.Fatal("key-mismatched approval must fail closed")
	}

	// Unparseable timestamp with a TTL set must fail closed.
	fcTTL := &FileCosign{Dir: dir, TTL: time.Hour}
	if err := os.WriteFile(cosignFile(dir, key), []byte(`{"key":"`+key+`","granted_at":"not-a-time"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if fcTTL.Approved(key) {
		t.Fatal("bad-timestamp approval must fail closed under a TTL")
	}
}
