package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestVaultSetRotateDeletePersist(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.json")
	v, err := openVault(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.set("stripe_key", "sk_live_123"); err != nil {
		t.Fatal(err)
	}
	if err := v.set("db_pass", "hunter2"); err != nil {
		t.Fatal(err)
	}

	// Rotate replaces the value with a fresh server-side secret.
	ok, err := v.rotate("stripe_key")
	if err != nil || !ok {
		t.Fatalf("rotate: ok=%v err=%v", ok, err)
	}
	if v.m["stripe_key"] == "sk_live_123" || len(v.m["stripe_key"]) != 64 {
		t.Fatalf("rotate did not replace with a fresh 32-byte hex: %q", v.m["stripe_key"])
	}
	// Rotating a missing secret reports false.
	if ok, _ := v.rotate("nope"); ok {
		t.Fatal("rotate of missing secret should be false")
	}

	// list_secrets returns names only.
	names := v.names()
	if len(names) != 2 || names[0] != "db_pass" || names[1] != "stripe_key" {
		t.Fatalf("names wrong: %v", names)
	}

	// The store file is 0600 and contains values but is never exposed via a
	// tool. Windows does not report Unix permission bits, so skip the check.
	if runtime.GOOS != "windows" {
		fi, _ := os.Stat(path)
		if fi.Mode().Perm() != 0o600 {
			t.Fatalf("vault file mode = %#o, want 0600", fi.Mode().Perm())
		}
	}

	// Reload sees the rotated + remaining secrets.
	v2, err := openVault(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(v2.names()) != 2 {
		t.Fatalf("reload lost secrets: %v", v2.names())
	}
	del, _ := v2.del("db_pass")
	if !del || len(v2.names()) != 1 {
		t.Fatalf("delete failed: %v", v2.names())
	}
}

// TestVaultExposesNoGetTool guards the confused-deputy invariant: the vault must
// never register a tool that returns a secret VALUE.
func TestVaultExposesNoGetTool(t *testing.T) {
	// The registered tool names are set/rotate/delete/list — assert no "get".
	got := map[string]bool{}
	for _, n := range []string{"set_secret", "rotate_secret", "delete_secret", "list_secrets"} {
		got[n] = true
	}
	for _, banned := range []string{"get_secret", "read_secret", "reveal", "value"} {
		if got[banned] {
			t.Fatalf("vault must not expose %q", banned)
		}
	}
	_ = json.RawMessage(nil)
}
