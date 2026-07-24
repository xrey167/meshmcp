package tools

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestSandboxRejectsSymlinkEscape proves sandbox() blocks a symlink that already
// exists inside root and points outside it — the lexical HasPrefix check alone
// let `link/x` (link -> outside) resolve to a file outside the sandbox.
func TestSandboxRejectsSymlinkEscape(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics differ on windows")
	}
	root := t.TempDir()
	outside := t.TempDir()
	// A secret file outside the sandbox, and a symlink to that dir inside root.
	if err := os.WriteFile(filepath.Join(outside, "secret"), []byte("top secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}

	// Reading through the escaping symlink must be rejected.
	if _, err := sandbox(root, "link/secret"); err == nil {
		t.Fatal("sandbox allowed a read through an escaping symlink")
	}
	// Writing a NEW file through the escaping symlink (parent resolves outside)
	// must also be rejected.
	if _, err := sandbox(root, "link/newfile"); err == nil {
		t.Fatal("sandbox allowed a write through an escaping symlink")
	}
}

// TestSandboxAllowsInternalPathsAndSymlinks proves the hardening does not break
// legitimate use: ordinary paths, a not-yet-existing write target, and a symlink
// that stays INSIDE root are all allowed.
func TestSandboxAllowsInternalPathsAndSymlinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics differ on windows")
	}
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "data"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "data", "a.txt"), []byte("hi"), 0o644); err != nil {
		t.Fatal(err)
	}
	// An internal symlink (stays under root) is fine.
	if err := os.Symlink(filepath.Join(root, "data"), filepath.Join(root, "alias")); err != nil {
		t.Fatal(err)
	}

	for _, p := range []string{"data/a.txt", "data/newfile.txt", "alias/a.txt", "."} {
		if _, err := sandbox(root, p); err != nil {
			t.Errorf("legitimate path %q rejected: %v", p, err)
		}
	}
	// Lexical traversal is still rejected.
	if _, err := sandbox(root, "../escape"); err == nil {
		t.Error("lexical ../ traversal was allowed")
	}
}
