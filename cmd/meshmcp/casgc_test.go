package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeCASBlob stores content at its true CAS path with the given mtime and
// returns the hash.
func writeCASBlob(t *testing.T, dir string, content []byte, mod time.Time) string {
	t.Helper()
	sum := sha256.Sum256(content)
	hash := hex.EncodeToString(sum[:])
	p := filepath.Join(dir, hash[:2], hash)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, content, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(p, mod, mod); err != nil {
		t.Fatal(err)
	}
	return hash
}

func TestCASGCAgeAndSizeBounds(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	old := writeCASBlob(t, dir, []byte("old-blob-aaaa"), now.Add(-48*time.Hour))
	mid := writeCASBlob(t, dir, []byte("mid-blob-bbbb"), now.Add(-2*time.Hour))
	fresh := writeCASBlob(t, dir, []byte("fresh-blob-cc"), now)

	// A foreign file and a malformed name must never be candidates.
	if err := os.WriteFile(filepath.Join(dir, "README.txt"), []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	badDir := filepath.Join(dir, "zz")
	if err := os.MkdirAll(badDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(badDir, "not-a-hash"), []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Dry run (default): plan reports the old blob, nothing is deleted.
	plan, err := runCASGC(dir, now, 24*time.Hour, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Scanned != 3 {
		t.Fatalf("scanned %d blobs, want 3", plan.Scanned)
	}
	if len(plan.Delete) != 1 || plan.Delete[0].Hash != old {
		t.Fatalf("age plan: %+v", plan.Delete)
	}
	if _, err := os.Stat(filepath.Join(dir, old[:2], old)); err != nil {
		t.Fatalf("dry run must not delete: %v", err)
	}

	// Apply: the old blob goes, the rest stay.
	if _, err := runCASGC(dir, now, 24*time.Hour, 0, true); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, old[:2], old)); !os.IsNotExist(err) {
		t.Fatalf("old blob should be deleted, stat err=%v", err)
	}
	for _, h := range []string{mid, fresh} {
		if _, err := os.Stat(filepath.Join(dir, h[:2], h)); err != nil {
			t.Fatalf("blob %s should survive: %v", h, err)
		}
	}

	// Size bound: cap to fresh-only size; the older survivor (mid) goes first.
	freshSize := int64(len("fresh-blob-cc"))
	plan, err = runCASGC(dir, now, 0, freshSize, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Delete) != 1 || plan.Delete[0].Hash != mid {
		t.Fatalf("size plan: %+v", plan.Delete)
	}
	if _, err := os.Stat(filepath.Join(dir, fresh[:2], fresh)); err != nil {
		t.Fatalf("fresh blob should survive: %v", err)
	}

	// Foreign files untouched throughout.
	if _, err := os.Stat(filepath.Join(dir, "README.txt")); err != nil {
		t.Fatalf("foreign file must survive: %v", err)
	}
	if _, err := os.Stat(filepath.Join(badDir, "not-a-hash")); err != nil {
		t.Fatalf("malformed name must survive: %v", err)
	}
}

// TestCASGCSkipsBlobRefreshedAfterScan closes the scan-to-delete TOCTOU: a
// blob re-dropped after the scan (recvOne renames a fresh-mtime copy over the
// path) must survive an --apply based on the stale scan verdict.
func TestCASGCSkipsBlobRefreshedAfterScan(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	stale := writeCASBlob(t, dir, []byte("refreshed-blob"), now.Add(-48*time.Hour))
	doomed := writeCASBlob(t, dir, []byte("genuinely-old-b"), now.Add(-48*time.Hour))

	blobs, err := scanCASBlobs(dir)
	if err != nil {
		t.Fatal(err)
	}
	plan := planCASGC(blobs, now, 24*time.Hour, 0)
	if len(plan.Delete) != 2 {
		t.Fatalf("plan: %+v", plan.Delete)
	}

	// Between plan and delete, the stale blob is re-dropped (fresh mtime).
	stalePath := filepath.Join(dir, stale[:2], stale)
	if err := os.Chtimes(stalePath, now, now); err != nil {
		t.Fatal(err)
	}

	deleted, err := deleteCASBlobs(plan)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stalePath); err != nil {
		t.Fatalf("refreshed blob must survive apply: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, doomed[:2], doomed)); !os.IsNotExist(err) {
		t.Fatalf("genuinely old blob should be deleted, stat err=%v", err)
	}
	if len(deleted.Delete) != 1 || deleted.Delete[0].Hash != doomed {
		t.Fatalf("deleted report must cover only what was removed: %+v", deleted.Delete)
	}
}

func TestCASGCRequiresABound(t *testing.T) {
	if _, err := runCASGC(t.TempDir(), time.Now(), 0, 0, false); err == nil {
		t.Fatal("gc without bounds must error, not delete everything")
	}
}

func TestCASGCSkipsMismatchedShard(t *testing.T) {
	dir := t.TempDir()
	// A 64-hex name filed under the wrong shard is not a well-formed blob.
	hash := writeCASBlob(t, dir, []byte("x"), time.Now().Add(-time.Hour))
	wrong := filepath.Join(dir, "ff")
	if hash[:2] == "ff" {
		wrong = filepath.Join(dir, "00")
	}
	if err := os.MkdirAll(wrong, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(wrong, hash), []byte("y"), 0o644); err != nil {
		t.Fatal(err)
	}
	blobs, err := scanCASBlobs(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(blobs) != 1 || blobs[0].Hash != hash {
		t.Fatalf("scan: %+v", blobs)
	}
}
