package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestFormatAuditLine covers decision colouring/plain rendering, backend
// filtering, non-audit rejection, and the time shortening.
func TestFormatAuditLine(t *testing.T) {
	old := colorOn
	colorOn = false
	defer func() { colorOn = old }()

	allow := `{"time":"2026-07-22T14:31:02Z","backend":"fs","peer":"a.mesh","method":"tools/call","tool":"read","decision":"allow","reason":"rule 2"}`
	s, ok := formatAuditLine([]byte(allow), "")
	if !ok || !strings.Contains(s, "14:31:02") || !strings.Contains(s, "allow") ||
		!strings.Contains(s, "a.mesh") || !strings.Contains(s, "tools/call · read") ||
		!strings.Contains(s, "fs") || !strings.Contains(s, "rule 2") {
		t.Fatalf("allow row wrong: %q (ok=%v)", s, ok)
	}
	// Backend filter: mismatch drops it.
	if _, ok := formatAuditLine([]byte(allow), "other"); ok {
		t.Fatal("backend filter should drop a mismatched record")
	}
	if _, ok := formatAuditLine([]byte(allow), "fs"); !ok {
		t.Fatal("backend filter should keep a matching record")
	}
	// Non-audit lines (no decision, or not JSON) are skipped.
	for _, junk := range []string{"", "not json", `{"seq":1}`} {
		if _, ok := formatAuditLine([]byte(junk), ""); ok {
			t.Fatalf("non-audit line accepted: %q", junk)
		}
	}
}

// TestStreamAuditDrainsExisting proves --from-start renders existing records
// (skipping non-audit lines) and then follows until the context is cancelled.
func TestStreamAuditDrainsExisting(t *testing.T) {
	old := colorOn
	colorOn = false
	defer func() { colorOn = old }()

	path := filepath.Join(t.TempDir(), "audit.jsonl")
	content := `{"time":"2026-07-22T14:31:02Z","backend":"fs","peer":"a.mesh","method":"tools/call","tool":"read","decision":"allow"}
{"backend":"fs","peer":"b.mesh","method":"tools/call","tool":"write","decision":"deny","reason":"tainted"}
not-json
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	var buf syncBuffer
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- streamAudit(ctx, path, true, "", 20*time.Millisecond, &buf) }()
	time.Sleep(120 * time.Millisecond) // let the initial drain render
	cancel()
	<-done

	out := buf.String()
	if !strings.Contains(out, "allow") || !strings.Contains(out, "a.mesh") {
		t.Fatalf("existing allow not rendered: %q", out)
	}
	if !strings.Contains(out, "deny") || !strings.Contains(out, "tainted") {
		t.Fatalf("existing deny not rendered: %q", out)
	}
	if strings.Contains(out, "not-json") {
		t.Fatalf("non-audit line leaked: %q", out)
	}
	if n := strings.Count(strings.TrimRight(out, "\n"), "\n") + 1; n != 2 {
		t.Fatalf("expected 2 rendered rows, got %d: %q", n, out)
	}
}
