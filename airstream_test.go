package main

import (
	"context"
	"fmt"
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
	go func() { done <- streamAudit(ctx, path, true, bindMatch{}, false, 20*time.Millisecond, &buf) }()
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

// waitFor polls until cond is true or the deadline elapses, so the tail tests
// don't race on a fixed sleep.
func waitFor(t *testing.T, d time.Duration, cond func() bool) bool {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return cond()
}

// TestStreamAuditFollowsAppendsAndPartialLines proves the live-tail path: with
// fromStart=false the follower seeks to EOF, then delivers records appended
// after it starts — including a record written in two steps (bytes, then the
// newline), which must be delivered exactly once (the incomplete-line rewind).
func TestStreamAuditFollowsAppendsAndPartialLines(t *testing.T) {
	old := colorOn
	colorOn = false
	defer func() { colorOn = old }()

	path := filepath.Join(t.TempDir(), "audit.jsonl")
	// Pre-existing record must NOT appear (fromStart=false seeks to EOF).
	if err := os.WriteFile(path, []byte(`{"peer":"old.mesh","decision":"allow","method":"m"}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	var buf syncBuffer
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- streamAudit(ctx, path, false, bindMatch{}, false, 10*time.Millisecond, &buf) }()
	// Let the follower seek to EOF before we append, or the append would land
	// before its start position and be (correctly) skipped — a test-only race.
	time.Sleep(80 * time.Millisecond)

	// A complete record appended after following starts.
	if _, err := f.WriteString(`{"peer":"new.mesh","decision":"deny","method":"m"}` + "\n"); err != nil {
		t.Fatal(err)
	}
	if !waitFor(t, 2*time.Second, func() bool { return strings.Contains(buf.String(), "new.mesh") }) {
		t.Fatalf("appended record not delivered: %q", buf.String())
	}
	// A record written in two steps: body first (no newline), then the newline.
	if _, err := f.WriteString(`{"peer":"split.mesh","decision":"cosign","method":"m"}`); err != nil {
		t.Fatal(err)
	}
	time.Sleep(40 * time.Millisecond) // observed mid-line: must not emit yet
	if strings.Contains(buf.String(), "split.mesh") {
		t.Fatalf("partial line emitted before its newline: %q", buf.String())
	}
	if _, err := f.WriteString("\n"); err != nil {
		t.Fatal(err)
	}
	if !waitFor(t, 2*time.Second, func() bool { return strings.Contains(buf.String(), "split.mesh") }) {
		t.Fatalf("completed split record not delivered: %q", buf.String())
	}
	cancel()
	<-done

	out := buf.String()
	if strings.Contains(out, "old.mesh") {
		t.Fatalf("pre-existing record leaked despite fromStart=false: %q", out)
	}
	if c := strings.Count(out, "split.mesh"); c != 1 {
		t.Fatalf("split record delivered %d times, want exactly 1: %q", c, out)
	}
}

// TestFollowAuditZeroIntervalNoPanic proves a non-positive interval degrades to
// a default instead of panicking in time.NewTicker (a crash on bad CLI input).
func TestFollowAuditZeroIntervalNoPanic(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	if err := os.WriteFile(path, []byte(`{"peer":"a.mesh","decision":"allow"}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	// interval 0 must not panic; cancel promptly ends the follow.
	go func() {
		defer func() {
			if r := recover(); r != nil {
				done <- fmt.Errorf("panic: %v", r)
			}
		}()
		done <- followAudit(ctx, path, true, 0, func([]byte) {})
	}()
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("followAudit with interval 0: %v", err)
	}
}

// TestFollowAuditRotation proves the rotation-aware reopen: after the file is
// truncated below the follower's offset and new records appended, the follower
// reopens from the start and delivers the post-rotation records.
func TestFollowAuditRotation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	// Start with a large-ish file so truncation clearly shrinks below our offset.
	if err := os.WriteFile(path, []byte(strings.Repeat(`{"peer":"pre.mesh","decision":"allow"}`+"\n", 5)), 0o644); err != nil {
		t.Fatal(err)
	}

	var mu syncBuffer
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- followAudit(ctx, path, true, 10*time.Millisecond, func(line []byte) {
			mu.Write(append([]byte(nil), line...))
		})
	}()
	// Wait until the initial content is drained.
	if !waitFor(t, 2*time.Second, func() bool { return strings.Count(mu.String(), "pre.mesh") == 5 }) {
		t.Fatalf("initial drain incomplete: %q", mu.String())
	}
	// Rotate in place: truncate to empty (size drops below offset), then append.
	if err := os.Truncate(path, 0); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(`{"peer":"post.mesh","decision":"deny"}` + "\n"); err != nil {
		t.Fatal(err)
	}
	if !waitFor(t, 2*time.Second, func() bool { return strings.Contains(mu.String(), "post.mesh") }) {
		t.Fatalf("post-rotation record not delivered after reopen: %q", mu.String())
	}
	cancel()
	<-done
}
