package main

import (
	"bytes"
	"context"
	"encoding/json"
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

// busEventLine builds one wire line as the hook bus emits it: a pubsub.Event
// envelope (broker-stamped time/publisher) whose payload is a hookPayload.
func busEventLine(t *testing.T, evTime string, p hookPayload) []byte {
	t.Helper()
	payload, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	line, err := json.Marshal(map[string]any{
		"topic": "gateway." + p.Event, "seq": 7, "time": evTime,
		"publisher": "PUBKEY", "payload": json.RawMessage(payload), "prev_hash": "",
	})
	if err != nil {
		t.Fatal(err)
	}
	return line
}

// TestStreamBusLine proves the bus decode+render path: a hook event renders
// the same decision-coloured row shape as the file tail (envelope time, event
// as decision), filters apply, unknown fields are tolerated, and non-decision
// lines are skipped.
func TestStreamBusLine(t *testing.T) {
	old := colorOn
	colorOn = false
	defer func() { colorOn = old }()

	deny := busEventLine(t, "2026-07-22T14:31:02Z", hookPayload{
		Event: "deny", Backend: "fs", Peer: "a.mesh", Method: "tools/call",
		Tool: "write", Reason: "tainted", Rule: 3, AuditSeq: 17,
	})
	var buf bytes.Buffer
	streamBusLine(deny, bindMatch{}, false, &buf)
	out := buf.String()
	if !strings.Contains(out, "14:31:02") || !strings.Contains(out, "deny") ||
		!strings.Contains(out, "a.mesh") || !strings.Contains(out, "tools/call · write") ||
		!strings.Contains(out, "fs") || !strings.Contains(out, "tainted") {
		t.Fatalf("bus deny row wrong: %q", out)
	}

	// Filter: a mismatched decision drops the event; a matching glob keeps it.
	buf.Reset()
	streamBusLine(deny, bindMatch{Decision: "allow"}, false, &buf)
	if buf.Len() != 0 {
		t.Fatalf("decision filter should drop a mismatched event: %q", buf.String())
	}
	buf.Reset()
	streamBusLine(deny, bindMatch{Decision: "d*"}, false, &buf)
	if buf.Len() == 0 {
		t.Fatal("decision glob should keep a matching event")
	}

	// Unknown fields in envelope and payload are tolerated (forward compat).
	future := []byte(`{"topic":"gateway.cosign","seq":9,"time":"2026-07-22T15:00:01Z","future_env":true,` +
		`"payload":{"event":"cosign","peer":"b.mesh","method":"tools/call","future_field":"x"},"prev_hash":""}`)
	buf.Reset()
	streamBusLine(future, bindMatch{}, false, &buf)
	if !strings.Contains(buf.String(), "cosign") || !strings.Contains(buf.String(), "b.mesh") {
		t.Fatalf("unknown fields not tolerated: %q", buf.String())
	}

	// Non-decision lines are skipped: junk, acks, foreign payloads.
	for _, junk := range []string{"", "not json", `{"ok":true}`, `{"topic":"t","seq":1,"payload":{"hello":1},"prev_hash":""}`} {
		buf.Reset()
		streamBusLine([]byte(junk), bindMatch{}, false, &buf)
		if buf.Len() != 0 {
			t.Fatalf("non-decision line rendered: %q -> %q", junk, buf.String())
		}
	}

	// --json passes the raw event line through untouched.
	buf.Reset()
	streamBusLine(append(deny, '\n'), bindMatch{}, true, &buf)
	if got := strings.TrimRight(buf.String(), "\n"); got != string(deny) {
		t.Fatalf("json passthrough altered the line: %q != %q", got, deny)
	}
}

// TestStreamRowTimeSanitized proves the one broker-controlled field that skips
// the RFC3339 fast path — time — cannot inject terminal escapes: a hostile
// envelope time is stripped by sanitizeCell like every other cell, both when
// streamTime passes it through untouched and when the escape hides inside the
// 8-byte HH:MM:SS window after a 'T'.
func TestStreamRowTimeSanitized(t *testing.T) {
	old := colorOn
	colorOn = false
	defer func() { colorOn = old }()

	for _, hostile := range []string{
		"\x1b]0;pwned\x07\x1b[2J", // no 'T': streamTime returns it untouched
		"AT\x1b[31mXXXXX",         // ESC inside the t[i+1:i+9] window
	} {
		line := busEventLine(t, hostile, hookPayload{Event: "deny", Peer: "a.mesh", Method: "tools/call"})
		var buf bytes.Buffer
		streamBusLine(line, bindMatch{}, false, &buf)
		if out := buf.String(); strings.ContainsAny(out, "\x1b\x07") {
			t.Fatalf("hostile time %q leaked escape bytes into the row: %q", hostile, out)
		} else if !strings.Contains(out, "deny") {
			t.Fatalf("hostile time %q dropped the row entirely: %q", hostile, out)
		}
	}
}

// TestBusLineHandlerThroughClientStream drives the exact subscribe-client seam
// streamBus uses: synthetic wire bytes written into a clientStream (the fake
// conn side) are line-split and fed to busLineHandler — the first line is the
// subscribe ack (not rendered), later lines render, and a rejection ack
// surfaces as an error.
func TestBusLineHandlerThroughClientStream(t *testing.T) {
	old := colorOn
	colorOn = false
	defer func() { colorOn = old }()

	var buf bytes.Buffer
	var acked *ackFrame
	stream := &clientStream{done: make(chan struct{})}
	stream.onLine = busLineHandler(bindMatch{}, false, &buf, func(a ackFrame) { acked = &a })

	// Ack, then one event — written in two chunks to exercise line reassembly.
	ev := busEventLine(t, "2026-07-22T14:31:02Z", hookPayload{Event: "deny", Peer: "a.mesh", Method: "tools/call"})
	if _, err := stream.Write([]byte(`{"ok":true}` + "\n")); err != nil {
		t.Fatal(err)
	}
	half := len(ev) / 2
	if _, err := stream.Write(ev[:half]); err != nil {
		t.Fatal(err)
	}
	if buf.Len() != 0 {
		t.Fatalf("partial line rendered early: %q", buf.String())
	}
	if _, err := stream.Write(append(ev[half:], '\n')); err != nil {
		t.Fatal(err)
	}

	if acked == nil || !acked.OK {
		t.Fatalf("subscribe ack not delivered to onAck: %+v", acked)
	}
	if strings.Contains(buf.String(), `"ok"`) {
		t.Fatalf("ack line leaked into rendered output: %q", buf.String())
	}
	if !strings.Contains(buf.String(), "deny") || !strings.Contains(buf.String(), "a.mesh") {
		t.Fatalf("event after ack not rendered: %q", buf.String())
	}

	// A rejection ack reaches onAck with the broker's error.
	rejected := &clientStream{done: make(chan struct{})}
	var rejErr string
	rejected.onLine = busLineHandler(bindMatch{}, false, &buf, func(a ackFrame) { rejErr = a.Error })
	if _, err := rejected.Write([]byte(`{"error":"not allowed"}` + "\n")); err != nil {
		t.Fatal(err)
	}
	if rejErr != "not allowed" {
		t.Fatalf("rejection ack error not surfaced: %q", rejErr)
	}
}

// TestAirStreamModeFlagConflicts proves a flag from the other source mode is
// rejected at parse time instead of silently ignored — a user asking for
// --from-start over the bus (or --since on a file) must get a diagnostic, not
// a stream quietly missing what they asked for.
func TestAirStreamModeFlagConflicts(t *testing.T) {
	if err := cmdAirStream([]string{"--bus", "1.2.3.4:9000", "--from-start"}); err == nil ||
		!strings.Contains(err.Error(), "file-mode flags") {
		t.Fatalf("--from-start with --bus not rejected: %v", err)
	}
	if err := cmdAirStream([]string{"--bus", "1.2.3.4:9000", "--interval", "1s"}); err == nil ||
		!strings.Contains(err.Error(), "file-mode flags") {
		t.Fatalf("--interval with --bus not rejected: %v", err)
	}
	if err := cmdAirStream([]string{"--since", "5", "audit.jsonl"}); err == nil ||
		!strings.Contains(err.Error(), "bus-mode flags") {
		t.Fatalf("--since with a file not rejected: %v", err)
	}
	if err := cmdAirStream([]string{"--topic", "gateway.*", "audit.jsonl"}); err == nil ||
		!strings.Contains(err.Error(), "bus-mode flags") {
		t.Fatalf("--topic with a file not rejected: %v", err)
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
