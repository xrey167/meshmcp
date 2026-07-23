package main

import (
	"os"
	"path/filepath"
	"testing"
)

// S58 review fix: usage export must cover the WHOLE rotated ledger, not just
// the active segment — a billing window spanning a rotation would otherwise
// silently under-count. auditSegmentPaths discovers sealed archives (the
// RotatingFileSink naming: <path>.<UTC ts>[-NNN]) oldest-first, active last.
func TestAuditSegmentPathsIncludesRotatedArchives(t *testing.T) {
	dir := t.TempDir()
	active := filepath.Join(dir, "audit.jsonl")
	older := active + ".20260701T000000Z"
	newer := active + ".20260710T120000Z-001"
	unrelated := active + ".checkpoint" // must NOT be mistaken for an archive
	for _, p := range []string{active, newer, older, unrelated} {
		if err := os.WriteFile(p, []byte("{}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	got, err := auditSegmentPaths(active)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{older, newer, active}
	if len(got) != len(want) {
		t.Fatalf("segments = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("segments = %v, want %v", got, want)
		}
	}
	// A missing active file fails loudly (never a silent empty report).
	if _, err := auditSegmentPaths(filepath.Join(dir, "missing.jsonl")); err == nil {
		t.Fatal("missing active audit file must error")
	}
}

// S58 review fix: a non-UTC RFC3339 bound must be normalized to the exact "Z"
// second-precision form the ledger writes (lexicographic comparison is only
// order-correct within that form); fractional seconds cannot be honored and
// are rejected rather than silently truncated.
func TestNormalizeUsageBound(t *testing.T) {
	got, err := normalizeUsageBound("since", "2026-07-01T02:00:00+02:00")
	if err != nil {
		t.Fatal(err)
	}
	if got != "2026-07-01T00:00:00Z" {
		t.Fatalf("offset bound not normalized to UTC: %q", got)
	}
	if got, err := normalizeUsageBound("until", "2026-07-01T00:00:00Z"); err != nil || got != "2026-07-01T00:00:00Z" {
		t.Fatalf("UTC bound must pass through: %q, %v", got, err)
	}
	if got, err := normalizeUsageBound("since", ""); err != nil || got != "" {
		t.Fatalf("empty bound must stay empty: %q, %v", got, err)
	}
	if _, err := normalizeUsageBound("since", "2026-07-01T00:00:00.5Z"); err == nil {
		t.Fatal("fractional-second bound must be rejected")
	}
	if _, err := normalizeUsageBound("until", "not-a-time"); err == nil {
		t.Fatal("malformed bound must be rejected")
	}
}
