package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xrey167/meshmcp/policy"
)

// buildLedger writes n hash-chained audit records to path via the real
// policy.AuditLog, so a full-chain film verifies through policy.VerifyChain.
func buildLedger(t *testing.T, path string, n int) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	base := time.Date(2026, 7, 22, 14, 0, 0, 0, time.UTC)
	i := 0
	al := policy.NewAuditLog(f, func() string { return base.Add(time.Duration(i) * time.Second).Format(time.RFC3339) })
	for ; i < n; i++ {
		if err := al.Append(policy.AuditRecord{
			Backend: "fs", Peer: fmt.Sprintf("p%d.mesh", i), Method: "tools/call", Tool: "read",
			Decision: "allow", Reason: "rule 2", PeerKey: "KEYMATERIAL", PeerAddr: "100.64.0.9",
		}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestFilmRecordFullChainRoundTrip(t *testing.T) {
	dir := t.TempDir()
	ledger := filepath.Join(dir, "audit.jsonl")
	film := filepath.Join(dir, "capture.film")
	buildLedger(t, ledger, 4)

	if err := filmRecord([]string{"--audit", ledger, film}); err != nil {
		t.Fatalf("record: %v", err)
	}
	man, records, err := readFilm(film)
	if err != nil {
		t.Fatal(err)
	}
	if man.Records != 4 || len(records) != 4 {
		t.Fatalf("want 4 records, got manifest=%d slice=%d", man.Records, len(records))
	}
	if !man.FullChain || !man.Verifiable || man.Redacted {
		t.Fatalf("full unfiltered capture should be full-chain verifiable: %+v", man)
	}
	if err := checkFilmIntegrity(man, records); err != nil {
		t.Fatalf("intact full-chain film failed verify: %v", err)
	}
	// A play with no delay + no verify must not error on a valid film.
	if err := filmPlay([]string{"--speed", "0", "--no-verify", film}); err != nil {
		t.Fatalf("play: %v", err)
	}
}

func TestFilmDetectsTampering(t *testing.T) {
	dir := t.TempDir()
	ledger := filepath.Join(dir, "audit.jsonl")
	film := filepath.Join(dir, "capture.film")
	buildLedger(t, ledger, 3)
	if err := filmRecord([]string{"--audit", ledger, film}); err != nil {
		t.Fatal(err)
	}
	// Flip a byte inside a record line (not the manifest).
	data, _ := os.ReadFile(film)
	s := string(data)
	s = strings.Replace(s, "p1.mesh", "pX.mesh", 1)
	if err := os.WriteFile(film, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
	man, records, err := readFilm(film)
	if err != nil {
		t.Fatal(err)
	}
	if err := checkFilmIntegrity(man, records); err == nil {
		t.Fatal("tampered film passed integrity check")
	}
}

func TestFilmRedactStripsIdentity(t *testing.T) {
	dir := t.TempDir()
	ledger := filepath.Join(dir, "audit.jsonl")
	film := filepath.Join(dir, "capture.film")
	buildLedger(t, ledger, 2)
	if err := filmRecord([]string{"--audit", ledger, "--redact", film}); err != nil {
		t.Fatal(err)
	}
	man, records, err := readFilm(film)
	if err != nil {
		t.Fatal(err)
	}
	if !man.Redacted || man.Verifiable {
		t.Fatalf("redacted film must be marked redacted + non-verifiable: %+v", man)
	}
	for _, line := range records {
		var m map[string]json.RawMessage
		if err := json.Unmarshal(line, &m); err != nil {
			t.Fatal(err)
		}
		if _, ok := m["peer_key"]; ok {
			t.Error("peer_key not redacted")
		}
		if _, ok := m["peer_addr"]; ok {
			t.Error("peer_addr not redacted")
		}
		if r, ok := m["reason"]; ok && string(r) != `"[redacted]"` {
			t.Errorf("reason not redacted: %s", r)
		}
	}
	// Content seal still holds over the redacted bytes.
	if err := checkFilmIntegrity(man, records); err != nil {
		t.Errorf("redacted film content seal should still verify: %v", err)
	}
}

func TestFilmWindowedNotFullChain(t *testing.T) {
	dir := t.TempDir()
	ledger := filepath.Join(dir, "audit.jsonl")
	film := filepath.Join(dir, "capture.film")
	buildLedger(t, ledger, 5)
	if err := filmRecord([]string{"--audit", ledger, "--last", "2", film}); err != nil {
		t.Fatal(err)
	}
	man, _, err := readFilm(film)
	if err != nil {
		t.Fatal(err)
	}
	if man.Records != 2 {
		t.Fatalf("want 2 records, got %d", man.Records)
	}
	if man.FullChain || man.Verifiable {
		t.Fatalf("a windowed (--last) film is not full-chain: %+v", man)
	}
}

func TestFilmRecordFilterByDecision(t *testing.T) {
	dir := t.TempDir()
	ledger := filepath.Join(dir, "audit.jsonl")
	// Mixed decisions: two allow, one deny.
	f, _ := os.Create(ledger)
	base := time.Date(2026, 7, 22, 14, 0, 0, 0, time.UTC)
	i := 0
	al := policy.NewAuditLog(f, func() string { return base.Add(time.Duration(i) * time.Second).Format(time.RFC3339) })
	decisions := []string{"allow", "deny", "allow"}
	for ; i < len(decisions); i++ {
		_ = al.Append(policy.AuditRecord{Backend: "fs", Peer: "p.mesh", Method: "m", Decision: decisions[i]})
	}
	f.Close()

	film := filepath.Join(dir, "deny.film")
	if err := filmRecord([]string{"--audit", ledger, "--decision", "deny", film}); err != nil {
		t.Fatal(err)
	}
	man, records, err := readFilm(film)
	if err != nil {
		t.Fatal(err)
	}
	if man.Records != 1 || len(records) != 1 {
		t.Fatalf("decision filter should keep 1 deny, got %d", man.Records)
	}
	r, _ := parseStreamRecord(records[0])
	if r.Decision != "deny" {
		t.Errorf("kept the wrong record: %+v", r)
	}
}

func TestRedactLine(t *testing.T) {
	line := []byte(`{"backend":"fs","peer":"p.mesh","peer_key":"K","peer_addr":"1.2.3.4","reason":"cost limit","decision":"deny"}`)
	out := redactLine(line)
	var m map[string]any
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m["peer_key"]; ok {
		t.Error("peer_key survived redaction")
	}
	if m["reason"] != "[redacted]" {
		t.Errorf("reason = %v, want [redacted]", m["reason"])
	}
	if m["decision"] != "deny" {
		t.Errorf("decision should survive: %v", m["decision"])
	}
}
