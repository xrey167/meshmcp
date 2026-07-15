package policy

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// writeChain produces n audit records through an AuditLog and returns the raw
// JSONL bytes.
func writeChain(n int) *bytes.Buffer {
	var buf bytes.Buffer
	a := NewAuditLog(&buf, func() string { return "T" })
	for i := 0; i < n; i++ {
		a.write(AuditRecord{Backend: "kg", Peer: "p", Method: "tools/call", Tool: "read_file", Decision: "allow", Rule: 0})
	}
	return &buf
}

func TestChainVerifiesIntact(t *testing.T) {
	buf := writeChain(5)
	res, err := VerifyChain(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !res.OK {
		t.Fatalf("chain should be intact: %+v", res)
	}
	if res.Count != 5 {
		t.Fatalf("expected 5 records, got %d", res.Count)
	}
	if res.LastHash == "" {
		t.Fatalf("expected a chain head hash")
	}
}

func TestChainDetectsEditedRecord(t *testing.T) {
	buf := writeChain(5)
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")

	// Tamper with the middle record's payload, keeping its stored hash — the
	// classic "edit the log and hope nobody recomputes" attack.
	var rec map[string]any
	if err := json.Unmarshal([]byte(lines[2]), &rec); err != nil {
		t.Fatal(err)
	}
	rec["tool"] = "delete_all" // was read_file
	edited, _ := json.Marshal(rec)
	lines[2] = string(edited)

	res, err := VerifyChain(strings.NewReader(strings.Join(lines, "\n")))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if res.OK {
		t.Fatalf("edited record should break the chain")
	}
	if res.BreakSeq != 3 {
		t.Fatalf("break should be at seq 3, got %d (%s)", res.BreakSeq, res.Reason)
	}
	if !strings.Contains(res.Reason, "edited") {
		t.Fatalf("reason should mention edit: %s", res.Reason)
	}
}

func TestChainDetectsDeletedRecord(t *testing.T) {
	buf := writeChain(5)
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	// Drop record #3 (seq 3): the surviving records now have a seq gap.
	lines = append(lines[:2], lines[3:]...)

	res, _ := VerifyChain(strings.NewReader(strings.Join(lines, "\n")))
	if res.OK {
		t.Fatalf("deleting a record should break the chain")
	}
	if res.BreakSeq != 4 {
		t.Fatalf("break should surface at seq 4 (the record after the gap), got %d (%s)", res.BreakSeq, res.Reason)
	}
}

func TestChainResumesAcrossRestart(t *testing.T) {
	// Simulate a process restart: write, read the tail, seed a fresh log, and
	// verify the concatenation is one unbroken chain.
	first := writeChain(3)
	seq, hash, err := LastLink(bytes.NewReader(first.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if seq != 3 {
		t.Fatalf("tail seq should be 3, got %d", seq)
	}

	var second bytes.Buffer
	a := NewAuditLog(&second, func() string { return "T" })
	a.SeedFrom(seq, hash)
	a.write(AuditRecord{Backend: "kg", Peer: "p", Method: "tools/call", Tool: "read_file", Decision: "allow", Rule: 0})
	a.write(AuditRecord{Backend: "kg", Peer: "p", Method: "tools/call", Tool: "read_file", Decision: "allow", Rule: 0})

	combined := first.String() + second.String()
	res, err := VerifyChain(strings.NewReader(combined))
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK {
		t.Fatalf("resumed chain should be intact: %+v", res)
	}
	if res.Count != 5 {
		t.Fatalf("expected 5 records across restart, got %d", res.Count)
	}
}
