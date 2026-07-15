package policy

import (
	"bytes"
	"strings"
	"testing"
)

func TestAnalyzeRollupAndChain(t *testing.T) {
	var buf bytes.Buffer
	a := NewAuditLog(&buf, func() string { return "T" })
	a.write(AuditRecord{Backend: "fs", Peer: "laptop", Method: "tools/call", Tool: "read_file", Decision: "allow", Rule: 0})
	a.write(AuditRecord{Backend: "fs", Peer: "laptop", Method: "tools/call", Tool: "delete_all", Decision: "deny", Rule: 1})
	a.write(AuditRecord{Backend: "fs", Peer: "bot", Method: "tools/call", Tool: "read_file", Decision: "allow", Rule: 0})

	sum, err := Analyze(bytes.NewReader(buf.Bytes()), 10)
	if err != nil {
		t.Fatal(err)
	}
	if sum.Records != 3 || sum.Allowed != 2 || sum.Denied != 1 {
		t.Fatalf("counts wrong: %+v", sum)
	}
	if !sum.Chain.OK {
		t.Fatalf("chain should verify: %+v", sum.Chain)
	}
	// laptop should be the busiest peer (2 calls).
	if len(sum.Peers) == 0 || sum.Peers[0].Peer != "laptop" || sum.Peers[0].Calls != 2 {
		t.Fatalf("peer rollup wrong: %+v", sum.Peers)
	}
	// read_file is the busiest tool (2 calls).
	if len(sum.Tools) == 0 || sum.Tools[0].Tool != "read_file" || sum.Tools[0].Calls != 2 {
		t.Fatalf("tool rollup wrong: %+v", sum.Tools)
	}
	// recent is most-recent-first: the bot read_file was last written.
	if len(sum.Recent) == 0 || sum.Recent[0].Peer != "bot" {
		t.Fatalf("recent order wrong: %+v", sum.Recent)
	}
	if len(sum.Backends) != 1 || sum.Backends[0] != "fs" {
		t.Fatalf("backends wrong: %+v", sum.Backends)
	}
}

func TestAnalyzeShowsTamper(t *testing.T) {
	buf := writeChain(4)
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	lines[1] = strings.Replace(lines[1], "read_file", "rm_rf", 1) // edit, keep hash

	sum, err := Analyze(strings.NewReader(strings.Join(lines, "\n")), 10)
	if err != nil {
		t.Fatal(err)
	}
	if sum.Chain.OK {
		t.Fatalf("analyze should surface the tamper in Chain")
	}
	if sum.Chain.BreakSeq != 2 {
		t.Fatalf("expected break at seq 2, got %d", sum.Chain.BreakSeq)
	}
}
