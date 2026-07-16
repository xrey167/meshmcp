package policy

import (
	"bytes"
	"testing"
)

func TestAnalyzeBackendStatsAndLastSeen(t *testing.T) {
	var buf bytes.Buffer
	a := NewAuditLog(&buf, func() string { return "" })
	// two backends, two peers; give each record an explicit time via the clock
	i := 0
	times := []string{
		"2026-07-16T10:00:00Z", "2026-07-16T10:00:01Z", "2026-07-16T10:00:02Z", "2026-07-16T10:00:03Z",
	}
	a = NewAuditLog(&buf, func() string { return times[i] })
	recs := []AuditRecord{
		{Backend: "fs", Peer: "reader", Method: "tools/call", Tool: "read_file", Decision: "allow"},
		{Backend: "fs", Peer: "reader", Method: "tools/call", Tool: "read_dir", Decision: "allow"},
		{Backend: "pay", Peer: "billing", Method: "tools/call", Tool: "charge", Decision: "cosign"},
		{Backend: "fs", Peer: "bot", Method: "tools/call", Tool: "delete_all", Decision: "deny"},
	}
	for _, r := range recs {
		a.Append(r)
		i++
	}

	sum, err := Analyze(bytes.NewReader(buf.Bytes()), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(sum.BackendStats) != 2 {
		t.Fatalf("expected 2 backend tiles, got %d", len(sum.BackendStats))
	}
	// fs is busiest: 3 calls, 2 peers, last at 10:00:03
	fs := sum.BackendStats[0]
	if fs.Backend != "fs" || fs.Calls != 3 || fs.Peers != 2 || fs.Denied != 1 {
		t.Fatalf("fs backend stat wrong: %+v", fs)
	}
	if fs.LastSeen != "2026-07-16T10:00:03Z" {
		t.Fatalf("fs last seen wrong: %q", fs.LastSeen)
	}
	// per-peer last seen/tool
	var reader *PeerStat
	for i := range sum.Peers {
		if sum.Peers[i].Peer == "reader" {
			reader = &sum.Peers[i]
		}
	}
	if reader == nil || reader.LastSeen != "2026-07-16T10:00:01Z" || reader.LastTool != "read_dir" {
		t.Fatalf("reader peer last-seen/tool wrong: %+v", reader)
	}
}
