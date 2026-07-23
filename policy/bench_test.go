package policy

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The repo's first benchmarks pin the hot paths a gateway pays per call:
// the policy decision, the audit append (with and without the default fsync),
// and boot-time chain verification. Run with:
//
//	go test ./policy/ -bench . -benchmem -run '^$'
//
// They are baselines for spotting regressions, not SLO targets; see
// docs/APPLE-STANDARDS-GAP.md gap 9 ("no performance narrative").

func benchPolicy() *Policy {
	return &Policy{
		DefaultAllow: false,
		Rules: []Rule{
			{Peers: []string{"ops-*.netbird.cloud"}, Tools: []string{"admin_*"}, Allow: true},
			{Peers: []string{"pubkey:SOMEKEY"}, Tools: []string{"write_*"}, Allow: true},
			{Peers: []string{"*"}, Tools: []string{"read_*", "search"}, Allow: true},
			{Peers: []string{"*"}, Tools: []string{"*"}, Allow: false},
		},
	}
}

// BenchmarkDecideToolCallAllow is the common case: an allowed read matching
// the third rule — every governed tools/call pays this.
func BenchmarkDecideToolCallAllow(b *testing.B) {
	eng := NewEngine(benchPolicy(), func() time.Time { return time.Unix(0, 0) }, nil)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if d := eng.DecideToolCall("agent-7.netbird.cloud", "k", "read_doc", nil); !d.Allow {
			b.Fatal("expected allow")
		}
	}
}

// BenchmarkDecideToolCallDeny is the miss: no rule matches, default-deny.
func BenchmarkDecideToolCallDeny(b *testing.B) {
	eng := NewEngine(benchPolicy(), func() time.Time { return time.Unix(0, 0) }, nil)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if d := eng.DecideToolCall("agent-7.netbird.cloud", "k", "delete_everything", nil); d.Allow {
			b.Fatal("expected deny")
		}
	}
}

func benchRecord() AuditRecord {
	return AuditRecord{
		Backend: "kb", Peer: "agent-7.netbird.cloud", PeerKey: "k",
		Method: "tools/call", Tool: "read_doc", Decision: "allow", Rule: 2,
	}
}

// BenchmarkAuditAppend is the chain append alone (hash + marshal + write to an
// in-memory sink): the audit cost every audited decision pays before I/O.
func BenchmarkAuditAppend(b *testing.B) {
	a := NewAuditLog(io.Discard, func() string { return "T" })
	rec := benchRecord()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if err := a.Append(rec); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkAuditAppendFsync is the DEFAULT production configuration: one
// fsync per committed record (audit_fsync on). The gap between this and
// BenchmarkAuditAppend is the price of power-loss durability — the number an
// operator weighing `audit_fsync: false` needs.
func BenchmarkAuditAppendFsync(b *testing.B) {
	f, err := os.OpenFile(filepath.Join(b.TempDir(), "audit.jsonl"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		b.Fatal(err)
	}
	defer f.Close()
	a := NewAuditLog(f, func() string { return "T" }).WithSync(true)
	rec := benchRecord()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if err := a.Append(rec); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkVerifyChain1k is the boot-time cost of verifying a 1000-record
// ledger (seedAuditFromExisting re-verifies on every start).
func BenchmarkVerifyChain1k(b *testing.B) {
	var buf bytes.Buffer
	a := NewAuditLog(&buf, func() string { return "T" })
	rec := benchRecord()
	for i := 0; i < 1000; i++ {
		if err := a.Append(rec); err != nil {
			b.Fatal(err)
		}
	}
	data := buf.Bytes()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		res, err := VerifyChain(bytes.NewReader(data))
		if err != nil || !res.OK {
			b.Fatalf("chain must verify: %+v %v", res, err)
		}
	}
}
