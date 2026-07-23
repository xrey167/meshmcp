package policy

import (
	"bytes"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"
)

// Rotation must produce sealed archive segments plus an active file whose
// concatenation (in name order) is ONE intact hash chain.
func TestRotatingFileSinkChainContinuity(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	tick := time.Unix(1_700_000_000, 0)
	now := func() time.Time { tick = tick.Add(time.Second); return tick }
	sink, err := OpenRotatingFileSink(path, 600, now) // a record is ~300 bytes
	if err != nil {
		t.Fatal(err)
	}
	a := NewAuditLog(sink, func() string { return "T" }).WithSync(true)
	for i := 0; i < 8; i++ {
		if err := a.Append(AuditRecord{
			Backend: "fs", Peer: "agent.mesh", Method: "tools/call",
			Tool: "read_file", Decision: "allow", Rule: 0,
		}); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}

	archives, err := filepath.Glob(path + ".*")
	if err != nil {
		t.Fatal(err)
	}
	if len(archives) < 2 {
		t.Fatalf("expected multiple sealed segments, got %v", archives)
	}
	sort.Strings(archives)

	// Concatenate segments in order + active file: the chain must verify end
	// to end with contiguous sequence numbers.
	var all bytes.Buffer
	for _, p := range append(archives, path) {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		all.Write(b)
	}
	res, err := VerifyChain(&all)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK || res.Count != 8 {
		t.Fatalf("concatenated segments must verify: %+v", res)
	}

	// Each archive alone is a mid-chain segment: strict VerifyChain refuses it
	// from genesis (except the first, which starts at seq 1).
	b, err := os.ReadFile(archives[len(archives)-1])
	if err != nil {
		t.Fatal(err)
	}
	seg, _ := VerifyChain(bytes.NewReader(b))
	if seg.OK {
		t.Fatal("a later segment alone must not verify from genesis (it is mid-chain)")
	}
	// But the seeded verifier accepts it given the previous head.
	prevData := func() []byte {
		var buf bytes.Buffer
		for _, p := range archives[:len(archives)-1] {
			bb, _ := os.ReadFile(p)
			buf.Write(bb)
		}
		return buf.Bytes()
	}()
	prevRes, _, _ := VerifyForRepair(prevData)
	if !prevRes.OK {
		t.Fatalf("prefix segments must verify: %+v", prevRes)
	}
	segRes, _, _ := VerifyForRepairFrom(b, prevRes.Count, prevRes.LastHash)
	if !segRes.OK {
		t.Fatalf("seeded segment verification must pass: %+v", segRes)
	}
}

// A single record larger than the budget must still be written (never dropped).
func TestRotatingFileSinkOversizedRecord(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	sink, err := OpenRotatingFileSink(path, 64, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()
	big := bytes.Repeat([]byte("x"), 200)
	big = append(big, '\n')
	if _, err := sink.Write(big); err != nil {
		t.Fatalf("first oversized write: %v", err)
	}
	if _, err := sink.Write(big); err != nil {
		t.Fatalf("second oversized write (rotates first): %v", err)
	}
	archives, _ := filepath.Glob(path + ".*")
	if len(archives) != 1 {
		t.Fatalf("expected one rotation, got %v", archives)
	}
}

func TestOpenRotatingFileSinkRejectsZeroBudget(t *testing.T) {
	if _, err := OpenRotatingFileSink(filepath.Join(t.TempDir(), "a"), 0, nil); err == nil {
		t.Fatal("maxBytes 0 must be rejected")
	}
}
