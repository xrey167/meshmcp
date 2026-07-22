package knowstore

import (
	"bytes"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/xrey167/meshmcp/air/know"
	"github.com/xrey167/meshmcp/kg"
	"github.com/xrey167/meshmcp/policy"
)

// newFacade builds a facade over a fresh temp store and an in-memory audit log,
// returning both the facade and the buffer the audit chain is written to.
func newFacade(t *testing.T) (*Facade, *bytes.Buffer) {
	t.Helper()
	st, err := kg.Open(filepath.Join(t.TempDir(), "kg.jsonl"), func() string { return "t" })
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	var buf bytes.Buffer
	audit := policy.NewAuditLog(&buf, func() string { return "t" })
	return New(st, audit), &buf
}

// grant builds a caller with the given corpus grants and peer identity.
func grant(peer string, corpora ...string) Caller {
	return Caller{Claims: policy.CapabilityClaims{Corpora: corpora}, Peer: peer}
}

// TestSingleWriterConcurrency is the headline: 32 goroutines each assert a
// distinct triple through ONE facade concurrently. After they all finish the
// hash chain must verify, every triple must be present exactly once, and the
// head must be exactly 32 — proving no append was lost, duplicated, interleaved,
// or corrupted despite the concurrency. This is the N-writer race made
// structurally impossible by the single serialized writer.
func TestSingleWriterConcurrency(t *testing.T) {
	f, _ := newFacade(t)
	const corpus = "shared"
	const n = 32

	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			caller := grant(fmt.Sprintf("wg:writer-%d", i), corpus)
			req := AssertRequest{Corpus: corpus, S: fmt.Sprintf("e%d", i), P: "n", O: "v"}
			if _, err := f.Assert(caller, req); err != nil {
				t.Errorf("assert %d: %v", i, err)
			}
		}(i)
	}
	wg.Wait()

	// Chain intact.
	if err := f.Verify(); err != nil {
		t.Fatalf("chain verify after concurrent writes: %v", err)
	}
	// No record lost or duplicated: exactly n appends.
	if got := f.Head(); got != n {
		t.Fatalf("head = %d, want %d (a write was lost or duplicated)", got, n)
	}
	// Every distinct triple present exactly once.
	reader := grant("wg:reader", corpus)
	recs, err := f.Query(reader, corpus, "", "", "", 0)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(recs) != n {
		t.Fatalf("active set = %d triples, want %d", len(recs), n)
	}
	seen := map[string]int{}
	for _, r := range recs {
		seen[r.S]++
	}
	for i := 0; i < n; i++ {
		s := fmt.Sprintf("e%d", i)
		if seen[s] != 1 {
			t.Errorf("triple %q present %d times, want exactly 1", s, seen[s])
		}
	}
}

// TestUnauthorizedWriteDeniedAndNotWritten proves deny-by-default for writes: a
// caller holding only a broad READ glob (no exact-literal grant) cannot write.
// The op is denied, nothing is written to the store, and a deny record is
// audited.
func TestUnauthorizedWriteDeniedAndNotWritten(t *testing.T) {
	f, buf := newFacade(t)
	// A glob grant confers read visibility but NOT exact write authority.
	attacker := grant("wg:attacker", "acme/*")

	_, err := f.Assert(attacker, AssertRequest{Corpus: "acme/product", S: "x", P: "y", O: "z"})
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("assert error = %v, want ErrDenied", err)
	}
	// Nothing was written — the store head never advanced.
	if got := f.Head(); got != 0 {
		t.Fatalf("head = %d after denied write, want 0 (triple must not be written)", got)
	}
	// A deny record was audited for the write.
	log := buf.String()
	if !strings.Contains(log, `"method":"know.assert"`) || !strings.Contains(log, `"decision":"deny"`) {
		t.Fatalf("expected an audited know.assert deny, got:\n%s", log)
	}
}

// TestUnauthorizedReadDenied proves deny-by-default for reads: an empty corpus
// grant shares nothing, so the read is rejected before the store is touched and
// a deny record is audited.
func TestUnauthorizedReadDenied(t *testing.T) {
	f, buf := newFacade(t)
	nobody := grant("wg:nobody") // empty grant

	recs, err := f.Query(nobody, "acme/product", "", "", "", 0)
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("query error = %v, want ErrDenied", err)
	}
	if recs != nil {
		t.Fatalf("denied read returned %d records, want none", len(recs))
	}
	if !strings.Contains(buf.String(), `"method":"know.retrieve"`) || !strings.Contains(buf.String(), `"decision":"deny"`) {
		t.Fatalf("expected an audited know.retrieve deny, got:\n%s", buf.String())
	}
}

// TestAssertReturnsVerifyingReceipt proves a successful write returns a stable
// KnowReceipt that verifies, and that its KnowHash is the content address of the
// exact fact written (independent of chain position).
func TestAssertReturnsVerifyingReceipt(t *testing.T) {
	f, _ := newFacade(t)
	writer := grant("wg:author", "notes")

	receipt, err := f.Assert(writer, AssertRequest{
		Corpus: "notes", S: "atlas", P: "ownedBy", O: "platform", Source: "roadmap.md",
	})
	if err != nil {
		t.Fatalf("assert: %v", err)
	}
	if !receipt.Verify() {
		t.Fatal("receipt does not verify")
	}
	if !strings.HasPrefix(receipt.KnowHash, "kh_") {
		t.Fatalf("KnowHash = %q, want kh_ prefix", receipt.KnowHash)
	}
	// The receipt addresses exactly the written content.
	want := know.KnowTriple{S: "atlas", P: "ownedBy", O: "platform", Peer: "wg:author", Source: "roadmap.md"}.KnowHash()
	if receipt.KnowHash != want {
		t.Fatalf("KnowHash = %q, want %q (must address the written fact)", receipt.KnowHash, want)
	}
}

// TestAuditChainVerifies runs a mix of allowed and denied writes and reads
// through the facade, then proves the whole audit ledger they produced is an
// unbroken hash chain under policy.VerifyChain — ingest and recall, allow and
// deny, all on one verifiable chain.
func TestAuditChainVerifies(t *testing.T) {
	f, buf := newFacade(t)
	author := grant("wg:author", "notes")
	attacker := grant("wg:attacker", "acme/*")
	nobody := grant("wg:nobody")

	if _, err := f.Assert(author, AssertRequest{Corpus: "notes", S: "a", P: "b", O: "c"}); err != nil {
		t.Fatalf("allowed assert: %v", err)
	}
	if _, err := f.Assert(attacker, AssertRequest{Corpus: "acme/product", S: "x", P: "y", O: "z"}); !errors.Is(err, ErrDenied) {
		t.Fatalf("denied assert error = %v, want ErrDenied", err)
	}
	if _, err := f.Query(author, "notes", "", "", "", 0); err != nil {
		t.Fatalf("allowed query: %v", err)
	}
	if _, err := f.Query(nobody, "notes", "", "", "", 0); !errors.Is(err, ErrDenied) {
		t.Fatalf("denied query error = %v, want ErrDenied", err)
	}

	res, err := policy.VerifyChain(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !res.OK {
		t.Fatalf("audit chain not intact: %s", res.Reason)
	}
	if res.Count != 4 {
		t.Fatalf("audit records = %d, want 4 (2 writes + 2 reads, allow and deny)", res.Count)
	}
}
