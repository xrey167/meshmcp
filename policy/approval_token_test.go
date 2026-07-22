package policy

import (
	"bufio"
	"bytes"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func mkStore(t *testing.T, ttl time.Duration) (*FileApprovalStore, *Signer) {
	t.Helper()
	signer, err := GenerateSigner()
	if err != nil {
		t.Fatal(err)
	}
	return NewFileApprovalStore(t.TempDir(), ttl, signer), signer
}

// TestApprovalArgumentBinding: an approval for one argument set must not
// authorize a different one — the core Phase-3 invariant.
func TestApprovalArgumentBinding(t *testing.T) {
	s, _ := mkStore(t, time.Minute)
	now := time.Unix(1000, 0)
	reqLow := NewApprovalRequest("peerA", "payments", "transfer", []byte(`{"amount":10}`), "")
	if _, err := s.Grant(reqLow, "approver", "", now); err != nil {
		t.Fatal(err)
	}
	// A different amount is a different request: not approved.
	reqHigh := NewApprovalRequest("peerA", "payments", "transfer", []byte(`{"amount":10000}`), "")
	if ok, _ := s.ConsumeApproval(reqHigh, now); ok {
		t.Fatal("approval for amount=10 must NOT authorize amount=10000")
	}
	// The exact approved request is authorized (once).
	if ok, why := s.ConsumeApproval(reqLow, now); !ok {
		t.Fatalf("exact approved request should consume: %s", why)
	}
}

// TestApprovalCanonicalArgs: key order / whitespace does not break a legitimate
// approval (canonical hashing), but a value change does.
func TestApprovalCanonicalArgs(t *testing.T) {
	s, _ := mkStore(t, time.Minute)
	now := time.Unix(1000, 0)
	req := NewApprovalRequest("p", "b", "t", []byte(`{"a":1,"b":2}`), "")
	if _, err := s.Grant(req, "op", "", now); err != nil {
		t.Fatal(err)
	}
	// Same object, different key order + spacing → same canonical hash.
	reordered := NewApprovalRequest("p", "b", "t", []byte(`{ "b": 2, "a": 1 }`), "")
	if ok, why := s.ConsumeApproval(reordered, now); !ok {
		t.Fatalf("canonically-identical args should match: %s", why)
	}
}

// TestApprovalSingleUse: an approval is consumable exactly once (replay
// protection).
func TestApprovalSingleUse(t *testing.T) {
	s, _ := mkStore(t, time.Minute)
	now := time.Unix(1000, 0)
	req := NewApprovalRequest("p", "b", "deploy", []byte(`{}`), "")
	if _, err := s.Grant(req, "op", "", now); err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.ConsumeApproval(req, now); !ok {
		t.Fatal("first consume should succeed")
	}
	if ok, _ := s.ConsumeApproval(req, now); ok {
		t.Fatal("second consume (replay) must fail — single-use")
	}
}

// TestApprovalConcurrentConsumeSingleWinner: under many concurrent consumers of
// one approval, exactly one wins.
func TestApprovalConcurrentConsumeSingleWinner(t *testing.T) {
	s, _ := mkStore(t, time.Minute)
	now := time.Unix(1000, 0)
	req := NewApprovalRequest("p", "b", "deploy", []byte(`{"env":"prod"}`), "")
	if _, err := s.Grant(req, "op", "", now); err != nil {
		t.Fatal(err)
	}
	var wins int64
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if ok, _ := s.ConsumeApproval(req, now); ok {
				atomic.AddInt64(&wins, 1)
			}
		}()
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("exactly one concurrent consumer must win, got %d", wins)
	}
}

// TestApprovalBackendBinding: an approval for one backend must not authorize the
// same tool on another backend.
func TestApprovalBackendBinding(t *testing.T) {
	s, _ := mkStore(t, time.Minute)
	now := time.Unix(1000, 0)
	req := NewApprovalRequest("p", "backendA", "run", []byte(`{}`), "")
	if _, err := s.Grant(req, "op", "", now); err != nil {
		t.Fatal(err)
	}
	other := NewApprovalRequest("p", "backendB", "run", []byte(`{}`), "")
	if ok, _ := s.ConsumeApproval(other, now); ok {
		t.Fatal("approval for backendA must not authorize backendB")
	}
}

// TestApprovalTTL: an expired approval is not honored, and TTL cannot be
// disabled by configuring zero.
func TestApprovalTTL(t *testing.T) {
	s, _ := mkStore(t, 30*time.Second)
	granted := time.Unix(1000, 0)
	req := NewApprovalRequest("p", "b", "t", []byte(`{}`), "")
	if _, err := s.Grant(req, "op", "", granted); err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.ConsumeApproval(req, granted.Add(31*time.Second)); ok {
		t.Fatal("expired approval must not be honored")
	}

	// A zero/negative configured TTL falls back to the default, never "forever".
	z := NewFileApprovalStore(t.TempDir(), 0, mustSigner(t))
	if z.TTL != defaultApprovalTTL {
		t.Fatalf("zero TTL must fall back to default, got %v", z.TTL)
	}
	huge := NewFileApprovalStore(t.TempDir(), 999*time.Hour, mustSigner(t))
	if huge.TTL != maxApprovalTTL {
		t.Fatalf("oversized TTL must clamp to max, got %v", huge.TTL)
	}
}

// TestApprovalSignatureRequired: a token signed by an unpinned/other key is not
// trusted, and a tampered token fails verification.
func TestApprovalSignatureRequired(t *testing.T) {
	s, _ := mkStore(t, time.Minute)
	now := time.Unix(1000, 0)
	req := NewApprovalRequest("p", "b", "t", []byte(`{}`), "")
	if _, err := s.Grant(req, "op", "", now); err != nil {
		t.Fatal(err)
	}
	// Pin a different expected key → the stored token no longer verifies.
	other := mustSigner(t)
	s.PinSigner(other.PubKeyHex())
	if ok, _ := s.ConsumeApproval(req, now); ok {
		t.Fatal("token must not be trusted when pinned to a different signer")
	}
}

// TestApprovalFilePermissions: approval files are written 0600.
func TestApprovalFilePermissions(t *testing.T) {
	s, _ := mkStore(t, time.Minute)
	now := time.Unix(1000, 0)
	req := NewApprovalRequest("p", "b", "t", []byte(`{}`), "")
	if _, err := s.Grant(req, "op", "", now); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(s.file(req.bindingKey()))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("approval file perms = %o, want 0600", perm)
	}
}

func mustSigner(t *testing.T) *Signer {
	t.Helper()
	s, err := GenerateSigner()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// TestFilterRequestBoundCosignEndToEnd proves the wiring: a require_cosign tool
// is authorized ONLY by a single-use approval bound to the exact arguments and
// backend, consumed atomically through the filter's tool-call path.
func TestFilterRequestBoundCosignEndToEnd(t *testing.T) {
	now := func() time.Time { return time.Unix(1000, 0) }
	pol := &Policy{
		DefaultAllow: false,
		Rules: []Rule{
			{Peers: []string{"*"}, Tools: []string{"transfer"}, Allow: true, RequireCosign: true},
		},
	}
	signer, err := GenerateSigner()
	if err != nil {
		t.Fatal(err)
	}
	store := NewFileApprovalStore(t.TempDir(), time.Minute, signer)
	eng := NewEngine(pol, now, nil)
	eng.SetRequestApprovals(store)

	backend := newRecBackend()
	auditBuf := &bytes.Buffer{}
	f := NewFilterEngine(backend, Caller{Backend: "payments", Peer: "p.mesh", PeerKey: "PEERKEY"}, eng,
		NewAuditLog(auditBuf, func() string { return "T" }), nil)
	go func() {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
		}
	}()

	send := func(id, args string) {
		if _, err := f.Write([]byte(`{"jsonrpc":"2.0","id":` + id + `,"method":"tools/call","params":{"name":"transfer","arguments":` + args + `}}` + "\n")); err != nil {
			t.Fatalf("write: %v", err)
		}
	}

	// 1) No approval yet → cosign, not forwarded.
	send("1", `{"amount":10}`)
	if got := backend.recorded(); strings.Contains(got, "transfer") {
		t.Fatalf("un-approved cosign tool must not reach backend: %q", got)
	}

	// 2) Grant an approval bound to amount=10, then the exact call is allowed once.
	req := NewApprovalRequest("PEERKEY", "payments", "transfer", []byte(`{"amount":10}`), "")
	if _, err := store.Grant(req, "approver.mesh", "", now()); err != nil {
		t.Fatal(err)
	}
	send("2", `{"amount":10}`)
	if got := backend.recorded(); !strings.Contains(got, "transfer") {
		t.Fatalf("approved exact call should reach backend: %q", got)
	}

	// 3) A different amount is NOT covered by that approval → not forwarded.
	before := backend.recorded()
	send("3", `{"amount":10000}`)
	if backend.recorded() != before {
		t.Fatalf("approval for amount=10 must not authorize amount=10000")
	}

	// 4) Replaying the approved amount again → single-use consumed, not forwarded.
	before = backend.recorded()
	send("4", `{"amount":10}`)
	if backend.recorded() != before {
		t.Fatalf("approval is single-use; a replay must not be forwarded")
	}
}

// TestApprovalArgsHashIntegerPrecision: distinct integers above 2^53 must NOT
// collide (the old float64 canonicalization coerced them to the same value, so
// an approval for one amount could authorize another).
func TestApprovalArgsHashIntegerPrecision(t *testing.T) {
	a := canonicalArgsHash([]byte(`{"amount":9007199254740993}`)) // 2^53 + 1
	b := canonicalArgsHash([]byte(`{"amount":9007199254740994}`)) // 2^53 + 2
	if a == b {
		t.Fatal("distinct large integers must not collide in the canonical args hash")
	}
	// Same value, different key order still matches (canonicalization holds).
	x := canonicalArgsHash([]byte(`{"a":1,"amount":9007199254740993}`))
	y := canonicalArgsHash([]byte(`{"amount":9007199254740993,"a":1}`))
	if x != y {
		t.Fatal("key order must not change the canonical hash")
	}
}

// TestApprovalSessionBinding: an approval granted for one session must not be
// consumed under a different session.
func TestApprovalSessionBinding(t *testing.T) {
	s, _ := mkStore(t, time.Minute)
	now := time.Unix(1000, 0)
	reqA := ApprovalRequest{PeerKey: "p", Backend: "b", Tool: "t", ArgsHash: canonicalArgsHash([]byte(`{}`)), Session: "sessA"}
	if _, err := s.Grant(reqA, "op", "", now); err != nil {
		t.Fatal(err)
	}
	reqB := reqA
	reqB.Session = "sessB"
	if ok, _ := s.ConsumeApproval(reqB, now); ok {
		t.Fatal("approval for sessA must not be consumed under sessB")
	}
	if ok, why := s.ConsumeApproval(reqA, now); !ok {
		t.Fatalf("approval for sessA should consume under sessA: %s", why)
	}
}

// TestApprovalPolicyHashBinding: an approval granted under one policy version is
// not honored after the policy changes.
func TestApprovalPolicyHashBinding(t *testing.T) {
	s, _ := mkStore(t, time.Minute)
	now := time.Unix(1000, 0)
	base := ApprovalRequest{PeerKey: "p", Backend: "b", Tool: "t", ArgsHash: canonicalArgsHash([]byte(`{}`))}

	// Consume under a different policy hash → rejected (and, being single-use,
	// the claimed approval is spent).
	if _, err := s.Grant(base, "op", "policy-v1", now); err != nil {
		t.Fatal(err)
	}
	underV2 := base
	underV2.PolicyHash = "policy-v2"
	if ok, why := s.ConsumeApproval(underV2, now); ok {
		t.Fatalf("approval under policy-v1 must not be honored under policy-v2 (got %q)", why)
	}

	// A fresh grant consumes under the matching policy hash.
	if _, err := s.Grant(base, "op", "policy-v1", now); err != nil {
		t.Fatal(err)
	}
	underV1 := base
	underV1.PolicyHash = "policy-v1"
	if ok, why := s.ConsumeApproval(underV1, now); !ok {
		t.Fatalf("approval should consume under the matching policy: %s", why)
	}
}
