package policy

import (
	"bufio"
	"fmt"
	"strings"
	"testing"
	"time"
)

func issueSingleUse(t *testing.T, s *Signer, base time.Time) string {
	t.Helper()
	tok, err := s.IssueCapability(CapabilityClaims{
		Subject:   "KEY",
		Audience:  "fs",
		Tools:     []string{"read_*"},
		SingleUse: true,
		ExpiresAt: base.Add(10 * time.Minute).Unix(),
	}, base)
	if err != nil {
		t.Fatalf("IssueCapability: %v", err)
	}
	return tok
}

func TestCapabilitySingleUseConsumedOnce(t *testing.T) {
	s, err := GenerateSigner()
	if err != nil {
		t.Fatal(err)
	}
	base := time.Unix(1_700_000_000, 0)
	v, _ := NewCapabilityVerifier([]string{s.PubKeyHex()}, func() time.Time { return base.Add(time.Minute) })
	v = v.WithReplayCache(NewMemNonceStore())
	tok := issueSingleUse(t, s, base)

	if _, err := v.Verify(tok, "KEY", "fs", "read_file"); err != nil {
		t.Fatalf("first use must verify: %v", err)
	}
	_, err = v.Verify(tok, "KEY", "fs", "read_file")
	if err == nil || !strings.Contains(err.Error(), "already been used") {
		t.Fatalf("replay must be refused, got %v", err)
	}
}

func TestCapabilitySingleUseFailedVerifyDoesNotBurn(t *testing.T) {
	s, err := GenerateSigner()
	if err != nil {
		t.Fatal(err)
	}
	base := time.Unix(1_700_000_000, 0)
	v, _ := NewCapabilityVerifier([]string{s.PubKeyHex()}, func() time.Time { return base.Add(time.Minute) })
	v = v.WithReplayCache(NewMemNonceStore())
	tok := issueSingleUse(t, s, base)

	// A binding failure (wrong tool) must not consume the grant.
	if _, err := v.Verify(tok, "KEY", "fs", "delete_everything"); err == nil {
		t.Fatal("wrong tool must not verify")
	}
	if _, err := v.Verify(tok, "KEY", "fs", "read_file"); err != nil {
		t.Fatalf("grant must survive a failed verify: %v", err)
	}
}

func TestCapabilitySingleUseNoCacheFailsClosed(t *testing.T) {
	s, err := GenerateSigner()
	if err != nil {
		t.Fatal(err)
	}
	base := time.Unix(1_700_000_000, 0)
	v, _ := NewCapabilityVerifier([]string{s.PubKeyHex()}, func() time.Time { return base.Add(time.Minute) })
	tok := issueSingleUse(t, s, base)

	_, err = v.Verify(tok, "KEY", "fs", "read_file")
	if err == nil || !strings.Contains(err.Error(), "no replay cache") {
		t.Fatalf("single-use token without a replay cache must fail closed, got %v", err)
	}
}

// newSingleUseFilter builds a filter over an echo backend with the given
// rules, a capability verifier with a replay cache, and a reply reader that
// survives multiple calls (unlike runCapCall's one-shot harness).
func newSingleUseFilter(t *testing.T, v *CapabilityVerifier, rules []Rule, base time.Time) (*Filter, chan string) {
	t.Helper()
	backend := newEchoBackend()
	eng := NewEngine(&Policy{DefaultAllow: false, Rules: rules}, func() time.Time { return base }, nil)
	f := NewFilterEngine(backend, Caller{Backend: "fs", Peer: "agent.mesh", PeerKey: "KEY"}, eng, NewAuditLog(nil, nil), nil)
	f.SetCapabilityVerifier(v, false)
	replies := make(chan string, 8)
	go func() {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			replies <- sc.Text()
		}
		close(replies)
	}()
	return f, replies
}

func singleUseCall(t *testing.T, f *Filter, replies chan string, id int, tok string) string {
	t.Helper()
	line := fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":"read_file","arguments":{},"_meta":{"com.meshmcp/capability":%q}}}`, id, tok) + "\n"
	if _, err := f.Write([]byte(line)); err != nil {
		t.Fatal(err)
	}
	select {
	case r := <-replies:
		return r
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for a reply")
		return ""
	}
}

// A single-use grant that upgrades a default-deny is consumed exactly once by
// the filter: the first call goes through, a replay of the same token is
// denied.
func TestFilterSingleUseConsumedOnFinalAllow(t *testing.T) {
	s, _ := GenerateSigner()
	base := time.Unix(1_700_000_000, 0)
	v, _ := NewCapabilityVerifier([]string{s.PubKeyHex()}, func() time.Time { return base.Add(time.Minute) })
	v = v.WithReplayCache(NewMemNonceStore())
	tok := issueSingleUse(t, s, base)
	f, replies := newSingleUseFilter(t, v, nil, base)

	if r := singleUseCall(t, f, replies, 1, tok); strings.Contains(r, "error") {
		t.Fatalf("first use must be allowed, got %s", r)
	}
	r := singleUseCall(t, f, replies, 2, tok)
	if !strings.Contains(r, "already been used") {
		t.Fatalf("replay through the filter must be denied, got %s", r)
	}
}

// A co-sign hold must NOT burn the grant: the call never executed, and the
// approved retry needs the capability again (otherwise the retry hard-fails
// and BOTH single-use artifacts — grant and approval — are wasted).
func TestFilterSingleUseNotBurnedByCosignHold(t *testing.T) {
	s, _ := GenerateSigner()
	base := time.Unix(1_700_000_000, 0)
	v, _ := NewCapabilityVerifier([]string{s.PubKeyHex()}, func() time.Time { return base.Add(time.Minute) })
	v = v.WithReplayCache(NewMemNonceStore())
	tok := issueSingleUse(t, s, base)
	rules := []Rule{{Peers: []string{"*"}, Tools: []string{"read_*"}, Allow: true, RequireCosign: true}}
	f, replies := newSingleUseFilter(t, v, rules, base)

	if r := singleUseCall(t, f, replies, 1, tok); !strings.Contains(r, "co-sign") {
		t.Fatalf("expected a co-sign hold, got %s", r)
	}
	// The grant must have survived the hold.
	if _, err := v.Verify(tok, "KEY", "fs", "read_file"); err != nil {
		t.Fatalf("a co-sign hold must not burn the single-use grant: %v", err)
	}
}

// An explicit policy deny must not burn the grant either.
func TestFilterSingleUseNotBurnedByExplicitDeny(t *testing.T) {
	s, _ := GenerateSigner()
	base := time.Unix(1_700_000_000, 0)
	v, _ := NewCapabilityVerifier([]string{s.PubKeyHex()}, func() time.Time { return base.Add(time.Minute) })
	v = v.WithReplayCache(NewMemNonceStore())
	tok := issueSingleUse(t, s, base)
	rules := []Rule{{Peers: []string{"*"}, Tools: []string{"read_*"}, Allow: false}}
	f, replies := newSingleUseFilter(t, v, rules, base)

	if r := singleUseCall(t, f, replies, 1, tok); !strings.Contains(r, "error") {
		t.Fatalf("expected an explicit deny, got %s", r)
	}
	if _, err := v.Verify(tok, "KEY", "fs", "read_file"); err != nil {
		t.Fatalf("an explicit deny must not burn the single-use grant: %v", err)
	}
}

// When the policy already allows the call (and the surface is not
// capability-required), the grant was not load-bearing and is not consumed.
func TestFilterSingleUseNotBurnedWhenPolicyAllows(t *testing.T) {
	s, _ := GenerateSigner()
	base := time.Unix(1_700_000_000, 0)
	v, _ := NewCapabilityVerifier([]string{s.PubKeyHex()}, func() time.Time { return base.Add(time.Minute) })
	v = v.WithReplayCache(NewMemNonceStore())
	tok := issueSingleUse(t, s, base)
	rules := []Rule{{Peers: []string{"*"}, Tools: []string{"read_*"}, Allow: true}}
	f, replies := newSingleUseFilter(t, v, rules, base)

	if r := singleUseCall(t, f, replies, 1, tok); strings.Contains(r, "error") {
		t.Fatalf("policy-allowed call must go through, got %s", r)
	}
	if _, err := v.Verify(tok, "KEY", "fs", "read_file"); err != nil {
		t.Fatalf("a policy-allowed call must not burn an unneeded single-use grant: %v", err)
	}
}

func TestCapabilityMultiUseUnaffectedByCache(t *testing.T) {
	s, err := GenerateSigner()
	if err != nil {
		t.Fatal(err)
	}
	base := time.Unix(1_700_000_000, 0)
	v, _ := NewCapabilityVerifier([]string{s.PubKeyHex()}, func() time.Time { return base.Add(time.Minute) })
	v = v.WithReplayCache(NewMemNonceStore())
	tok, err := s.IssueCapability(CapabilityClaims{
		Subject: "KEY", Audience: "fs", Tools: []string{"read_*"},
		ExpiresAt: base.Add(10 * time.Minute).Unix(),
	}, base)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if _, err := v.Verify(tok, "KEY", "fs", "read_file"); err != nil {
			t.Fatalf("multi-use verify #%d: %v", i+1, err)
		}
	}
}
