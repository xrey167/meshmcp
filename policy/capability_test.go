package policy

import (
	"bufio"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func mkToken(t *testing.T, s *Signer, now time.Time, sub, aud string, tools []string, exp time.Time) string {
	t.Helper()
	tok, err := s.IssueCapability(CapabilityClaims{
		Issuer: "test-authority", Subject: sub, Audience: aud, Tools: tools, ExpiresAt: exp.Unix(),
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func TestCapabilityIssueAndVerify(t *testing.T) {
	base := time.Unix(1_800_000_000, 0)
	nowf := func() time.Time { return base }
	s, _ := GenerateSigner()
	v, err := NewCapabilityVerifier([]string{s.PubKeyHex()}, nowf)
	if err != nil {
		t.Fatal(err)
	}
	tok := mkToken(t, s, base, "KEY", "finance", []string{"read_*"}, base.Add(15*time.Minute))

	// Happy path.
	if _, err := v.Verify(tok, "KEY", "finance", "read_invoice"); err != nil {
		t.Fatalf("valid capability should verify: %v", err)
	}
	// Rejections.
	cases := []struct {
		name            string
		token           string
		peer, aud, tool string
	}{
		{"wrong subject", tok, "OTHER", "finance", "read_invoice"},
		{"wrong audience", tok, "KEY", "hr", "read_invoice"},
		{"tool not covered", tok, "KEY", "finance", "delete_all"},
		{"garbage token", "not-a-token", "KEY", "finance", "read_invoice"},
	}
	for _, c := range cases {
		if _, err := v.Verify(c.token, c.peer, c.aud, c.tool); err == nil {
			t.Fatalf("%s: expected rejection", c.name)
		}
	}

	// Unpinned authority: a token from a different signer must be rejected.
	other, _ := GenerateSigner()
	otherTok := mkToken(t, other, base, "KEY", "finance", []string{"read_*"}, base.Add(time.Minute))
	if _, err := v.Verify(otherTok, "KEY", "finance", "read_invoice"); err == nil {
		t.Fatal("token from an unpinned authority must be rejected")
	}

	// Expired.
	expired := mkToken(t, s, base.Add(-time.Hour), "KEY", "finance", []string{"read_*"}, base.Add(-30*time.Minute))
	if _, err := v.Verify(expired, "KEY", "finance", "read_invoice"); err == nil {
		t.Fatal("expired capability must be rejected")
	}

	// Over-24h lifetime is refused at issue time.
	if _, err := s.IssueCapability(CapabilityClaims{Subject: "K", Audience: "a", Tools: []string{"*"}, ExpiresAt: base.Add(48 * time.Hour).Unix()}, base); err == nil {
		t.Fatal("issuing a >24h capability must fail")
	}
}

// filterWithCap builds a filter over an echo backend with a deny-by-default
// engine and a capability verifier, and returns the filter + backend + a
// function to read one reply.
func runCapCall(t *testing.T, required bool, rules []Rule, token string) (reply string, backendSaw string) {
	t.Helper()
	base := time.Unix(1_800_000_000, 0)
	s, _ := GenerateSigner()
	v, _ := NewCapabilityVerifier([]string{s.PubKeyHex()}, func() time.Time { return base })

	// If the test wants a valid token, mint one for (KEY, fs, read_*).
	tok := token
	if token == "VALID" {
		tok = mkToken(t, s, base, "KEY", "fs", []string{"read_*"}, base.Add(10*time.Minute))
	}

	backend := newEchoBackend()
	eng := NewEngine(&Policy{DefaultAllow: false, Rules: rules}, func() time.Time { return base }, nil)
	f := NewFilterEngine(backend, Caller{Backend: "fs", Peer: "agent.mesh", PeerKey: "KEY"}, eng, NewAuditLog(nil, nil), nil)
	f.SetCapabilityVerifier(v, required)

	replies := make(chan string, 4)
	go func() {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			replies <- sc.Text()
		}
		close(replies)
	}()

	meta := ""
	if tok != "" {
		meta = `,"_meta":{"com.meshmcp/capability":"` + tok + `"}`
	}
	line := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{}` + meta + `}}` + "\n"
	if _, err := f.Write([]byte(line)); err != nil {
		t.Fatal(err)
	}
	select {
	case r := <-replies:
		return r, strings.Join(backend.got, "\n")
	case <-time.After(5 * time.Second):
		t.Fatal("timed out")
		return "", ""
	}
}

// TestFilterCapabilityStrippedFromNonToolCall guards the invariant that the
// token is removed from EVERY governed client->backend line, not just
// tools/call. A caller sets the capability once on the session, so it rides
// along on follow-up requests (task polling, tools/list); none of those may
// forward it to the backend, trace, or audit.
func TestFilterCapabilityStrippedFromNonToolCall(t *testing.T) {
	base := time.Unix(1_800_000_000, 0)
	s, _ := GenerateSigner()
	v, _ := NewCapabilityVerifier([]string{s.PubKeyHex()}, func() time.Time { return base })
	tok := mkToken(t, s, base, "KEY", "fs", []string{"read_*"}, base.Add(10*time.Minute))

	backend := newEchoBackend()
	eng := NewEngine(&Policy{DefaultAllow: false}, func() time.Time { return base }, nil)
	f := NewFilterEngine(backend, Caller{Backend: "fs", Peer: "agent.mesh", PeerKey: "KEY"}, eng, NewAuditLog(nil, nil), nil)
	f.SetCapabilityVerifier(v, false)

	replies := make(chan string, 4)
	go func() {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			replies <- sc.Text()
		}
		close(replies)
	}()

	// A task-status poll carrying the same capability in _meta (as the CLI's
	// session-wide RequestMeta would attach it). tasks/get is a governed method
	// with no rule, so it passes through — but must be stripped first.
	line := `{"jsonrpc":"2.0","id":7,"method":"tasks/get","params":{"taskId":"t1","_meta":{"com.meshmcp/capability":"` + tok + `"}}}` + "\n"
	if _, err := f.Write([]byte(line)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-replies:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out")
	}
	saw := strings.Join(backend.got, "\n")
	if !strings.Contains(saw, "tasks/get") {
		t.Fatalf("the tasks/get request should have reached the backend: %q", saw)
	}
	if strings.Contains(saw, "com.meshmcp/capability") {
		t.Fatalf("the capability token must be stripped from tasks/get before the backend, but saw: %q", saw)
	}
}

func TestCapabilityRevocation(t *testing.T) {
	base := time.Unix(1_800_000_000, 0)
	s, _ := GenerateSigner()
	tok := mkToken(t, s, base, "KEY", "fs", []string{"read_*"}, base.Add(10*time.Minute))

	// Without revocation the token verifies.
	v, _ := NewCapabilityVerifier([]string{s.PubKeyHex()}, func() time.Time { return base })
	c, err := v.Verify(tok, "KEY", "fs", "read_file")
	if err != nil {
		t.Fatalf("token should verify before revocation: %v", err)
	}
	// Wiring a predicate that revokes exactly this token's ID must make it fail.
	vr := v.WithRevocation(func(id string) bool { return id == c.ID })
	if _, err := vr.Verify(tok, "KEY", "fs", "read_file"); err == nil {
		t.Fatal("a revoked token ID must be rejected")
	}
	// A different ID stays valid.
	vr2 := v.WithRevocation(func(id string) bool { return id == "cap_other" })
	if _, err := vr2.Verify(tok, "KEY", "fs", "read_file"); err != nil {
		t.Fatalf("a non-revoked token must still verify: %v", err)
	}
}

func TestCapabilityNotBefore(t *testing.T) {
	base := time.Unix(1_800_000_000, 0)
	s, _ := GenerateSigner()
	v, _ := NewCapabilityVerifier([]string{s.PubKeyHex()}, func() time.Time { return base })

	// Issue a token that becomes valid 10m from now and expires in 30m.
	tok, err := s.IssueCapability(CapabilityClaims{
		Subject: "KEY", Audience: "fs", Tools: []string{"read_*"},
		NotBefore: base.Add(10 * time.Minute).Unix(),
		ExpiresAt: base.Add(30 * time.Minute).Unix(),
	}, base)
	if err != nil {
		t.Fatal(err)
	}
	// Not yet valid at base.
	if _, err := v.Verify(tok, "KEY", "fs", "read_file"); err == nil {
		t.Fatal("a not-yet-valid (nbf in the future) token must be rejected")
	}
	// Valid once nbf has passed.
	v2, _ := NewCapabilityVerifier([]string{s.PubKeyHex()}, func() time.Time { return base.Add(11 * time.Minute) })
	if _, err := v2.Verify(tok, "KEY", "fs", "read_file"); err != nil {
		t.Fatalf("token should verify after not-before: %v", err)
	}
}

// TestCapabilityRejectsMalformedGlobAtIssue: an authority can't mint a token
// whose tool pattern can never match.
func TestCapabilityRejectsMalformedGlobAtIssue(t *testing.T) {
	base := time.Unix(1_800_000_000, 0)
	s, _ := GenerateSigner()
	if _, err := s.IssueCapability(CapabilityClaims{
		Subject: "KEY", Audience: "fs", Tools: []string{"read_["}, ExpiresAt: base.Add(time.Minute).Unix(),
	}, base); err == nil {
		t.Fatal("issuing a token with a malformed tool glob must fail")
	}
}

func TestFilterCapabilityUpgradesDefaultDeny(t *testing.T) {
	// deny-by-default (no rule for read_file) + a valid capability → allowed,
	// and the token must NOT reach the backend.
	reply, saw := runCapCall(t, false, nil, "VALID")
	if strings.Contains(reply, "blocked") || strings.Contains(reply, "denied") {
		t.Fatalf("valid capability should upgrade a default-deny to allow, got: %s", reply)
	}
	if !strings.Contains(saw, "read_file") {
		t.Fatalf("call should have reached the backend: %q", saw)
	}
	if strings.Contains(saw, "com.meshmcp/capability") || strings.Contains(saw, "_meta") {
		t.Fatalf("the capability token/_meta must be stripped before the backend, but saw: %q", saw)
	}
}

func TestFilterCapabilityFailsClosedOnInvalid(t *testing.T) {
	reply, saw := runCapCall(t, false, nil, "garbage-token")
	if !strings.Contains(reply, "invalid capability") {
		t.Fatalf("an invalid presented token must fail closed, got: %s", reply)
	}
	if strings.Contains(saw, "read_file") {
		t.Fatalf("a failed-closed call must not reach the backend: %q", saw)
	}
}

func TestFilterCapabilityExplicitDenyWins(t *testing.T) {
	// An explicit deny rule for read_file must beat a valid capability.
	rules := []Rule{{Peers: []string{"*"}, Tools: []string{"read_file"}, Allow: false}}
	reply, saw := runCapCall(t, false, rules, "VALID")
	if !strings.Contains(reply, "denied") && !strings.Contains(reply, "blocked") {
		t.Fatalf("explicit deny should win over a capability, got: %s", reply)
	}
	if strings.Contains(saw, "read_file") {
		t.Fatalf("explicitly denied call must not reach the backend: %q", saw)
	}
}

func TestFilterCapabilityRequired(t *testing.T) {
	// required=true, no token → denied even though nothing explicitly forbids it.
	reply, _ := runCapCall(t, true, nil, "")
	if !strings.Contains(reply, "capability required") {
		t.Fatalf("required surface with no token should deny, got: %s", reply)
	}
	// required=true + valid token → allowed.
	reply2, _ := runCapCall(t, true, nil, "VALID")
	if strings.Contains(reply2, "denied") || strings.Contains(reply2, "blocked") || strings.Contains(reply2, "required") {
		t.Fatalf("required surface with a valid token should allow, got: %s", reply2)
	}
}

// sanity: the token itself is never a normal JSON field the backend expects.
func TestCapabilityTokenIsOpaqueBase64(t *testing.T) {
	base := time.Unix(1_800_000_000, 0)
	s, _ := GenerateSigner()
	tok := mkToken(t, s, base, "K", "a", []string{"*"}, base.Add(time.Minute))
	if strings.ContainsAny(tok, "{}\" ") {
		t.Fatalf("token should be opaque base64url, got %q", tok)
	}
	var probe map[string]any
	if json.Unmarshal([]byte(tok), &probe) == nil {
		t.Fatal("token must not be raw JSON")
	}
}

// TestCapabilitySingleUse proves S19: a single-use grant is redeemable at most
// once, a replay is refused, and presenting one to a verifier with no replay
// guard is refused (fail-closed). A rejected call never burns the token.
func TestCapabilitySingleUse(t *testing.T) {
	s, err := GenerateSigner()
	if err != nil {
		t.Fatal(err)
	}
	base := time.Unix(1_800_000_000, 0)
	nowf := func() time.Time { return base }

	tok, err := s.IssueCapability(CapabilityClaims{
		Issuer: "a", Subject: "peerK", Audience: "fs", Tools: []string{"read_*"},
		SingleUse: true, ExpiresAt: base.Add(time.Hour).Unix(),
	}, base)
	if err != nil {
		t.Fatal(err)
	}

	// No replay guard configured → a single-use grant is refused outright.
	vNone, _ := NewCapabilityVerifier([]string{s.PubKeyHex()}, nowf)
	if _, err := vNone.Verify(tok, "peerK", "fs", "read_x"); err == nil {
		t.Fatalf("single-use grant with no replay guard must be refused")
	}

	// With a guard: first redemption succeeds, second is refused.
	seen := map[string]bool{}
	v, _ := NewCapabilityVerifier([]string{s.PubKeyHex()}, nowf)
	v = v.WithReplayGuard(func(id string) bool {
		if seen[id] {
			return false
		}
		seen[id] = true
		return true
	})
	if _, err := v.Verify(tok, "peerK", "fs", "read_x"); err != nil {
		t.Fatalf("first redemption should succeed: %v", err)
	}
	if _, err := v.Verify(tok, "peerK", "fs", "read_x"); err == nil {
		t.Fatalf("second redemption of a single-use grant must be refused")
	}

	// A REJECTED call (wrong tool) must NOT burn the token: the guard is the last
	// gate, so a fresh single-use grant survives a failed check.
	tok2, _ := s.IssueCapability(CapabilityClaims{
		Issuer: "a", Subject: "peerK", Audience: "fs", Tools: []string{"read_*"},
		SingleUse: true, ExpiresAt: base.Add(time.Hour).Unix(),
	}, base)
	if _, err := v.Verify(tok2, "peerK", "fs", "write_x"); err == nil {
		t.Fatalf("wrong tool should fail")
	}
	if _, err := v.Verify(tok2, "peerK", "fs", "read_x"); err != nil {
		t.Fatalf("a failed check must not consume the single-use token: %v", err)
	}
}
