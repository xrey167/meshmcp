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
		name              string
		token             string
		peer, aud, tool   string
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
