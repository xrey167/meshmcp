package policy

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// wireBase is the deterministic clock for the wire tests.
var wireBase = time.Unix(1_800_000_000, 0)

// mintWireToken issues + encodes a token for the standard test hop:
// caller CALLER via router ROUTER to audience GW, backend fs, tool read_file.
func mintWireToken(t *testing.T, s *Signer, args []byte) string {
	t.Helper()
	tok, err := s.IssueDelegation(DelegationClaims{
		Caller: "CALLER", Router: "ROUTER", Audience: "GW",
		Backend: "fs", Tool: "read_file", Args: args,
	}, wireBase)
	if err != nil {
		t.Fatal(err)
	}
	enc, err := EncodeDelegation(tok)
	if err != nil {
		t.Fatal(err)
	}
	return enc
}

func newWireVerifier(t *testing.T, s *Signer, audience string) *DelegationVerifier {
	t.Helper()
	v, err := NewDelegationVerifier([]string{s.PubKeyHex()}, audience, NewMemNonceStore(), func() time.Time { return wireBase })
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// TestDelegationWireRoundTrip drives the real wire shape end to end: mint →
// encode → ride a tools/call line's _meta → strip → decode → verify. The
// stripped line must byte-equal the pre-injection line — the backend never
// sees the token.
func TestDelegationWireRoundTrip(t *testing.T) {
	s, _ := GenerateSigner()
	args := []byte(`{"path":"/a"}`)
	enc := mintWireToken(t, s, args)

	// Keys in Go-canonical (sorted) order so the strip's re-marshal reproduces
	// the original bytes exactly.
	original := []byte(`{"id":1,"jsonrpc":"2.0","method":"tools/call","params":{"arguments":{"path":"/a"},"name":"read_file"}}` + "\n")
	injected := []byte(`{"id":1,"jsonrpc":"2.0","method":"tools/call","params":{"_meta":{"` + DelegationMetaKey + `":"` + enc + `"},"arguments":{"path":"/a"},"name":"read_file"}}` + "\n")

	token, out := stripMetaToken(injected, DelegationMetaKey)
	if token != enc {
		t.Fatalf("stripped token mismatch: got %q", token)
	}
	if !bytes.Equal(out, original) {
		t.Fatalf("stripped line must byte-equal the pre-injection line:\n got: %s\nwant: %s", out, original)
	}

	v := newWireVerifier(t, s, "GW")
	tok, err := v.Check(token, "ROUTER", "fs", "read_file", args)
	if err != nil {
		t.Fatalf("round-trip verify failed: %v", err)
	}
	if tok.Caller != "CALLER" || tok.Nonce == "" {
		t.Fatalf("decoded token lost claims: %+v", tok)
	}
}

// TestDelegationWireCheckDenials: every hop-binding violation fails closed.
func TestDelegationWireCheckDenials(t *testing.T) {
	s, _ := GenerateSigner()
	other, _ := GenerateSigner()
	args := []byte(`{"path":"/a"}`)

	cases := []struct {
		name     string
		token    func(t *testing.T) string
		audience string
		router   string
		backend  string
		tool     string
		args     []byte
		wantErr  string
	}{
		{"tampered args", func(t *testing.T) string { return mintWireToken(t, s, args) }, "GW", "ROUTER", "fs", "read_file", []byte(`{"path":"/etc/shadow"}`), "arguments do not match"},
		{"wrong router", func(t *testing.T) string { return mintWireToken(t, s, args) }, "GW", "EVIL", "fs", "read_file", args, "router does not match"},
		{"wrong audience", func(t *testing.T) string { return mintWireToken(t, s, args) }, "OTHERGW", "ROUTER", "fs", "read_file", args, "audience"},
		{"wrong backend", func(t *testing.T) string { return mintWireToken(t, s, args) }, "GW", "ROUTER", "payments", "read_file", args, "not for this backend/tool"},
		{"wrong tool", func(t *testing.T) string { return mintWireToken(t, s, args) }, "GW", "ROUTER", "fs", "delete_file", args, "not for this backend/tool"},
		{"unpinned signer", func(t *testing.T) string { return mintWireToken(t, other, args) }, "GW", "ROUTER", "fs", "read_file", args, "pinned router authority"},
		{"garbage base64", func(t *testing.T) string { return "!!!not-base64url!!!" }, "GW", "ROUTER", "fs", "read_file", args, "base64url"},
		{"garbage JSON", func(t *testing.T) string { return base64.RawURLEncoding.EncodeToString([]byte("notjson")) }, "GW", "ROUTER", "fs", "read_file", args, "not valid JSON"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := newWireVerifier(t, s, tc.audience)
			if _, err := v.Check(tc.token(t), tc.router, tc.backend, tc.tool, tc.args); err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
			}
		})
	}

	t.Run("expired", func(t *testing.T) {
		v, err := NewDelegationVerifier([]string{s.PubKeyHex()}, "GW", NewMemNonceStore(),
			func() time.Time { return wireBase.Add(10 * time.Minute) }) // past the 5m cap
		if err != nil {
			t.Fatal(err)
		}
		if _, err := v.Check(mintWireToken(t, s, args), "ROUTER", "fs", "read_file", args); err == nil || !strings.Contains(err.Error(), "expired") {
			t.Fatalf("want expiry error, got %v", err)
		}
	})

	t.Run("replay", func(t *testing.T) {
		v := newWireVerifier(t, s, "GW")
		enc := mintWireToken(t, s, args)
		if _, err := v.Check(enc, "ROUTER", "fs", "read_file", args); err != nil {
			t.Fatalf("first use must verify: %v", err)
		}
		if _, err := v.Check(enc, "ROUTER", "fs", "read_file", args); err == nil || !strings.Contains(err.Error(), "replay") {
			t.Fatalf("second use must be a replay denial, got %v", err)
		}
	})
}

// TestDelegationVerifierConstruction: fail-closed construction — no keys, a
// malformed key, an empty audience, or a nil nonce store all refuse.
func TestDelegationVerifierConstruction(t *testing.T) {
	s, _ := GenerateSigner()
	good := []string{s.PubKeyHex()}
	if _, err := NewDelegationVerifier(nil, "GW", NewMemNonceStore(), nil); err == nil {
		t.Fatal("empty key set must refuse")
	}
	if _, err := NewDelegationVerifier([]string{"nothex"}, "GW", NewMemNonceStore(), nil); err == nil {
		t.Fatal("malformed key must refuse")
	}
	if _, err := NewDelegationVerifier(good, "", NewMemNonceStore(), nil); err == nil {
		t.Fatal("empty audience must refuse")
	}
	if _, err := NewDelegationVerifier(good, "GW", nil, nil); err == nil {
		t.Fatal("nil nonce store must refuse (replay protection is not optional)")
	}
	if _, err := NewDelegationVerifier(good, "GW", NewMemNonceStore(), nil); err != nil {
		t.Fatalf("valid construction failed: %v", err)
	}
}

// runDelegCall drives one tools/call through a filter whose backend is pinned
// to a delegation authority. The connecting peer is ROUTER; token identifies
// CALLER. It returns the peer-visible reply, everything the backend received,
// and the parsed audit records.
func runDelegCall(t *testing.T, rules []Rule, required bool, token string) (reply string, backendSaw string, records []AuditRecord) {
	t.Helper()
	s, _ := GenerateSigner()
	v := newWireVerifier(t, s, "GW")

	tok := token
	if token == "VALID" {
		tok = mintWireToken(t, s, []byte(`{"path":"/a"}`))
	}

	var auditBuf bytes.Buffer
	backend := newEchoBackend()
	eng := NewEngine(&Policy{DefaultAllow: false, Rules: rules}, func() time.Time { return wireBase }, nil)
	f := NewFilterEngine(backend, Caller{Backend: "fs", Peer: "router.mesh", PeerKey: "ROUTER"},
		eng, NewAuditLog(&auditBuf, nil), nil)
	f.SetDelegationVerifier(v, required)

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
		meta = `,"_meta":{"` + DelegationMetaKey + `":"` + tok + `"}`
	}
	line := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/a"}` + meta + `}}` + "\n"
	if _, err := f.Write([]byte(line)); err != nil {
		t.Fatal(err)
	}
	select {
	case r := <-replies:
		for _, ln := range strings.Split(strings.TrimSpace(auditBuf.String()), "\n") {
			if ln == "" {
				continue
			}
			var rec AuditRecord
			if err := json.Unmarshal([]byte(ln), &rec); err != nil {
				t.Fatalf("unparseable audit record %q: %v", ln, err)
			}
			records = append(records, rec)
		}
		return r, strings.Join(backend.got, "\n"), records
	case <-time.After(5 * time.Second):
		t.Fatal("timed out")
		return "", "", nil
	}
}

// bothAllowed permits CALLER and ROUTER the read_* tools.
func bothAllowed() []Rule {
	return []Rule{{Peers: []string{"pubkey:CALLER", "pubkey:ROUTER"}, Tools: []string{"read_*"}, Allow: true}}
}

// TestFilterDelegationValidTokenAllowed: pinned+required backend — a valid
// token is allowed, the backend never sees it, and the audit record preserves
// both identities plus the nonce.
func TestFilterDelegationValidTokenAllowed(t *testing.T) {
	reply, saw, recs := runDelegCall(t, bothAllowed(), true, "VALID")
	if !strings.Contains(reply, `"tool":"read_file"`) {
		t.Fatalf("call should reach the backend, got reply %q", reply)
	}
	if !strings.Contains(saw, "read_file") {
		t.Fatalf("backend should have received the call: %q", saw)
	}
	if strings.Contains(saw, DelegationMetaKey) {
		t.Fatalf("the delegation token must be stripped before the backend: %q", saw)
	}
	if len(recs) != 1 {
		t.Fatalf("want 1 audit record, got %d", len(recs))
	}
	rec := recs[0]
	if rec.Decision != "allow" || !strings.Contains(rec.Reason, "caller ∩ router ∩ delegation") {
		t.Fatalf("unexpected decision: %+v", rec)
	}
	if rec.DelegatedCaller != "CALLER" || rec.DelegationRouter != "ROUTER" || rec.DelegationNonce == "" {
		t.Fatalf("audit must preserve both identities + nonce: %+v", rec)
	}
}

// TestFilterDelegationRequiredNoToken: a token-less call on a required surface
// is denied, never dispatched, and the denial is attributed to the router.
func TestFilterDelegationRequiredNoToken(t *testing.T) {
	reply, saw, recs := runDelegCall(t, bothAllowed(), true, "")
	if !strings.Contains(reply, "router delegation required") {
		t.Fatalf("want a delegation-required denial, got %q", reply)
	}
	if strings.Contains(saw, "read_file") {
		t.Fatalf("a denied call must never reach the backend: %q", saw)
	}
	if len(recs) != 1 || recs[0].Decision != "deny" || recs[0].DelegationRouter != "ROUTER" {
		t.Fatalf("denial must be audited with the router identity: %+v", recs)
	}
}

// TestFilterDelegationScopeIntersection: the upstream allows only when BOTH
// the token's caller and the connecting router are independently allowed.
func TestFilterDelegationScopeIntersection(t *testing.T) {
	// Router allowed, token-caller not → denied by caller policy.
	onlyRouter := []Rule{{Peers: []string{"pubkey:ROUTER"}, Tools: []string{"read_*"}, Allow: true}}
	reply, saw, _ := runDelegCall(t, onlyRouter, true, "VALID")
	if !strings.Contains(reply, "denied by caller policy") {
		t.Fatalf("want caller-policy denial, got %q", reply)
	}
	if strings.Contains(saw, "read_file") {
		t.Fatal("caller-denied call reached the backend")
	}

	// Caller allowed, router not → denied by router policy.
	onlyCaller := []Rule{{Peers: []string{"pubkey:CALLER"}, Tools: []string{"read_*"}, Allow: true}}
	reply, saw, _ = runDelegCall(t, onlyCaller, true, "VALID")
	if !strings.Contains(reply, "denied by router policy") {
		t.Fatalf("want router-policy denial, got %q", reply)
	}
	if strings.Contains(saw, "read_file") {
		t.Fatal("router-denied call reached the backend")
	}
}

// TestFilterDelegationInvalidTokenDenied: a presented-but-invalid token denies
// even when both identities would be allowed by policy (fail closed).
func TestFilterDelegationInvalidTokenDenied(t *testing.T) {
	reply, saw, recs := runDelegCall(t, bothAllowed(), false, "bogus-token")
	if !strings.Contains(reply, "delegation invalid") {
		t.Fatalf("want a delegation-invalid denial, got %q", reply)
	}
	if strings.Contains(saw, "read_file") {
		t.Fatal("invalid-token call reached the backend")
	}
	if len(recs) != 1 || recs[0].Decision != "deny" {
		t.Fatalf("invalid token must be an audited deny: %+v", recs)
	}
}

// TestFilterDelegationCostIsMax: the intersection charges the most restrictive
// (maximum) cost of the two allowing legs.
func TestFilterDelegationCostIsMax(t *testing.T) {
	rules := []Rule{
		{Peers: []string{"pubkey:CALLER"}, Tools: []string{"read_*"}, Allow: true, Rate: &RateLimit{Max: 100, Per: "1m", Cost: 2}},
		{Peers: []string{"pubkey:ROUTER"}, Tools: []string{"read_*"}, Allow: true, Rate: &RateLimit{Max: 100, Per: "1m", Cost: 5}},
	}
	_, _, recs := runDelegCall(t, rules, true, "VALID")
	if len(recs) != 1 || recs[0].Decision != "allow" {
		t.Fatalf("want an allow, got %+v", recs)
	}
	if recs[0].Cost != 5 {
		t.Fatalf("cost must be the max of the two legs (5), got %d", recs[0].Cost)
	}
}

// countingApprovals is a RequestApprovalStore that counts consumption
// attempts — a probe for side effects on the ORIGINAL caller's budgets.
type countingApprovals struct {
	attempts int
	grant    bool
}

func (c *countingApprovals) ConsumeApproval(ApprovalRequest, time.Time) (bool, string) {
	c.attempts++
	if c.grant {
		return true, ""
	}
	return false, "no approval"
}

// TestFilterDelegationRouterDenyDoesNotBurnCallerApprovals: a router-denied
// delegated call must have NO side effects on the ORIGINAL caller's budgets.
// The caller leg atomically consumes single-use co-sign approvals (and rate
// tokens), so it may run only when the router leg already allows — otherwise
// anyone able to keep the router leg denying could drain a caller's pending
// approvals at will (approval-DoS). The control case proves an allowed call
// still consumes exactly one approval.
func TestFilterDelegationRouterDenyDoesNotBurnCallerApprovals(t *testing.T) {
	run := func(t *testing.T, rules []Rule) (*countingApprovals, string) {
		t.Helper()
		s, _ := GenerateSigner()
		v := newWireVerifier(t, s, "GW")
		tok := mintWireToken(t, s, []byte(`{"path":"/a"}`))

		approvals := &countingApprovals{grant: true}
		backend := newEchoBackend()
		eng := NewEngine(&Policy{DefaultAllow: false, Rules: rules}, func() time.Time { return wireBase }, nil)
		eng.SetRequestApprovals(approvals)
		var auditBuf bytes.Buffer
		f := NewFilterEngine(backend, Caller{Backend: "fs", Peer: "router.mesh", PeerKey: "ROUTER"},
			eng, NewAuditLog(&auditBuf, nil), nil)
		f.SetDelegationVerifier(v, true)

		replies := make(chan string, 4)
		go func() {
			sc := bufio.NewScanner(f)
			for sc.Scan() {
				replies <- sc.Text()
			}
			close(replies)
		}()
		line := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/a"},"_meta":{"` + DelegationMetaKey + `":"` + tok + `"}}}` + "\n"
		if _, err := f.Write([]byte(line)); err != nil {
			t.Fatal(err)
		}
		select {
		case r := <-replies:
			return approvals, r
		case <-time.After(5 * time.Second):
			t.Fatal("timed out")
			return nil, ""
		}
	}

	// Caller is co-sign-gated with a pre-granted approval available; the
	// ROUTER matches no rule, so the router leg is a default deny.
	routerDenied := []Rule{{Peers: []string{"pubkey:CALLER"}, Tools: []string{"read_*"}, Allow: true, RequireCosign: true}}
	approvals, reply := run(t, routerDenied)
	if !strings.Contains(reply, "denied by router policy") {
		t.Fatalf("want a router-policy denial, got %q", reply)
	}
	if approvals.attempts != 0 {
		t.Fatalf("a router-denied call must not touch the caller's approvals, got %d consume attempts", approvals.attempts)
	}

	// Control: router allowed → the same call consumes exactly one approval
	// and is allowed end to end.
	bothLegs := []Rule{
		{Peers: []string{"pubkey:CALLER"}, Tools: []string{"read_*"}, Allow: true, RequireCosign: true},
		{Peers: []string{"pubkey:ROUTER"}, Tools: []string{"read_*"}, Allow: true},
	}
	approvals, reply = run(t, bothLegs)
	if !strings.Contains(reply, `"tool":"read_file"`) {
		t.Fatalf("router-allowed + approved caller should be allowed, got %q", reply)
	}
	if approvals.attempts != 1 {
		t.Fatalf("an allowed delegated call must consume exactly one approval, got %d attempts", approvals.attempts)
	}
}

// TestFilterDelegationNotRequiredLegacy: required:false + no token keeps the
// ordinary single-hop decision — no delegation attribution on the record.
func TestFilterDelegationNotRequiredLegacy(t *testing.T) {
	onlyRouter := []Rule{{Peers: []string{"pubkey:ROUTER"}, Tools: []string{"read_*"}, Allow: true}}
	reply, saw, recs := runDelegCall(t, onlyRouter, false, "")
	if !strings.Contains(reply, `"tool":"read_file"`) {
		t.Fatalf("legacy single-hop call should be allowed, got %q", reply)
	}
	if !strings.Contains(saw, "read_file") {
		t.Fatalf("legacy call should reach the backend: %q", saw)
	}
	if len(recs) != 1 || recs[0].DelegatedCaller != "" || recs[0].DelegationNonce != "" || recs[0].DelegationRouter != "" {
		t.Fatalf("a token-less legacy call must carry no delegation attribution: %+v", recs)
	}
}
