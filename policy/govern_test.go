package policy

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

// TestProvenanceReceiptTamperEvident proves the F6 property: a retrieval
// receipt (the document/triple hashes that produced an answer) rides the
// tamper-evident audit chain, so editing which sources were used is detectable.
func TestProvenanceReceiptTamperEvident(t *testing.T) {
	var buf bytes.Buffer
	log := NewAuditLog(&buf, func() string { return "t" })
	log.Append(AuditRecord{Backend: "vectors", Peer: "agent", Method: "tools/call", Tool: "search",
		Decision: "allow", Provenance: []string{"hashA", "hashB"}})
	log.Append(AuditRecord{Backend: "vectors", Peer: "agent", Method: "tools/call", Tool: "search",
		Decision: "allow", Provenance: []string{"hashC"}})

	if res, err := VerifyChain(bytes.NewReader(buf.Bytes())); err != nil || !res.OK {
		t.Fatalf("clean receipt chain should verify: ok=%v err=%v", res.OK, err)
	}

	// Forge which source produced the answer: hashB -> hashX.
	tampered := strings.Replace(buf.String(), "hashB", "hashX", 1)
	if res, _ := VerifyChain(strings.NewReader(tampered)); res.OK {
		t.Fatal("tampering a provenance receipt must break verification")
	}
}

// TestTaintContainsRAG proves the F7 property: once a retrieval marks the
// session tainted, an egress/write tool is denied at the engine — below the
// model, where prompt injection cannot reach.
func TestTaintContainsRAG(t *testing.T) {
	pol := &Policy{
		DefaultAllow: false,
		Rules: []Rule{
			{Peers: []string{"*"}, Tools: []string{"search"}, Allow: true, TaintSource: true},
			{Peers: []string{"*"}, Tools: []string{"write_file"}, Allow: true, TaintGuard: true},
		},
	}
	eng := NewEngine(pol, func() time.Time { return time.Unix(0, 0) }, nil)

	labels := map[string]bool{}

	// A write BEFORE any retrieval is allowed.
	if d := eng.DecideToolCall("agent.mesh", "K", "write_file", labels); !d.Allow {
		t.Fatalf("clean write should be allowed, got %q (%s)", d.Outcome, d.Reason)
	}

	// Retrieval is allowed and taints the session.
	d := eng.DecideToolCall("agent.mesh", "K", "search", labels)
	if !d.Allow {
		t.Fatalf("search should be allowed, got %q", d.Outcome)
	}
	for _, l := range d.AddLabels {
		labels[l] = true
	}
	if !labels["tainted"] {
		t.Fatalf("search should taint the session; labels=%v", labels)
	}

	// Now the same write is blocked — network-layer injection containment.
	if d := eng.DecideToolCall("agent.mesh", "K", "write_file", labels); d.Allow {
		t.Fatalf("write after tainted retrieval must be denied")
	} else if d.Outcome != OutcomeDeny {
		t.Fatalf("expected deny, got %q", d.Outcome)
	}
}

// TestKnowledgeCapability proves the S4 property: a signed capability can be
// scoped to specific corpora/subgraphs, the scope is covered by the signature,
// and AllowsCorpus gates queries accordingly.
func TestKnowledgeCapability(t *testing.T) {
	base := time.Unix(1_800_000_000, 0)
	nowf := func() time.Time { return base }
	s, _ := GenerateSigner()
	v, err := NewCapabilityVerifier([]string{s.PubKeyHex()}, nowf)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := s.IssueCapability(CapabilityClaims{
		Subject: "AGENTKEY", Audience: "vectors", Tools: []string{"search"},
		Corpora: []string{"legal", "hr-*"}, ExpiresAt: base.Add(time.Hour).Unix(),
	}, base)
	if err != nil {
		t.Fatal(err)
	}

	claims, err := v.Verify(tok, "AGENTKEY", "vectors", "search")
	if err != nil {
		t.Fatalf("scoped capability should verify: %v", err)
	}
	if !claims.AllowsCorpus("legal") || !claims.AllowsCorpus("hr-payroll") {
		t.Error("capability should allow its granted corpora")
	}
	if claims.AllowsCorpus("medical") {
		t.Error("capability must NOT allow an ungranted corpus")
	}

	// An unscoped capability (no Corpora) places no corpus restriction.
	tok2, _ := s.IssueCapability(CapabilityClaims{
		Subject: "AGENTKEY", Audience: "vectors", Tools: []string{"search"},
		ExpiresAt: base.Add(time.Hour).Unix(),
	}, base)
	c2, _ := v.Verify(tok2, "AGENTKEY", "vectors", "search")
	if !c2.AllowsCorpus("anything") {
		t.Error("unscoped capability should allow any corpus")
	}
}

// TestCostQuota proves the S6 property: a weighted cost drains the token
// bucket faster than one-per-call, enforcing a per-identity budget.
func TestCostQuota(t *testing.T) {
	now := time.Unix(0, 0)
	pol := &Policy{
		DefaultAllow: false,
		Rules: []Rule{
			// Budget of 10 units/hour; each call costs 5 -> only 2 calls.
			{Peers: []string{"*"}, Tools: []string{"embed"}, Allow: true,
				Rate: &RateLimit{Max: 10, Per: "1h", Cost: 5}},
		},
	}
	eng := NewEngine(pol, func() time.Time { return now }, nil)

	if d := eng.DecideToolCall("a.mesh", "K", "embed", nil); !d.Allow {
		t.Fatal("1st call within budget should be allowed")
	}
	if d := eng.DecideToolCall("a.mesh", "K", "embed", nil); !d.Allow {
		t.Fatal("2nd call within budget should be allowed")
	}
	// Budget exhausted (10 units spent): the 3rd is denied by budget.
	if d := eng.DecideToolCall("a.mesh", "K", "embed", nil); d.Allow {
		t.Fatal("3rd call should be denied — budget exhausted")
	}
}
