package insight

import (
	"strings"
	"testing"

	"github.com/xrey167/meshmcp/policy"
)

func richCorpus() string {
	var recs []policy.AuditRecord
	// agent K: read_file (allowed, many), read_dir (allowed), delete_all (denied).
	for i := 0; i < 5; i++ {
		recs = append(recs,
			policy.AuditRecord{Time: "2026-07-15T09:0" + string(rune('0'+i)) + ":00Z", Peer: "a.mesh", PeerKey: "K", Method: "tools/call", Tool: "read_file", Decision: "allow", Rule: 0},
		)
	}
	recs = append(recs,
		policy.AuditRecord{Time: "2026-07-15T10:00:00Z", Peer: "a.mesh", PeerKey: "K", Method: "tools/call", Tool: "read_dir", Decision: "allow", Rule: 0},
		policy.AuditRecord{Time: "2026-07-15T11:00:00Z", Peer: "a.mesh", PeerKey: "K", Method: "tools/call", Tool: "delete_all", Decision: "deny", Rule: -1},
		policy.AuditRecord{Time: "2026-07-15T09:30:00Z", Peer: "b.mesh", PeerKey: "K2", Method: "tools/call", Tool: "add", Decision: "allow", Rule: 0},
	)
	return buildAudit(recs)
}

func TestRecommendGrantsObservedDeniesRest(t *testing.T) {
	c, _ := Profile(strings.NewReader(richCorpus()), nil)
	pol, notes := Recommend(c, RecommendOptions{})
	if pol.DefaultAllow {
		t.Fatal("recommended policy must be deny-by-default")
	}
	// agent K should be granted read_file + read_dir but NOT delete_all.
	var kRule *policy.Rule
	for i := range pol.Rules {
		if pol.Rules[i].Peers[0] == "pubkey:K" {
			kRule = &pol.Rules[i]
		}
	}
	if kRule == nil {
		t.Fatalf("no rule for agent K; rules=%+v", pol.Rules)
	}
	joined := strings.Join(kRule.Tools, ",")
	if !strings.Contains(joined, "read_file") || !strings.Contains(joined, "read_dir") {
		t.Fatalf("K should be granted its read tools, got %v", kRule.Tools)
	}
	if strings.Contains(joined, "delete_all") {
		t.Fatalf("delete_all was only ever denied; must not be granted: %v", kRule.Tools)
	}
	// A rate cap should be derived (timestamps present).
	if kRule.Rate == nil || kRule.Rate.Max < 1 {
		t.Fatalf("expected a rate cap for K, got %+v", kRule.Rate)
	}
	if len(notes) == 0 {
		t.Fatal("expected review notes")
	}
}

// The round-trip invariant: a policy learned from behavior must not deny that
// behavior. Recommend → Simulate against the same corpus → zero regressions.
func TestRecommendRoundTripNoRegression(t *testing.T) {
	corpus := richCorpus()
	c, _ := Profile(strings.NewReader(corpus), nil)
	pol, _ := Recommend(c, RecommendOptions{})

	res, err := Simulate(strings.NewReader(corpus), pol)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK() {
		t.Fatalf("a recommended policy must not regress its own corpus, got: %+v", res.Regressions)
	}
	// delete_all was denied historically and should stay denied (not loosened).
	for _, l := range res.Loosened {
		if l.Tool == "delete_all" {
			t.Fatalf("delete_all should remain denied, but was loosened")
		}
	}
}

func TestRecommendGeneralize(t *testing.T) {
	c, _ := Profile(strings.NewReader(richCorpus()), nil)
	pol, notes := Recommend(c, RecommendOptions{Generalize: true})
	var kRule *policy.Rule
	for i := range pol.Rules {
		if pol.Rules[i].Peers[0] == "pubkey:K" {
			kRule = &pol.Rules[i]
		}
	}
	// read_file + read_dir share the read_ prefix → collapsed to read_*.
	if kRule == nil || strings.Join(kRule.Tools, ",") != "read_*" {
		t.Fatalf("generalize should collapse to read_*, got %v", kRule.Tools)
	}
	widened := false
	for _, n := range notes {
		if strings.Contains(n, "widened") {
			widened = true
		}
	}
	if !widened {
		t.Fatal("generalization must be flagged in notes")
	}
}
