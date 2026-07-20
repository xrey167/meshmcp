package insight

import (
	"strings"
	"testing"

	"github.com/xrey167/meshmcp/policy"
)

// A recorded corpus: an agent that historically was ALLOWED read_file (x2) and
// add, and DENIED delete_all. We then simulate tighter/looser policies.
func recordedCorpus() string {
	return buildAudit([]policy.AuditRecord{
		{Time: "2026-07-15T09:00:00Z", Peer: "a.mesh", PeerKey: "K", Method: "tools/call", Tool: "read_file", Decision: "allow", Rule: 0},
		{Time: "2026-07-15T09:00:05Z", Peer: "a.mesh", PeerKey: "K", Method: "tools/call", Tool: "read_file", Decision: "allow", Rule: 0},
		{Time: "2026-07-15T09:01:00Z", Peer: "a.mesh", PeerKey: "K", Method: "tools/call", Tool: "add", Decision: "allow", Rule: 0},
		{Time: "2026-07-15T09:02:00Z", Peer: "a.mesh", PeerKey: "K", Method: "tools/call", Tool: "delete_all", Decision: "deny", Rule: -1},
	})
}

func TestSimulateDetectsRegression(t *testing.T) {
	// A policy that only allows read_* → `add` (previously allowed) now denied.
	tighter := &policy.Policy{
		DefaultAllow: false,
		Rules:        []policy.Rule{{Peers: []string{"*"}, Tools: []string{"read_*"}, Allow: true}},
	}
	res, err := Simulate(strings.NewReader(recordedCorpus()), tighter)
	if err != nil {
		t.Fatal(err)
	}
	if res.OK() {
		t.Fatalf("tighter policy should regress: %+v", res)
	}
	if len(res.Regressions) != 1 || res.Regressions[0].Tool != "add" {
		t.Fatalf("expected the `add` regression, got %+v", res.Regressions)
	}
	if res.Regressions[0].Was != "allow" || res.Regressions[0].Now != "deny" {
		t.Fatalf("regression classification wrong: %+v", res.Regressions[0])
	}
}

func TestSimulateNoRegressionWhenFaithful(t *testing.T) {
	// A policy that allows exactly what was historically allowed.
	faithful := &policy.Policy{
		DefaultAllow: false,
		Rules: []policy.Rule{
			{Peers: []string{"*"}, Tools: []string{"read_file", "add"}, Allow: true},
		},
	}
	res, err := Simulate(strings.NewReader(recordedCorpus()), faithful)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK() {
		t.Fatalf("faithful policy must not regress: %+v", res.Regressions)
	}
	// delete_all was denied before and is denied now (default deny) → no diff.
	if len(res.Loosened) != 0 {
		t.Fatalf("nothing should be loosened: %+v", res.Loosened)
	}
	// 3 of 4 decisions matched an explicit rule (read_file x2, add); delete_all
	// falls to default → coverage 3/4.
	if res.Coverage < 0.74 || res.Coverage > 0.76 {
		t.Fatalf("coverage should be ~0.75, got %v", res.Coverage)
	}
}

func TestSimulateDetectsLoosening(t *testing.T) {
	// A policy that now allows delete_all (was denied).
	looser := &policy.Policy{
		DefaultAllow: true,
		Rules:        nil,
	}
	res, err := Simulate(strings.NewReader(recordedCorpus()), looser)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Loosened) != 1 || res.Loosened[0].Tool != "delete_all" {
		t.Fatalf("expected delete_all loosening, got %+v", res.Loosened)
	}
}

func TestSimulateRateAndCosign(t *testing.T) {
	// read_file was allowed twice within 5s. A max:1/min rate rule → the second
	// call regresses to deny; a require_cosign rule would move an allow to cosign.
	rated := &policy.Policy{
		DefaultAllow: false,
		Rules: []policy.Rule{
			{Peers: []string{"*"}, Tools: []string{"read_file"}, Allow: true, Rate: &policy.RateLimit{Max: 1, Per: "1m"}},
			{Peers: []string{"*"}, Tools: []string{"add"}, Allow: true, RequireCosign: true},
		},
	}
	res, err := Simulate(strings.NewReader(recordedCorpus()), rated)
	if err != nil {
		t.Fatal(err)
	}
	// One read_file call exceeds the rate → a regression.
	foundRate := false
	for _, r := range res.Regressions {
		if r.Tool == "read_file" {
			foundRate = true
		}
	}
	if !foundRate {
		t.Fatalf("rate limit should regress the 2nd read_file: %+v", res.Regressions)
	}
	// add now needs co-sign.
	if len(res.NowCosign) != 1 || res.NowCosign[0].Tool != "add" {
		t.Fatalf("add should move to cosign, got %+v", res.NowCosign)
	}
}
