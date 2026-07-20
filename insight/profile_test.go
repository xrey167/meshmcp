package insight

import (
	"bytes"
	"strings"
	"testing"

	"github.com/xrey167/meshmcp/policy"
)

// buildAudit writes a hash-chained audit log from records. The AuditLog stamps
// each record's Time from its clock, so we feed each record's own Time through
// the clock as it is appended (preserving per-record timestamps).
func buildAudit(recs []policy.AuditRecord) string {
	var buf bytes.Buffer
	i := 0
	a := policy.NewAuditLog(&buf, func() string { return recs[i].Time })
	for _, r := range recs {
		a.Append(r)
		i++
	}
	return buf.String()
}

func TestProfileAggregates(t *testing.T) {
	recs := []policy.AuditRecord{
		{Time: "2026-07-15T09:00:00Z", Peer: "agent.mesh", PeerKey: "K1", Method: "tools/call", Tool: "read_file", Decision: "allow", Rule: 0},
		{Time: "2026-07-15T09:00:10Z", Peer: "agent.mesh", PeerKey: "K1", Method: "tools/call", Tool: "read_file", Decision: "allow", Rule: 0},
		{Time: "2026-07-15T09:05:00Z", Peer: "agent.mesh", PeerKey: "K1", Method: "tools/call", Tool: "delete_all", Decision: "deny", Rule: -1},
		{Time: "2026-07-15T10:00:00Z", Peer: "bot.mesh", PeerKey: "K2", Method: "tools/call", Tool: "add", Decision: "allow", Rule: 0},
	}
	c, err := Profile(strings.NewReader(buildAudit(recs)), nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.Records != 4 || !c.ChainOK {
		t.Fatalf("expected 4 records + intact chain, got %d chainOK=%v", c.Records, c.ChainOK)
	}
	if len(c.Identities) != 2 {
		t.Fatalf("expected 2 identities, got %d", len(c.Identities))
	}
	agent := c.Identities[idKey("agent.mesh", "K1")]
	if agent == nil || agent.Calls != 3 || agent.Allowed != 2 || agent.Denied != 1 {
		t.Fatalf("agent profile wrong: %+v", agent)
	}
	// read_file is the busiest tool; two calls in the same minute → p99>=2.
	var rf *ToolProfile
	for _, tp := range agent.Tools {
		if tp.Tool == "read_file" {
			rf = tp
		}
	}
	if rf == nil || rf.Calls != 2 || rf.PerMinP99 < 2 {
		t.Fatalf("read_file tool profile wrong: %+v", rf)
	}
	// Active at hour 9 UTC on a Wednesday (2026-07-15).
	if agent.Hours[9] == 0 || agent.Days[3] == 0 {
		t.Fatalf("temporal footprint wrong: hours=%v days=%v", agent.Hours, agent.Days)
	}
}

func TestProfileAttributesLabelsViaPolicy(t *testing.T) {
	pol := &policy.Policy{Rules: []policy.Rule{
		{Peers: []string{"*"}, Tools: []string{"read_customer"}, Allow: true, EmitLabels: []string{"pii"}},
	}}
	recs := []policy.AuditRecord{
		{Time: "2026-07-15T09:00:00Z", Peer: "agent.mesh", PeerKey: "K1", Method: "tools/call", Tool: "read_customer", Decision: "allow", Rule: 0},
	}
	c, err := Profile(strings.NewReader(buildAudit(recs)), pol)
	if err != nil {
		t.Fatal(err)
	}
	agent := c.Identities[idKey("agent.mesh", "K1")]
	if agent == nil || len(agent.EmittedLabels) != 1 || agent.EmittedLabels[0] != "pii" {
		t.Fatalf("expected pii emitted label, got %+v", agent)
	}
}

func TestProfileFlagsTamperedChain(t *testing.T) {
	recs := []policy.AuditRecord{
		{Time: "2026-07-15T09:00:00Z", Peer: "a", Method: "tools/call", Tool: "read_file", Decision: "allow", Rule: 0},
		{Time: "2026-07-15T09:00:01Z", Peer: "a", Method: "tools/call", Tool: "read_file", Decision: "allow", Rule: 0},
	}
	log := buildAudit(recs)
	tampered := strings.Replace(log, "read_file", "rm_rf", 1)
	c, err := Profile(strings.NewReader(tampered), nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.ChainOK {
		t.Fatal("profile must report the tampered chain as not OK (don't learn from a tampered log)")
	}
}

func TestPercentile(t *testing.T) {
	if p := percentile([]int{1, 2, 3, 4, 100}, 0.99); p != 100 {
		t.Fatalf("p99 should be 100, got %d", p)
	}
	if p := percentile(nil, 0.5); p != 0 {
		t.Fatalf("empty p50 should be 0, got %d", p)
	}
}
