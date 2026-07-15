package insight

import (
	"fmt"
	"strings"
	"testing"

	"meshmcp/policy"
)

// baselineCorpus: agent K, weekday business hours (09-11 UTC), read_file only,
// a couple calls per minute at most.
func baselineCorpus() Corpus {
	var recs []policy.AuditRecord
	for h := 9; h <= 11; h++ {
		for i := 0; i < 2; i++ {
			ts := fmt.Sprintf("2026-07-15T%02d:%02d:00Z", h, i) // Wed
			recs = append(recs, policy.AuditRecord{Time: ts, Peer: "a.mesh", PeerKey: "K", Method: "tools/call", Tool: "read_file", Decision: "allow", Rule: 0})
		}
	}
	c, _ := Profile(strings.NewReader(buildAudit(recs)), nil)
	return c
}

func hasKind(as []Anomaly, kind string) bool {
	for _, a := range as {
		if a.Kind == kind {
			return true
		}
	}
	return false
}

func TestDetectNewTool(t *testing.T) {
	base := baselineCorpus()
	newLog := buildAudit([]policy.AuditRecord{
		{Time: "2026-07-15T09:05:00Z", Peer: "a.mesh", PeerKey: "K", Method: "tools/call", Tool: "delete_all", Decision: "allow", Rule: 0},
	})
	as, _ := Detect(base, strings.NewReader(newLog), DetectOptions{})
	if !hasKind(as, "new-tool") {
		t.Fatalf("should flag the never-before-seen tool: %+v", as)
	}
	// The response must be fail-to-human, not a hard block.
	for _, a := range as {
		if a.Kind == "new-tool" && !strings.Contains(a.Response, "co-sign") {
			t.Fatalf("new-tool should route to co-sign, got %q", a.Response)
		}
	}
}

func TestDetectUnknownIdentity(t *testing.T) {
	base := baselineCorpus()
	newLog := buildAudit([]policy.AuditRecord{
		{Time: "2026-07-15T09:05:00Z", Peer: "stranger.mesh", PeerKey: "ZZ", Method: "tools/call", Tool: "read_file", Decision: "allow", Rule: 0},
	})
	as, _ := Detect(base, strings.NewReader(newLog), DetectOptions{})
	if !hasKind(as, "unknown-identity") {
		t.Fatalf("should flag the unknown identity: %+v", as)
	}
	if as[0].Kind != "unknown-identity" {
		t.Fatalf("unknown-identity should rank highest (score 1.0), got %+v", as[0])
	}
}

func TestDetectRateSpike(t *testing.T) {
	base := baselineCorpus() // read_file p99 is ~1/min
	var recs []policy.AuditRecord
	for i := 0; i < 12; i++ {
		recs = append(recs, policy.AuditRecord{Time: "2026-07-15T09:05:00Z", Peer: "a.mesh", PeerKey: "K", Method: "tools/call", Tool: "read_file", Decision: "allow", Rule: 0})
	}
	as, _ := Detect(base, strings.NewReader(buildAudit(recs)), DetectOptions{})
	if !hasKind(as, "rate-spike") {
		t.Fatalf("12 calls in one minute should trip a rate spike: %+v", as)
	}
}

func TestDetectOffHours(t *testing.T) {
	base := baselineCorpus() // window 09-11 UTC
	newLog := buildAudit([]policy.AuditRecord{
		{Time: "2026-07-15T03:00:00Z", Peer: "a.mesh", PeerKey: "K", Method: "tools/call", Tool: "read_file", Decision: "allow", Rule: 0},
	})
	as, _ := Detect(base, strings.NewReader(newLog), DetectOptions{})
	if !hasKind(as, "off-hours") {
		t.Fatalf("3am activity should be flagged off-hours: %+v", as)
	}
}

func TestDetectDenySpike(t *testing.T) {
	base := baselineCorpus()
	var recs []policy.AuditRecord
	for i := 0; i < 20; i++ {
		recs = append(recs, policy.AuditRecord{Time: "2026-07-15T09:05:00Z", Peer: "a.mesh", PeerKey: "K", Method: "tools/call", Tool: "read_file", Decision: "deny", Rule: -1})
	}
	as, _ := Detect(base, strings.NewReader(buildAudit(recs)), DetectOptions{})
	if !hasKind(as, "deny-spike") {
		t.Fatalf("a wall of denies should trip deny-spike: %+v", as)
	}
}

func TestDetectQuietOnNormalTraffic(t *testing.T) {
	base := baselineCorpus()
	// Normal: read_file in-window, in-baseline, low rate.
	newLog := buildAudit([]policy.AuditRecord{
		{Time: "2026-07-15T10:30:00Z", Peer: "a.mesh", PeerKey: "K", Method: "tools/call", Tool: "read_file", Decision: "allow", Rule: 0},
	})
	as, _ := Detect(base, strings.NewReader(newLog), DetectOptions{})
	if len(as) != 0 {
		t.Fatalf("normal traffic should produce no anomalies, got %+v", as)
	}
}
