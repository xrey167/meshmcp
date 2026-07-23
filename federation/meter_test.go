package federation

import (
	"bytes"
	"strings"
	"testing"

	"github.com/xrey167/meshmcp/policy"
)

// meterBoundary builds a boundary whose crossings land in buf as audit JSONL,
// with an injectable clock for the time-window test.
func meterBoundary(buf *bytes.Buffer, times []string) *Boundary {
	i := 0
	audit := policy.NewAuditLog(buf, func() string {
		t := times[i%len(times)]
		i++
		return t
	})
	return NewBoundary(
		[]Grant{
			{Org: "acme", Tools: []string{"search", "fetch_*"}, Corpora: []string{"eng-*"}},
			{Org: "globex", Tools: []string{"search"}},
		},
		[]Mapping{
			{Match: "pubkey:acme-key", Org: "acme"},
			{Match: "pubkey:globex-key", Org: "globex"},
		},
		audit,
	)
}

func TestAggregateUsageRollsUpPerOrgToolAndCorpus(t *testing.T) {
	var buf bytes.Buffer
	b := meterBoundary(&buf, []string{"2026-07-10T00:00:00Z"})

	// acme: 2 allowed tool calls, 1 denied tool, 1 allowed + 1 denied corpus.
	b.Check("acme", "search")
	b.Check("acme", "search")
	b.Check("acme", "rm_rf")
	b.CheckCorpus("acme", "eng-docs")
	b.CheckCorpus("acme", "finance")
	// globex: 1 allowed.
	b.Check("globex", "search")
	// unrecognized peer: metered under the unrecognized bucket.
	b.Check("", "search")

	report, err := AggregateUsage(bytes.NewReader(buf.Bytes()), "", "")
	if err != nil {
		t.Fatal(err)
	}
	if report.Crossings != 7 {
		t.Fatalf("expected 7 crossings, got %d", report.Crossings)
	}
	if len(report.Orgs) != 3 {
		t.Fatalf("expected 3 orgs (incl. unrecognized), got %+v", report.Orgs)
	}
	// Deterministic order: "(unrecognized)" < "acme" < "globex".
	if report.Orgs[0].Org != unrecognizedOrg || report.Orgs[1].Org != "acme" || report.Orgs[2].Org != "globex" {
		t.Fatalf("org order wrong: %+v", report.Orgs)
	}
	acme := report.Orgs[1]
	if acme.Allowed != 3 || acme.Denied != 2 {
		t.Fatalf("acme totals wrong: %+v", acme)
	}
	if len(acme.Tools) != 2 || acme.Tools[0].Name != "rm_rf" || acme.Tools[0].Denied != 1 ||
		acme.Tools[1].Name != "search" || acme.Tools[1].Allowed != 2 {
		t.Fatalf("acme tool stats wrong: %+v", acme.Tools)
	}
	if len(acme.Corpora) != 2 || acme.Corpora[0].Name != "eng-docs" || acme.Corpora[0].Allowed != 1 ||
		acme.Corpora[1].Name != "finance" || acme.Corpora[1].Denied != 1 {
		t.Fatalf("acme corpus stats wrong: %+v", acme.Corpora)
	}
	if report.Orgs[0].Denied != 1 || report.Orgs[0].Allowed != 0 {
		t.Fatalf("unrecognized bucket wrong: %+v", report.Orgs[0])
	}
	if report.Orgs[2].Allowed != 1 || len(report.Orgs[2].Corpora) != 0 {
		t.Fatalf("globex stats wrong: %+v", report.Orgs[2])
	}
}

func TestAggregateUsageSkipsNonFederationRecords(t *testing.T) {
	var buf bytes.Buffer
	audit := policy.NewAuditLog(&buf, func() string { return "2026-07-10T00:00:00Z" })
	// A gateway record sharing the ledger must not be billed to anyone.
	audit.Append(policy.AuditRecord{Backend: "files", Peer: "agent", Method: "tools/call", Tool: "read", Decision: "allow"})
	b := NewBoundary([]Grant{{Org: "acme", Tools: []string{"search"}}},
		[]Mapping{{Match: "pubkey:k", Org: "acme"}}, audit)
	b.Check("acme", "search")

	report, err := AggregateUsage(bytes.NewReader(buf.Bytes()), "", "")
	if err != nil {
		t.Fatal(err)
	}
	if report.Crossings != 1 || len(report.Orgs) != 1 || report.Orgs[0].Org != "acme" {
		t.Fatalf("non-federation record leaked into metering: %+v", report)
	}
}

func TestAggregateUsageTimeWindow(t *testing.T) {
	var buf bytes.Buffer
	b := meterBoundary(&buf, []string{
		"2026-06-30T23:59:59Z", // before the window
		"2026-07-01T00:00:00Z", // in (inclusive lower bound)
		"2026-07-31T23:59:59Z", // in
		"2026-08-01T00:00:00Z", // out (exclusive upper bound)
	})
	for i := 0; i < 4; i++ {
		b.Check("acme", "search")
	}
	report, err := AggregateUsage(bytes.NewReader(buf.Bytes()), "2026-07-01T00:00:00Z", "2026-08-01T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if report.Crossings != 2 || report.Orgs[0].Allowed != 2 {
		t.Fatalf("July window should count exactly 2 crossings: %+v", report)
	}
}

func TestAggregateUsageFailsOnMalformedLine(t *testing.T) {
	r := strings.NewReader(`{"backend":"federation-boundary","peer":"acme","method":"federation/tools/call","tool":"search","decision":"allow"}` + "\n" + `{not json`)
	if _, err := AggregateUsage(r, "", ""); err == nil {
		t.Fatal("a malformed audit line must fail the export, not silently under-bill")
	}
}
