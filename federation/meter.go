package federation

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"sort"

	"github.com/xrey167/meshmcp/policy"
)

// Federation metering (S58): a stateless read-side aggregation over the
// boundary's crossing audit records. Every crossing is already identity- and
// org-attributed in the tamper-evident audit trail, so billing/usage export is
// a replay of that trail — no new hot-path state, and the numbers are backed
// by the same log a customer can independently verify.

// UsageStat is one org's metered crossings for one tool or corpus.
type UsageStat struct {
	Name    string `json:"name"`
	Allowed int64  `json:"allowed"`
	Denied  int64  `json:"denied"`
}

// OrgUsage rolls up one remote org's boundary crossings.
type OrgUsage struct {
	Org     string      `json:"org"` // "" (unrecognized peers) exports as "(unrecognized)"
	Allowed int64       `json:"allowed"`
	Denied  int64       `json:"denied"`
	Tools   []UsageStat `json:"tools,omitempty"`
	Corpora []UsageStat `json:"corpora,omitempty"`
}

// UsageReport is the exportable metering rollup of a crossing audit log.
type UsageReport struct {
	Since     string     `json:"since,omitempty"` // inclusive RFC3339 lower bound, if applied
	Until     string     `json:"until,omitempty"` // exclusive RFC3339 upper bound, if applied
	Crossings int64      `json:"crossings"`       // federation records counted
	Orgs      []OrgUsage `json:"orgs"`
}

// unrecognizedOrg is the export bucket for crossings whose peer mapped to no
// known org (always denied, but still metered — they are boundary pressure).
const unrecognizedOrg = "(unrecognized)"

// AggregateUsage replays audit JSONL from r and rolls up the federation
// boundary crossings per org, per tool, and per corpus. Non-federation records
// are skipped, so the gateway's shared ledger can be metered directly. since
// (inclusive) and until (exclusive) are optional RFC3339 UTC bounds compared
// lexicographically, which is order-correct for the RFC3339 UTC timestamps the
// boundary writes. Output ordering is deterministic (orgs and names sorted).
func AggregateUsage(r io.Reader, since, until string) (UsageReport, error) {
	report := UsageReport{Since: since, Until: until}
	orgs := map[string]*OrgUsage{}
	tools := map[string]map[string]*UsageStat{}   // org -> tool -> stat
	corpora := map[string]map[string]*UsageStat{} // org -> corpus -> stat

	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<20), 16<<20)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var rec policy.AuditRecord
		if err := json.Unmarshal(line, &rec); err != nil {
			// Billing numbers must not be silently partial: a malformed line is
			// surfaced, not skipped.
			return UsageReport{}, fmt.Errorf("federation usage: audit line %d is not valid JSON: %w", lineNo, err)
		}
		if rec.Backend != boundaryAuditBackend {
			continue
		}
		if rec.Method != boundaryMethodTool && rec.Method != boundaryMethodCorpus {
			continue
		}
		if since != "" && rec.Time < since {
			continue
		}
		if until != "" && rec.Time >= until {
			continue
		}
		org := rec.Peer
		if org == "" {
			org = unrecognizedOrg
		}
		ou := orgs[org]
		if ou == nil {
			ou = &OrgUsage{Org: org}
			orgs[org] = ou
			tools[org] = map[string]*UsageStat{}
			corpora[org] = map[string]*UsageStat{}
		}
		byName := tools[org]
		if rec.Method == boundaryMethodCorpus {
			byName = corpora[org]
		}
		st := byName[rec.Tool]
		if st == nil {
			st = &UsageStat{Name: rec.Tool}
			byName[rec.Tool] = st
		}
		report.Crossings++
		if rec.Decision == "allow" {
			ou.Allowed++
			st.Allowed++
		} else {
			ou.Denied++
			st.Denied++
		}
	}
	if err := sc.Err(); err != nil {
		return UsageReport{}, fmt.Errorf("federation usage: read audit log: %w", err)
	}

	for org, ou := range orgs {
		ou.Tools = sortedStats(tools[org])
		ou.Corpora = sortedStats(corpora[org])
		report.Orgs = append(report.Orgs, *ou)
	}
	sort.Slice(report.Orgs, func(i, j int) bool { return report.Orgs[i].Org < report.Orgs[j].Org })
	return report, nil
}

func sortedStats(m map[string]*UsageStat) []UsageStat {
	if len(m) == 0 {
		return nil
	}
	out := make([]UsageStat, 0, len(m))
	for _, s := range m {
		out = append(out, *s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
