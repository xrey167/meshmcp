package air

import (
	"fmt"
	"sort"
	"strings"
)

// Air · Osint change — how my attack surface drifted since the last snapshot.
//
// This mirrors change.go's snapshot+diff pattern for the exposure report: given
// an older and a current report it names the findings that appeared, the ones
// that resolved, and the identities whose reach grew or shrank — so a new
// wildcard grant that ships between two runs surfaces as drift (and, wired to a
// fail-on gate, fails a deploy). Pure logic, unit-testable without a mesh.

// ReachChange records how one identity's reachable backends moved between two
// reports.
type ReachChange struct {
	Identity string   `json:"identity"`
	Gained   []string `json:"gained,omitempty"` // backends newly reachable
	Lost     []string `json:"lost,omitempty"`   // backends no longer reachable
}

// ExposureDelta is the difference between an older and a current report.
type ExposureDelta struct {
	NewFindings      []Finding     `json:"new_findings"`
	ResolvedFindings []Finding     `json:"resolved_findings"`
	ReachChanges     []ReachChange `json:"reach_changes"`
	ScoreFrom        ExposureScore `json:"score_from"`
	ScoreTo          ExposureScore `json:"score_to"`
}

// Empty reports whether nothing drifted between the two reports.
func (d ExposureDelta) Empty() bool {
	return len(d.NewFindings) == 0 && len(d.ResolvedFindings) == 0 && len(d.ReachChanges) == 0
}

// DiffReports computes how the surface drifted from old to cur. Findings are
// matched by a stable key (rule + backend + evidence) so a genuinely new risk is
// distinguished from one that merely moved in sort order.
func DiffReports(old, cur ExposureReport) ExposureDelta {
	d := ExposureDelta{ScoreFrom: old.Score, ScoreTo: cur.Score}

	oldF := indexFindings(old.Findings)
	curF := indexFindings(cur.Findings)
	for k, f := range curF {
		if _, ok := oldF[k]; !ok {
			d.NewFindings = append(d.NewFindings, f)
		}
	}
	for k, f := range oldF {
		if _, ok := curF[k]; !ok {
			d.ResolvedFindings = append(d.ResolvedFindings, f)
		}
	}
	sortFindings(d.NewFindings)
	sortFindings(d.ResolvedFindings)

	oldReach := indexReach(old.Reach)
	curReach := indexReach(cur.Reach)
	ids := map[string]bool{}
	for id := range oldReach {
		ids[id] = true
	}
	for id := range curReach {
		ids[id] = true
	}
	for id := range ids {
		gained := subtract(curReach[id], oldReach[id])
		lost := subtract(oldReach[id], curReach[id])
		if len(gained) == 0 && len(lost) == 0 {
			continue
		}
		d.ReachChanges = append(d.ReachChanges, ReachChange{Identity: id, Gained: gained, Lost: lost})
	}
	sort.Slice(d.ReachChanges, func(i, j int) bool { return d.ReachChanges[i].Identity < d.ReachChanges[j].Identity })
	return d
}

// Summary renders a one-line count of the drift, e.g.
// "+2 findings  -1 resolved  ~1 identity" or "no drift".
func (d ExposureDelta) Summary() string {
	if d.Empty() {
		return "no drift"
	}
	var parts []string
	if n := len(d.NewFindings); n > 0 {
		parts = append(parts, fmt.Sprintf("+%d findings", n))
	}
	if n := len(d.ResolvedFindings); n > 0 {
		parts = append(parts, fmt.Sprintf("-%d resolved", n))
	}
	if n := len(d.ReachChanges); n > 0 {
		parts = append(parts, fmt.Sprintf("~%d identity", n))
	}
	return strings.Join(parts, "  ")
}

// findingKey is the stable identity of a finding for diffing: its rule, backend,
// and evidence (so two distinct wildcard grants on one backend do not collapse).
func findingKey(f Finding) string {
	return f.Rule + "\x00" + f.Backend + "\x00" + strings.Join(f.Evidence, ",")
}

func indexFindings(fs []Finding) map[string]Finding {
	m := make(map[string]Finding, len(fs))
	for _, f := range fs {
		m[findingKey(f)] = f
	}
	return m
}

func sortFindings(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		if ri, rj := severityRank(fs[i].Severity), severityRank(fs[j].Severity); ri != rj {
			return ri < rj
		}
		if fs[i].Rule != fs[j].Rule {
			return fs[i].Rule < fs[j].Rule
		}
		return fs[i].Backend < fs[j].Backend
	})
}

func indexReach(rs []Reach) map[string][]string {
	m := make(map[string][]string, len(rs))
	for _, r := range rs {
		m[r.Identity] = r.Backends
	}
	return m
}

// subtract returns the elements of a not present in b, sorted.
func subtract(a, b []string) []string {
	have := make(map[string]bool, len(b))
	for _, x := range b {
		have[x] = true
	}
	var out []string
	for _, x := range a {
		if !have[x] {
			out = append(out, x)
		}
	}
	sort.Strings(out)
	return out
}
