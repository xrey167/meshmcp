package insight

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"sort"
	"time"

	"github.com/xrey167/meshmcp/policy"
)

// Change is one aggregated difference between the recorded verdict and the
// verdict a candidate policy would produce.
type Change struct {
	Peer    string `json:"peer"`
	PeerKey string `json:"peer_key,omitempty"`
	Tool    string `json:"tool,omitempty"`
	Method  string `json:"method,omitempty"`
	Was     string `json:"was"`
	Now     string `json:"now"`
	Reason  string `json:"reason,omitempty"`
	Count   int    `json:"count"`
	Example string `json:"example,omitempty"` // rpc id or timestamp of one instance
}

// SimResult is the diff of a candidate policy against recorded traffic.
type SimResult struct {
	Total       int      `json:"total"`       // decisions simulated
	Matched     int      `json:"matched"`     // identical verdict
	Coverage    float64  `json:"coverage"`    // fraction matched by an explicit rule (not the default)
	Regressions []Change `json:"regressions"` // was allow → now deny (breaks working traffic)
	NowCosign   []Change `json:"now_cosign"`  // was allow → now cosign (adds a human gate)
	Loosened    []Change `json:"loosened"`    // was deny → now allow (widens access)
}

// OK reports whether the candidate policy introduces no regressions.
func (r SimResult) OK() bool { return len(r.Regressions) == 0 }

// Simulate replays a recorded audit corpus through a candidate policy and diffs
// the resulting verdict against what actually happened. It reuses the real
// policy.Engine, so rate limits, time windows, and data-flow labels are
// evaluated exactly as in production. Records are replayed in time order and
// the engine clock is driven from each record's timestamp, so stateful
// constraints (rate buckets refill by elapsed time; labels accumulate per
// identity) reproduce faithfully. This is the CI gate: no firewall change ships
// without seeing what it would have done to last week's traffic.
func Simulate(auditR io.Reader, candidate *policy.Policy) (SimResult, error) {
	var res SimResult

	// Engine clock driven by the record under evaluation.
	clk := time.Unix(0, 0).UTC()
	eng := policy.NewEngine(candidate, func() time.Time { return clk }, nil)

	// Per-identity simulated label state (to reproduce taint/label flow).
	labels := map[string]map[string]bool{}

	regs := map[string]*Change{}
	cos := map[string]*Change{}
	loose := map[string]*Change{}

	sc := bufio.NewScanner(auditR)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var rec policy.AuditRecord
		if json.Unmarshal(line, &rec) != nil {
			continue
		}
		// Only simulate records that represent a policy decision.
		if rec.Decision != "allow" && rec.Decision != "deny" && rec.Decision != "cosign" {
			continue
		}

		// Advance the clock: use the record's time, else tick forward 1s so
		// rate buckets still behave deterministically on time-less corpora.
		if rec.Time != "" {
			if t, err := time.Parse(time.RFC3339, rec.Time); err == nil {
				clk = t.UTC()
			} else {
				clk = clk.Add(time.Second)
			}
		} else {
			clk = clk.Add(time.Second)
		}

		var dec policy.Decision
		if rec.Tool != "" {
			k := idKey(rec.Peer, rec.PeerKey)
			ls := labels[k]
			dec = eng.DecideToolCall(rec.Peer, rec.PeerKey, rec.Tool, ls)
			if dec.Outcome == policy.OutcomeAllow && len(dec.AddLabels) > 0 {
				if ls == nil {
					ls = map[string]bool{}
					labels[k] = ls
				}
				for _, l := range dec.AddLabels {
					ls[l] = true
				}
			}
		} else if rec.Method != "" {
			dec = eng.Policy().DecideMethod(rec.Peer, rec.PeerKey, rec.Method)
		} else {
			continue
		}

		res.Total++
		if dec.RuleID != -1 {
			res.Coverage++ // count now; divided below
		}
		now := dec.Outcome.String()
		if now == rec.Decision {
			res.Matched++
			continue
		}
		ch := Change{Peer: rec.Peer, PeerKey: rec.PeerKey, Tool: rec.Tool, Method: rec.Method,
			Was: rec.Decision, Now: now, Reason: dec.Reason, Example: exampleOf(rec)}
		switch {
		case rec.Decision == "allow" && now == "deny":
			accumulate(regs, ch)
		case rec.Decision == "allow" && now == "cosign":
			accumulate(cos, ch)
		case rec.Decision == "deny" && now == "allow":
			accumulate(loose, ch)
		}
	}
	if err := sc.Err(); err != nil {
		return res, err
	}
	if res.Total > 0 {
		res.Coverage = res.Coverage / float64(res.Total)
	}
	res.Regressions = sortedChanges(regs)
	res.NowCosign = sortedChanges(cos)
	res.Loosened = sortedChanges(loose)
	return res, nil
}

func exampleOf(rec policy.AuditRecord) string {
	if rec.RPCID != "" {
		return "rpc " + rec.RPCID
	}
	return rec.Time
}

func changeKey(c Change) string {
	return c.Peer + "\x00" + c.PeerKey + "\x00" + c.Tool + "\x00" + c.Method + "\x00" + c.Was + "\x00" + c.Now
}

func accumulate(m map[string]*Change, c Change) {
	k := changeKey(c)
	if e := m[k]; e != nil {
		e.Count++
		return
	}
	c.Count = 1
	m[k] = &c
}

func sortedChanges(m map[string]*Change) []Change {
	out := make([]Change, 0, len(m))
	for _, c := range m {
		out = append(out, *c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Count > out[j].Count })
	return out
}
