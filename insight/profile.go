// Package insight is the read side of the meshmcp firewall: it turns the audit
// stream back into policy. Where policy/ enforces rules, insight/ observes what
// agents actually do, recommends a least-privilege policy from that behavior,
// simulates a candidate policy against recorded traffic, and detects deviation
// from a learned baseline. It is the function AUDIT-RECORD* -> POLICY-DSL — the
// missing morphism between the two formats meshmcp standardizes.
package insight

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/xrey167/meshmcp/policy"
)

// ToolProfile is one identity's observed usage of one tool.
type ToolProfile struct {
	Tool      string   `json:"tool"`
	Calls     int      `json:"calls"`
	Allowed   int      `json:"allowed"`
	Denied    int      `json:"denied"`
	Cosign    int      `json:"cosign"`
	PerMinP50 int      `json:"per_min_p50"`      // median calls in an active minute
	PerMinP99 int      `json:"per_min_p99"`      // 99th-percentile calls in an active minute
	Labels    []string `json:"labels,omitempty"` // labels this tool emits (from the policy in effect)

	perMinute map[int64]int // active-minute -> count (internal, for percentiles)
}

// IdentityProfile is the observed behavioral fingerprint of one caller.
type IdentityProfile struct {
	Peer          string         `json:"peer"`
	PeerKey       string         `json:"peer_key,omitempty"`
	Calls         int            `json:"calls"`
	Allowed       int            `json:"allowed"`
	Denied        int            `json:"denied"`
	Cosign        int            `json:"cosign"`
	Tools         []*ToolProfile `json:"tools"`
	Methods       map[string]int `json:"methods,omitempty"`
	Hours         [24]int        `json:"hours"` // activity histogram by UTC hour
	Days          [7]int         `json:"days"`  // 0=Sun..6=Sat
	FirstSeen     string         `json:"first_seen,omitempty"`
	LastSeen      string         `json:"last_seen,omitempty"`
	EmittedLabels []string       `json:"emitted_labels,omitempty"` // labels this identity ever produced
	DeniedByLabel int            `json:"denied_by_label,omitempty"`
	HasTimes      bool           `json:"has_times"`

	toolIdx map[string]*ToolProfile
	labels  map[string]bool
}

// Corpus is the analyzed set of identity profiles plus provenance.
type Corpus struct {
	Records    int                         `json:"records"`
	ChainOK    bool                        `json:"chain_ok"` // did the audit hash chain verify?
	Identities map[string]*IdentityProfile `json:"identities"`
}

// Profile reads an audit log and builds a per-identity behavioral profile. If
// pol is non-nil, the rule index on each record is used to attribute emitted
// data-flow labels (which the record does not store directly). The audit hash
// chain is verified first — you must not learn a baseline from a tampered log —
// and the verdict is reported in Corpus.ChainOK.
func Profile(auditR io.Reader, pol *policy.Policy) (Corpus, error) {
	data, err := io.ReadAll(auditR)
	if err != nil {
		return Corpus{}, err
	}
	c := Corpus{Identities: map[string]*IdentityProfile{}}
	if res, _ := policy.VerifyChain(bytes.NewReader(data)); res.OK {
		c.ChainOK = true
	}

	sc := bufio.NewScanner(bytes.NewReader(data))
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
		c.Records++
		c.observe(rec, pol)
	}
	if err := sc.Err(); err != nil {
		return c, err
	}
	c.finalize()
	return c, nil
}

func idKey(peer, peerKey string) string { return peer + "\x00" + peerKey }

func (c *Corpus) observe(rec policy.AuditRecord, pol *policy.Policy) {
	k := idKey(rec.Peer, rec.PeerKey)
	ip := c.Identities[k]
	if ip == nil {
		ip = &IdentityProfile{Peer: rec.Peer, PeerKey: rec.PeerKey,
			Methods: map[string]int{}, toolIdx: map[string]*ToolProfile{}, labels: map[string]bool{}}
		c.Identities[k] = ip
	}
	ip.Calls++
	ip.Methods[rec.Method]++
	switch rec.Decision {
	case "allow":
		ip.Allowed++
	case "deny":
		ip.Denied++
	case "cosign":
		ip.Cosign++
	}

	var minute int64 = -1
	if rec.Time != "" {
		if t, err := time.Parse(time.RFC3339, rec.Time); err == nil {
			ip.HasTimes = true
			ut := t.UTC()
			ip.Hours[ut.Hour()]++
			ip.Days[int(ut.Weekday())]++
			minute = ut.Truncate(time.Minute).Unix()
			if ip.FirstSeen == "" || rec.Time < ip.FirstSeen {
				ip.FirstSeen = rec.Time
			}
			if rec.Time > ip.LastSeen {
				ip.LastSeen = rec.Time
			}
		}
	}

	if rec.Tool == "" {
		return
	}
	tp := ip.toolIdx[rec.Tool]
	if tp == nil {
		tp = &ToolProfile{Tool: rec.Tool, perMinute: map[int64]int{}}
		ip.toolIdx[rec.Tool] = tp
	}
	tp.Calls++
	switch rec.Decision {
	case "allow":
		tp.Allowed++
	case "deny":
		tp.Denied++
	case "cosign":
		tp.Cosign++
	}
	if minute >= 0 {
		tp.perMinute[minute]++
	}

	// Attribute emitted labels via the rule that fired, if we have the policy.
	if pol != nil && rec.Rule >= 0 && rec.Rule < len(pol.Rules) {
		r := pol.Rules[rec.Rule]
		if rec.Decision == "allow" {
			for _, l := range r.EmitLabels {
				ip.labels[l] = true
				addLabel(tp, l)
			}
			if r.TaintSource {
				ip.labels["tainted"] = true
				addLabel(tp, "tainted")
			}
		}
	}
	// A deny explained by a label block is a data-flow signal.
	if rec.Decision == "deny" && (strings.Contains(rec.Reason, "label") || strings.Contains(rec.Reason, "tainted")) {
		ip.DeniedByLabel++
	}
}

func (c *Corpus) finalize() {
	for _, ip := range c.Identities {
		for _, tp := range ip.toolIdx {
			counts := make([]int, 0, len(tp.perMinute))
			for _, n := range tp.perMinute {
				counts = append(counts, n)
			}
			tp.PerMinP50 = percentile(counts, 0.50)
			tp.PerMinP99 = percentile(counts, 0.99)
			ip.Tools = append(ip.Tools, tp)
		}
		sort.Slice(ip.Tools, func(i, j int) bool { return ip.Tools[i].Calls > ip.Tools[j].Calls })
		for l := range ip.labels {
			ip.EmittedLabels = append(ip.EmittedLabels, l)
		}
		sort.Strings(ip.EmittedLabels)
	}
}

// percentile returns the p-quantile (0..1) of counts using nearest-rank. An
// empty set yields 0. Used for the per-active-minute call-rate distribution.
func percentile(counts []int, p float64) int {
	if len(counts) == 0 {
		return 0
	}
	sort.Ints(counts)
	rank := int(p*float64(len(counts)-1) + 0.5)
	if rank < 0 {
		rank = 0
	}
	if rank >= len(counts) {
		rank = len(counts) - 1
	}
	return counts[rank]
}

func addLabel(tp *ToolProfile, l string) {
	for _, e := range tp.Labels {
		if e == l {
			return
		}
	}
	tp.Labels = append(tp.Labels, l)
}
