package insight

import (
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/xrey167/meshmcp/policy"
)

// RecommendOptions tunes policy synthesis.
type RecommendOptions struct {
	// Generalize collapses tools that share a prefix (read_a, read_b → read_*)
	// and flags the widening in the notes. Off by default: least privilege
	// grants exactly what was observed.
	Generalize bool
	// RateSafety multiplies the observed p99 calls/minute to set a rate cap
	// (default 2.0). A rate rule is only emitted when timestamps were present.
	RateSafety float64
	// MinCallsForWindow is the minimum calls before a time-window is proposed
	// (default 20) — small samples don't justify locking hours.
	MinCallsForWindow int
}

func (o RecommendOptions) withDefaults() RecommendOptions {
	if o.RateSafety <= 0 {
		o.RateSafety = 2.0
	}
	if o.MinCallsForWindow <= 0 {
		o.MinCallsForWindow = 20
	}
	return o
}

var shortDay = []string{"sun", "mon", "tue", "wed", "thu", "fri", "sat"}

// egressHints classify a tool name as likely external egress (heuristic).
var egressHints = []string{"post_", "email_", "http_", "fetch", "upload_", "send_", "webhook", "sms_", "external", "publish_", "slack_"}

func looksEgress(tool string) bool {
	for _, h := range egressHints {
		if strings.HasPrefix(tool, h) || tool == strings.TrimSuffix(h, "_") {
			return true
		}
	}
	return false
}

// Recommend synthesizes a least-privilege policy from an observed corpus: one
// allow rule per identity granting exactly the tools it successfully used, a
// per-identity rate cap from its p99, an optional activity window, and — as
// notes, not silent rules — data-flow guard suggestions. The output is valid
// POLICY-DSL that the firewall consumes directly: "write a policy from scratch"
// becomes "review a generated one". Nothing is auto-enforced; the notes call
// out every widening and every judgment call for human review.
func Recommend(c Corpus, opts RecommendOptions) (*policy.Policy, []string) {
	opts = opts.withDefaults()
	pol := &policy.Policy{DefaultAllow: false}
	var notes []string

	if !c.ChainOK {
		notes = append(notes, "WARNING: the audit chain did not verify — this corpus may be tampered; do not enforce a policy learned from it without checking integrity.")
	}

	keys := make([]string, 0, len(c.Identities))
	for k := range c.Identities {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	labelsSeen := map[string]bool{}
	egressSeen := map[string]bool{}
	riskyFlow := false

	for _, k := range keys {
		ip := c.Identities[k]

		// Grant only tools that were ALLOWED at least once (least privilege:
		// tools that were only ever denied stay denied).
		var granted []string
		var maxP99 int
		emittedAny := len(ip.EmittedLabels) > 0
		for _, tp := range ip.Tools {
			if tp.Allowed == 0 {
				continue
			}
			granted = append(granted, tp.Tool)
			if tp.PerMinP99 > maxP99 {
				maxP99 = tp.PerMinP99
			}
			for _, l := range ip.EmittedLabels {
				labelsSeen[l] = true
			}
			if looksEgress(tp.Tool) {
				egressSeen[tp.Tool] = true
				if emittedAny {
					riskyFlow = true // a label-emitter that also egresses
				}
			}
		}
		if len(granted) == 0 {
			continue
		}
		sort.Strings(granted)

		tools := granted
		if opts.Generalize {
			var gnotes []string
			tools, gnotes = generalize(granted)
			for _, n := range gnotes {
				notes = append(notes, fmt.Sprintf("identity %s: %s", ip.selector(), n))
			}
		}

		rule := policy.Rule{
			Peers: []string{ip.selector()},
			Tools: tools,
			Allow: true,
		}
		if maxP99 > 0 {
			rule.Rate = &policy.RateLimit{Max: int(math.Ceil(float64(maxP99) * opts.RateSafety)), Per: "1m"}
		}
		if w, note := window(ip, opts.MinCallsForWindow); w != nil {
			rule.When = w
			notes = append(notes, fmt.Sprintf("identity %s: %s", ip.selector(), note))
		}
		pol.Rules = append(pol.Rules, rule)
	}

	// Data-flow guard suggestion (advisory — never auto-applied, since it could
	// regress a flow that was historically allowed).
	if len(labelsSeen) > 0 && len(egressSeen) > 0 {
		var labs, egr []string
		for l := range labelsSeen {
			labs = append(labs, l)
		}
		for e := range egressSeen {
			egr = append(egr, e)
		}
		sort.Strings(labs)
		sort.Strings(egr)
		if riskyFlow {
			notes = append(notes, fmt.Sprintf("RISK: a label-emitting identity (%v) also used an egress-looking tool (%v). Review this flow; if unintended, add block_labels:%v to those tools.", labs, egr, labs))
		} else {
			notes = append(notes, fmt.Sprintf("SUGGESTION: labels %v were produced and egress-looking tools %v exist but were never combined. Consider a guard rule: {tools: %v, allow: true, block_labels: %v} to enforce that %v never leaves the mesh.", labs, egr, egr, labs, labs))
		}
	}

	notes = append(notes, "REVIEW before enforcing: this policy grants exactly what was observed; a legitimate but never-before-seen call will be denied. Run it through `insight simulate` and consider a monitor-mode burn-in first.")
	return pol, notes
}

// selector is the policy peer selector for an identity: its cryptographic key
// when known (most precise), else its FQDN.
func (ip *IdentityProfile) selector() string {
	if ip.PeerKey != "" {
		return "pubkey:" + ip.PeerKey
	}
	if ip.Peer != "" {
		return ip.Peer
	}
	return "*"
}

// generalize collapses tools sharing a prefix up to the first '_' into a glob
// when 2+ share it, returning the tool list and notes describing each widening.
func generalize(tools []string) ([]string, []string) {
	groups := map[string][]string{}
	var order []string
	for _, t := range tools {
		p := t
		if i := strings.IndexByte(t, '_'); i >= 0 {
			p = t[:i+1]
		}
		if _, ok := groups[p]; !ok {
			order = append(order, p)
		}
		groups[p] = append(groups[p], t)
	}
	var out, notes []string
	for _, p := range order {
		members := groups[p]
		if len(members) >= 2 && strings.HasSuffix(p, "_") {
			out = append(out, p+"*")
			notes = append(notes, fmt.Sprintf("widened %v → %s* (grants more than observed)", members, p))
		} else {
			out = append(out, members...)
		}
	}
	sort.Strings(out)
	return out, notes
}

// window proposes an activity window from an identity's temporal footprint, or
// nil if activity is not clearly bounded (weekend activity, too few samples, or
// spans the whole day).
func window(ip *IdentityProfile, minCalls int) (*policy.Window, string) {
	if !ip.HasTimes || ip.Calls < minCalls {
		return nil, ""
	}
	if ip.Days[0] > 0 || ip.Days[6] > 0 {
		return nil, "" // weekend activity: don't propose a weekday window
	}
	var days []string
	for d := 1; d <= 5; d++ {
		if ip.Days[d] > 0 {
			days = append(days, shortDay[d])
		}
	}
	minH, maxH := -1, -1
	for h := 0; h < 24; h++ {
		if ip.Hours[h] > 0 {
			if minH < 0 {
				minH = h
			}
			maxH = h
		}
	}
	if minH < 0 || (minH == 0 && maxH == 23) {
		return nil, "" // no bound
	}
	endH := maxH + 1
	if endH > 24 {
		endH = 24
	}
	w := &policy.Window{Days: days, Hours: fmt.Sprintf("%02d:00-%02d:00", minH, endH), TZ: "UTC"}
	return w, fmt.Sprintf("proposed window %v %s UTC from observed activity", days, w.Hours)
}
