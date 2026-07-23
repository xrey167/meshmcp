package harness

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/xrey167/meshmcp/policy"
)

// Governor is the harness's single authorization + audit choke point. It never
// invents access rules: it holds a policy.Engine compiled from the role registry
// (CompilePolicy) and honors its verdict, and it emits one hash-chained audit
// record per action via policy.AuditLog. Both the MCP server (before running a
// tool) and the scheduler (before spawning a worker) call Guard.
//
// The Engine is the authority for allow/deny/cosign, rate limits, time windows,
// and data-flow label blocks; the Governor adds only auditing and the
// convenience of the GovernedAction envelope.
type Governor struct {
	eng     *policy.Engine
	audit   *policy.AuditLog
	backend string
	now     func() time.Time
}

// NewGovernor compiles pol into an Engine and wires the co-sign store and audit
// log. cosign may be nil (require_cosign rules then deny with a reason rather
// than hang). audit may be nil (auditing becomes a no-op — not recommended in
// production, where audit is a control).
func NewGovernor(pol *policy.Policy, cosign policy.CosignStore, audit *policy.AuditLog, now func() time.Time) *Governor {
	if now == nil {
		now = time.Now
	}
	return &Governor{
		eng:     policy.NewEngine(pol, now, cosign),
		audit:   audit,
		backend: "harness",
		now:     now,
	}
}

// Engine exposes the underlying policy engine (for SetPolicy hot-reload, group
// resolvers, method decisions, and reporting).
func (g *Governor) Engine() *policy.Engine { return g.eng }

// SetPolicy hot-swaps the enforced policy (e.g. after an insight-recommended
// tightening). Rate-limit buckets and co-sign state are preserved.
func (g *Governor) SetPolicy(pol *policy.Policy) { g.eng.SetPolicy(pol) }

// Flush seals any buffered audit records into a final signed checkpoint. Nil-safe.
func (g *Governor) Flush() { g.audit.Flush() }

// Emit records a decision the caller made outside DecideToolCall (e.g. a pending
// co-sign the harness recognizes at the approve gate). It is the exported form of
// the internal emit used across the package.
func (g *Governor) Emit(a GovernedAction, d policy.Decision) { g.emit(a, d) }

// Guard authorizes a for its actor against the current session label set and
// emits exactly one audit record describing the decision. sessionLabels is the
// run's accumulated data-flow label set (nil is fine); a decision may add labels
// (returned in policy.Decision.AddLabels) that the caller folds back into the
// run's set. Guard never blocks: a cosign outcome is returned to the caller,
// which parks the action on meshmcp `approve`.
func (g *Governor) Guard(a GovernedAction, sessionLabels map[string]bool) policy.Decision {
	d := g.eng.DecideToolCall(a.Actor.FQDN, a.Actor.Key, a.Target, sessionLabels)
	g.emit(a, d)
	return d
}

// Allowed is a convenience wrapper: it Guards and reports whether the action may
// proceed (allow), returning a descriptive error for a deny or a pending cosign.
func (g *Governor) Allowed(a GovernedAction, sessionLabels map[string]bool) (policy.Decision, error) {
	d := g.Guard(a, sessionLabels)
	switch d.Outcome {
	case policy.OutcomeAllow:
		return d, nil
	case policy.OutcomeCosign:
		return d, fmt.Errorf("action %q by %s needs co-sign: %s", a.Target, a.Actor.FQDN, d.Reason)
	default:
		return d, fmt.Errorf("action %q by %s denied: %s", a.Target, a.Actor.FQDN, reasonOr(d.Reason, "default-deny"))
	}
}

// emit writes one audit record. The base meshmcp record carries the caller
// identity, kind, target, decision, rule, and cost on the tamper-evident hash
// chain; the harness-specific context (run/job/category/mode/provider, the
// action's labels, and the redacted args digest) is folded into the Reason field
// so it too is covered by the chain without modifying the shared record type.
func (g *Governor) emit(a GovernedAction, d policy.Decision) {
	if g.audit == nil {
		return
	}
	_ = g.audit.Append(policy.AuditRecord{
		Backend:  g.backend,
		Peer:     a.Actor.FQDN,
		PeerKey:  a.Actor.Key,
		Method:   string(a.Kind),
		Tool:     a.Target,
		Decision: d.Outcome.String(),
		Reason:   g.reason(a, d),
		Rule:     d.RuleID,
		Cost:     d.Cost,
	})
}

// reason composes the human-readable + structured audit reason.
func (g *Governor) reason(a GovernedAction, d policy.Decision) string {
	var b strings.Builder
	if d.Reason != "" {
		b.WriteString(d.Reason)
		b.WriteString(" | ")
	}
	pairs := []string{}
	if a.RunID != "" {
		pairs = append(pairs, "run="+a.RunID)
	}
	if a.JobID != "" {
		pairs = append(pairs, "job="+a.JobID)
	}
	if a.Category != "" {
		pairs = append(pairs, "category="+string(a.Category))
	}
	if a.Mode != "" {
		pairs = append(pairs, "mode="+string(a.Mode))
	}
	if a.Provider != "" {
		pairs = append(pairs, "provider="+a.Provider)
	}
	if len(a.Labels) > 0 {
		ls := append([]string(nil), a.Labels...)
		sort.Strings(ls)
		pairs = append(pairs, "labels="+strings.Join(ls, ","))
	}
	if dig := a.argsDigest(); dig != "" {
		pairs = append(pairs, "args="+dig)
	}
	b.WriteString(strings.Join(pairs, " "))
	return strings.TrimSuffix(b.String(), " | ")
}

func reasonOr(s, fallback string) string {
	if strings.TrimSpace(s) == "" {
		return fallback
	}
	return s
}
