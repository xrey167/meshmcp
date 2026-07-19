package policy

import "encoding/json"

// ToolCallInfo is the immutable view of a governed tools/call handed to a
// DecisionHook: the caller identity, the tool, its raw arguments (token- and
// secret-free — hooks run before capability stripping's downstream secret
// injection), and the session's current data-flow labels.
type ToolCallInfo struct {
	Caller    Caller
	Tool      string
	Arguments json.RawMessage
	Labels    map[string]bool
}

// DecisionHook lets a plugin refine the engine's decision for a tools/call
// after the built-in rule pipeline (and any capability upgrade) has run.
//
// A hook may only TIGHTEN the outcome — deny, or escalate to co-sign — and may
// add data-flow labels; it can NEVER widen a deny or a co-sign into an allow.
// This preserves the core invariant "deny is the safe default": a hook cannot
// talk the firewall into allowing what a rule or the default denied. The
// composed outcome is the most restrictive of the base and every hook.
type DecisionHook interface {
	// DecideTool returns the (possibly tightened) decision. Returning base
	// unchanged is a no-op. AddLabels on the returned decision are unioned into
	// the labels an allowed call contributes to the session.
	DecideTool(info ToolCallInfo, base Decision) Decision
}

// outcomeSeverity ranks outcomes by restrictiveness so hooks can only tighten.
func outcomeSeverity(o Outcome) int {
	switch o {
	case OutcomeDeny:
		return 2
	case OutcomeCosign:
		return 1
	default: // OutcomeAllow
		return 0
	}
}

// applyDecisionHooks folds hooks over a base decision, enforcing tighten-only
// composition: the outcome can move toward deny/cosign but never back toward
// allow, and labels are unioned. It is safe with a nil/empty hook slice.
func applyDecisionHooks(hooks []DecisionHook, info ToolCallInfo, base Decision) Decision {
	dec := base
	for _, h := range hooks {
		if h == nil {
			continue
		}
		out := h.DecideTool(info, dec)
		// Union any labels the hook wants recorded on an allowed call.
		if len(out.AddLabels) > 0 {
			seen := map[string]bool{}
			merged := make([]string, 0, len(dec.AddLabels)+len(out.AddLabels))
			for _, l := range dec.AddLabels {
				if !seen[l] {
					seen[l] = true
					merged = append(merged, l)
				}
			}
			for _, l := range out.AddLabels {
				if !seen[l] {
					seen[l] = true
					merged = append(merged, l)
				}
			}
			dec.AddLabels = merged
		}
		// Tighten-only: adopt the hook's outcome only if it is more restrictive.
		if outcomeSeverity(out.Outcome) > outcomeSeverity(dec.Outcome) {
			dec.Outcome = out.Outcome
			dec.Allow = out.Outcome == OutcomeAllow
			if out.Reason != "" {
				dec.Reason = out.Reason
			}
		}
	}
	return dec
}
