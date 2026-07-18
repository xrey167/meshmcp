package policy

// ShadowHook evaluates a CANDIDATE policy against live traffic alongside the
// enforced policy and reports where the two would disagree — a live canary for a
// policy change (F24). It is a DecisionHook, but observe-only: it never changes
// the enforced outcome (it returns base unchanged), it only calls report when
// the candidate's verdict differs. Run it in production before promoting a
// candidate policy, so a regression shows up as a logged divergence rather than
// a denied (or wrongly allowed) call after the switch.
type ShadowHook struct {
	candidate *Engine
	report    func(ev ShadowDivergence)
}

// ShadowDivergence is one call where the candidate policy disagreed with the
// enforced one.
type ShadowDivergence struct {
	Peer    string
	PeerKey string
	Tool    string
	Live    Outcome // what the enforced policy decided (and what actually happened)
	Shadow  Outcome // what the candidate policy would have decided
}

// NewShadowHook builds a shadow hook over a candidate policy. report is called
// for each divergent call (nil is allowed — then the hook is a no-op).
func NewShadowHook(candidate *Policy, report func(ShadowDivergence)) *ShadowHook {
	return &ShadowHook{candidate: NewEngine(candidate, nil, nil), report: report}
}

// DecideTool observes: it computes the candidate verdict and reports a
// divergence, but returns the base decision unchanged so enforcement is
// unaffected.
func (h *ShadowHook) DecideTool(info ToolCallInfo, base Decision) Decision {
	shadow := h.candidate.DecideToolCall(info.Caller.Peer, info.Caller.PeerKey, info.Tool, info.Labels)
	if shadow.Outcome != base.Outcome && h.report != nil {
		h.report(ShadowDivergence{
			Peer: info.Caller.Peer, PeerKey: info.Caller.PeerKey, Tool: info.Tool,
			Live: base.Outcome, Shadow: shadow.Outcome,
		})
	}
	return base
}
