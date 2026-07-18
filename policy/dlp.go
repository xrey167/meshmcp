package policy

import (
	"fmt"
	"regexp"
)

// DLPSpec declares one content rule for the DLP decision hook: a set of regex
// patterns matched against a tools/call's raw arguments, and what to do on a
// match — deny the call inline, and/or tag the session with a data-flow label
// so downstream block_labels rules act on it.
type DLPSpec struct {
	Patterns []string `yaml:"patterns"`
	Label    string   `yaml:"label"` // data-flow label to emit on a match (optional)
	Deny     bool     `yaml:"deny"`  // deny the call outright on a match (optional)
}

type dlpRule struct {
	res   []*regexp.Regexp
	label string
	deny  bool
}

// PatternDLPHook is a DecisionHook that scans a tools/call's arguments for
// sensitive content (secrets, PII, keys) and tightens the decision: a match can
// deny the call or emit a data-flow label, enforcing data-loss prevention at
// the network layer, below the model, as a swappable plugin (F18). It composes
// with the existing emit_labels/block_labels lattice.
type PatternDLPHook struct{ rules []dlpRule }

// NewPatternDLP compiles the specs into a hook. It errors on a bad regex or a
// spec that neither denies nor labels (which would be a silent no-op).
func NewPatternDLP(specs []DLPSpec) (*PatternDLPHook, error) {
	h := &PatternDLPHook{}
	for i, s := range specs {
		if !s.Deny && s.Label == "" {
			return nil, fmt.Errorf("dlp rule #%d: must set deny:true or a label (else it does nothing)", i+1)
		}
		if len(s.Patterns) == 0 {
			return nil, fmt.Errorf("dlp rule #%d: needs at least one pattern", i+1)
		}
		var res []*regexp.Regexp
		for _, p := range s.Patterns {
			re, err := regexp.Compile(p)
			if err != nil {
				return nil, fmt.Errorf("dlp rule #%d: pattern %q: %w", i+1, p, err)
			}
			res = append(res, re)
		}
		h.rules = append(h.rules, dlpRule{res: res, label: s.Label, deny: s.Deny})
	}
	return h, nil
}

// DecideTool scans the call arguments and tightens the decision on a match.
func (h *PatternDLPHook) DecideTool(info ToolCallInfo, base Decision) Decision {
	if len(info.Arguments) == 0 {
		return base
	}
	for _, r := range h.rules {
		if !matchesAny(r.res, info.Arguments) {
			continue
		}
		if r.deny {
			return Decision{Outcome: OutcomeDeny, Reason: "DLP: sensitive content matched in tool arguments"}
		}
		if r.label != "" {
			base.AddLabels = append(base.AddLabels, r.label)
		}
	}
	return base
}

func matchesAny(res []*regexp.Regexp, b []byte) bool {
	for _, re := range res {
		if re.Match(b) {
			return true
		}
	}
	return false
}
