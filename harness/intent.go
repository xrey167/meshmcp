package harness

import (
	"context"
	"strings"

	"github.com/xrey167/meshmcp/harness/provider"
)

// Intent is the IntentGate's classification of a request. It is attached to the
// run and is itself an audited decision (so routing is explainable and
// replayable).
type Intent struct {
	Category Category
	Mode     Mode
	Risk     string   // low | medium | high
	Labels   []string // coarse labels the request implies
}

// IntentGate is the first pre-plan hook. It classifies a goal deterministically
// first (keyword, then heuristic) and only falls back to a cheap model pass when
// still ambiguous — so the common cases are free and explainable.
type IntentGate struct {
	reg   *provider.Registry // optional: for the model pass (mini-class)
	table CategoryTable
}

// NewIntentGate builds a gate. reg may be nil (then only keyword + heuristic run).
func NewIntentGate(reg *provider.Registry, table CategoryTable) *IntentGate {
	if table == nil {
		table = DefaultCategoryTable()
	}
	return &IntentGate{reg: reg, table: table}
}

// magicWords maps a keyword to a mode override (omo/OMC "magic words"). It is an
// ordered list, not a map, so a goal that contains several magic words resolves
// deterministically: the FIRST match in this precedence wins (a map range would
// pick a nondeterministic winner and make the classification unreproducible —
// which would in turn desync the audited intent decision across replays).
var magicWords = []struct {
	Word string
	Mode Mode
}{
	{"ultrawork", ModeUltrawork},
	{"ulw", ModeUltrawork},
	{"autopilot", ModeAutopilot},
	{"ralph", ModeRalph},
	{"synthesize", ModeSynthesize},
}

// Classify returns the intent for goal. hintCat and hintMode, when non-empty,
// are the caller's explicit request (which the keyword pass may still override
// via a magic word, but a heuristic never overrides an explicit choice).
func (g *IntentGate) Classify(ctx context.Context, goal string, hintCat Category, hintMode Mode) Intent {
	lc := strings.ToLower(goal)
	in := Intent{Category: hintCat, Mode: hintMode, Risk: "low"}

	// 1. Keyword pass — magic words and effort raisers. First match in the fixed
	// precedence wins, so the result is deterministic regardless of how many
	// magic words the goal contains.
	for _, mw := range magicWords {
		if containsWord(lc, mw.Word) {
			in.Mode = mw.Mode
			break
		}
	}
	if containsWord(lc, "ultrathink") || containsWord(lc, "think") {
		in.Risk = "medium"
	}

	// 2. Heuristic pass — only fills gaps the caller left.
	if in.Category == "" {
		in.Category = g.heuristicCategory(lc)
	}
	if in.Mode == "" {
		in.Mode = g.heuristicMode(lc, in.Category)
	}
	in.Risk = raiseRisk(in.Risk, g.heuristicRisk(lc))

	// 3. Model pass — only when still ambiguous and a classifier is available.
	if in.Category == CatUnspecifiedHigh && g.reg != nil {
		if cat, ok := g.modelClassify(ctx, goal); ok {
			in.Category = cat
		}
	}
	in.Labels = g.labelsFor(in)
	return in
}

func (g *IntentGate) heuristicCategory(lc string) Category {
	switch {
	case hasAny(lc, "typo", "rename", "one line", "small fix", "quick"):
		return CatQuick
	case hasAny(lc, "ui", "css", "layout", "screenshot", "visual", "diagram", "image"):
		return CatVisualEngineering
	case hasAny(lc, "architecture", "design", "refactor the", "hard", "tricky", "complex"):
		return CatUltrabrain
	case hasAny(lc, "write", "docs", "blog", "readme", "prose", "essay"):
		return CatWriting
	case hasAny(lc, "creative", "brainstorm", "ideas"):
		return CatArtistry
	case hasAny(lc, "investigate", "why", "root cause", "debug", "analyze"):
		return CatDeep
	default:
		return CatUnspecifiedHigh
	}
}

func (g *IntentGate) heuristicMode(lc string, cat Category) Mode {
	if cat == CatQuick {
		return ModeQuick
	}
	if hasAny(lc, "plan only", "just plan", "draft a plan") {
		return ModePlanOnly
	}
	if hasAny(lc, "interview", "clarify requirements") {
		return ModeInterviewOnly
	}
	return ModeTeam
}

func (g *IntentGate) heuristicRisk(lc string) string {
	if hasAny(lc, "prod", "production", "delete", "drop table", "migrate", "secret", "credential", "deploy") {
		return "high"
	}
	if hasAny(lc, "database", "auth", "payment", "billing") {
		return "medium"
	}
	return "low"
}

// modelClassify asks a mini-class provider to pick a category. On any failure it
// returns ok=false so the deterministic result stands.
func (g *IntentGate) modelClassify(ctx context.Context, goal string) (Category, bool) {
	p, err := g.reg.Resolve(ctx, "mini-class")
	if err != nil {
		return "", false
	}
	comp, err := p.Invoke(ctx, provider.Prompt{
		System: "Classify the request into exactly one category: visual-engineering, ultrabrain, deep, artistry, writing, quick. Reply with the single category word only.",
		User:   goal,
	})
	if err != nil {
		return "", false
	}
	cat := Category(strings.TrimSpace(strings.ToLower(comp.Text)))
	if KnownCategory(cat) {
		return cat, true
	}
	return "", false
}

func (g *IntentGate) labelsFor(in Intent) []string {
	labels := []string{}
	switch in.Mode {
	case ModeQuick, ModeTeam, ModeAutopilot, ModeRalph, ModeUltrawork:
		labels = append(labels, LabelDelegateSpawn)
	}
	if in.Risk == "high" {
		labels = append(labels, LabelExecShell)
	}
	return labels
}

// --- small helpers ---

func containsWord(lc, w string) bool {
	return hasAny(lc, w)
}

func hasAny(lc string, subs ...string) bool {
	for _, s := range subs {
		if strings.Contains(lc, s) {
			return true
		}
	}
	return false
}

func raiseRisk(a, b string) string {
	rank := map[string]int{"low": 0, "medium": 1, "high": 2}
	if rank[b] > rank[a] {
		return b
	}
	return a
}
