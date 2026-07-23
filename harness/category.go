package harness

import "sort"

// Category is a work-class that selects a model class, fan-out width, whether an
// interview is warranted, and a default reviewer count. Merged from oh-my-openagent's
// routing categories. Category → model-class routing is a POLICY ARTIFACT
// (CategoryTable), not a constant: insight can tune it and a policy override can
// force a class per identity/org (e.g. writing → local model for confidentiality).
type Category string

const (
	CatVisualEngineering Category = "visual-engineering"
	CatUltrabrain        Category = "ultrabrain"
	CatDeep              Category = "deep"
	CatArtistry          Category = "artistry"
	CatWriting           Category = "writing"
	CatQuick             Category = "quick"
	CatUnspecifiedLow    Category = "unspecified-low"
	CatUnspecifiedHigh   Category = "unspecified-high"
)

// FanOut is a qualitative parallelism level a category requests; the scheduler
// clamps it to concrete widths bounded by policy and CPU (see Scheduler).
type FanOut string

const (
	FanNone   FanOut = "none"
	FanLow    FanOut = "low"
	FanMedium FanOut = "medium"
	FanHigh   FanOut = "high"
)

// width maps a qualitative FanOut to a concrete worker count.
func (f FanOut) width() int {
	switch f {
	case FanHigh:
		return 8
	case FanMedium:
		return 4
	case FanLow:
		return 2
	default:
		return 1
	}
}

// Route is a category's default routing decision.
type Route struct {
	Category   Category
	ModelClass string // resolved to a concrete Provider at runtime via the fallback chain
	FanOut     FanOut
	Interview  bool // whether an interview phase is warranted by default
	Reviewers  int  // review_work reviewer count
}

// CategoryTable is the routing table. It is mutable so insight/policy can tune
// it; DefaultCategoryTable seeds it from the source harness defaults.
type CategoryTable map[Category]Route

// DefaultCategoryTable is the seed routing table (§7.2 of the spec).
func DefaultCategoryTable() CategoryTable {
	return CategoryTable{
		CatVisualEngineering: {CatVisualEngineering, "gemini-class", FanMedium, false, 3},
		CatUltrabrain:        {CatUltrabrain, "gpt-high", FanLow, true, 5},
		CatDeep:              {CatDeep, "gpt-medium", FanMedium, true, 5},
		CatArtistry:          {CatArtistry, "opus-class", FanLow, false, 2},
		CatWriting:           {CatWriting, "opus-class", FanLow, false, 2},
		CatQuick:             {CatQuick, "mini-class", FanNone, false, 1},
		CatUnspecifiedLow:    {CatUnspecifiedLow, "mini-class", FanNone, false, 1},
		CatUnspecifiedHigh:   {CatUnspecifiedHigh, "gpt-medium", FanMedium, false, 3},
	}
}

// Route returns the routing decision for cat, falling back to unspecified-high
// for an unknown category so an unmapped category never silently no-ops.
func (t CategoryTable) Route(cat Category) Route {
	if r, ok := t[cat]; ok {
		return r
	}
	if r, ok := t[CatUnspecifiedHigh]; ok {
		r.Category = cat
		return r
	}
	return Route{Category: cat, ModelClass: "mini-class", FanOut: FanNone, Reviewers: 1}
}

// Categories lists the table's categories in a stable order.
func (t CategoryTable) Categories() []Category {
	out := make([]Category, 0, len(t))
	for c := range t {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// KnownCategory reports whether c is one of the canonical categories.
func KnownCategory(c Category) bool {
	switch c {
	case CatVisualEngineering, CatUltrabrain, CatDeep, CatArtistry,
		CatWriting, CatQuick, CatUnspecifiedLow, CatUnspecifiedHigh:
		return true
	}
	return false
}
