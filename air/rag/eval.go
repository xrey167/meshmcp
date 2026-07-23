package rag

// Deterministic retrieval eval (Air Knowledge System, Phase 2): the non-LLM
// half of a RAGAS-style harness — context precision/recall against a gold
// chunk set — pure and reproducible, so chunking/fusion changes can be gated
// in CI with zero model dependency. The LLM-judged half (faithfulness, answer
// relevancy) stays deferred behind CapLLM with the rest of Phase 4.

// EvalCase is one gold-labeled retrieval case: a question and the ids of the
// chunks a correct retrieval returns for it.
type EvalCase struct {
	Question string   `json:"question"`
	Gold     []string `json:"gold"`
}

// EvalResult is one case's scored outcome.
type EvalResult struct {
	Case      EvalCase `json:"case"`
	Retrieved []string `json:"retrieved"`
	Precision float64  `json:"precision"`
	Recall    float64  `json:"recall"`
}

// EvalSummary aggregates a run: the case count and the mean precision/recall.
type EvalSummary struct {
	Cases         int     `json:"cases"`
	MeanPrecision float64 `json:"mean_precision"`
	MeanRecall    float64 `json:"mean_recall"`
}

// setOf builds the dedup set of non-empty ids — both metrics are SET metrics:
// duplicates and ordering never change a score (order-invariance is what makes
// the harness deterministic across retrievers).
func setOf(ids []string) map[string]bool {
	out := make(map[string]bool, len(ids))
	for _, id := range ids {
		if id != "" {
			out[id] = true
		}
	}
	return out
}

func intersectionSize(a, b map[string]bool) int {
	n := 0
	for id := range a {
		if b[id] {
			n++
		}
	}
	return n
}

// ContextPrecision is |retrieved ∩ gold| / |retrieved|: how much of what was
// returned is relevant. Edges (defined, never NaN): nothing retrieved scores 0
// when gold expected something, and 1 when gold was empty too (retrieved
// nothing, wanted nothing).
func ContextPrecision(retrieved, gold []string) float64 {
	r, g := setOf(retrieved), setOf(gold)
	if len(r) == 0 {
		if len(g) == 0 {
			return 1
		}
		return 0
	}
	return float64(intersectionSize(r, g)) / float64(len(r))
}

// ContextRecall is |retrieved ∩ gold| / |gold|: how much of the relevant set
// was found. Edge (defined, never NaN): an empty gold set scores 1 — there was
// nothing to recall.
func ContextRecall(retrieved, gold []string) float64 {
	r, g := setOf(retrieved), setOf(gold)
	if len(g) == 0 {
		return 1
	}
	return float64(intersectionSize(r, g)) / float64(len(g))
}

// Evaluate scores one case against what a retriever returned.
func Evaluate(c EvalCase, retrieved []string) EvalResult {
	return EvalResult{
		Case:      c,
		Retrieved: retrieved,
		Precision: ContextPrecision(retrieved, c.Gold),
		Recall:    ContextRecall(retrieved, c.Gold),
	}
}

// Summarize aggregates per-case results into run means. Empty input yields the
// zero summary (0 cases, 0 means) rather than NaN.
func Summarize(results []EvalResult) EvalSummary {
	s := EvalSummary{Cases: len(results)}
	if len(results) == 0 {
		return s
	}
	for _, r := range results {
		s.MeanPrecision += r.Precision
		s.MeanRecall += r.Recall
	}
	s.MeanPrecision /= float64(len(results))
	s.MeanRecall /= float64(len(results))
	return s
}
