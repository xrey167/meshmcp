package rag

import "sort"

// DefaultRRFK is the reciprocal-rank-fusion constant (k). The standard value is
// 60: large enough that top ranks are not dominated by a single list, small
// enough that deep ranks contribute little.
const DefaultRRFK = 60

// FuseRRF combines any number of ranked lists into one, using Reciprocal Rank
// Fusion: a document's fused score is the sum over the lists of 1/(k + rank),
// where rank is its 1-based position in that list. Fusion depends ONLY on rank
// position, never on the lists' raw scores, so a keyword (BM25) list and a dense
// (cosine) list — whose score scales are incomparable — combine without any
// calibration. A document ranked highly in one list and mid in another can beat
// a document that tops only a single list, which is the value of fusion.
//
// Pure and deterministic: ties in the fused score break by id, so the result is
// order-independent in the inputs and stable across runs. k <= 0 uses
// DefaultRRFK. Empty inputs yield nil.
func FuseRRF(runs [][]Scored, k int) []Scored {
	if k <= 0 {
		k = DefaultRRFK
	}
	fused := map[string]float64{}
	for _, run := range runs {
		for rank, s := range run {
			fused[s.ID] += 1.0 / float64(k+rank+1) // rank is 0-based here; +1 => 1-based
		}
	}
	if len(fused) == 0 {
		return nil
	}
	out := make([]Scored, 0, len(fused))
	for id, score := range fused {
		out = append(out, Scored{ID: id, Score: score})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// TopN truncates scored to at most n items (n <= 0 returns nil).
func TopN(scored []Scored, n int) []Scored {
	if n <= 0 {
		return nil
	}
	if len(scored) > n {
		return scored[:n]
	}
	return scored
}
