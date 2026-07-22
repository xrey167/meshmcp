package rag

import (
	"math"
	"sort"
)

// Scored is one ranked candidate: a document/chunk id and its retriever score.
// It is the common currency the dense retriever, the BM25 retriever, and RRF
// fusion all speak, so the three arms compose without any score-scale coupling.
type Scored struct {
	ID    string  `json:"id"`
	Score float64 `json:"score"`
}

// Default Okapi BM25 parameters. k1 controls term-frequency saturation; b
// controls length normalization. These are the widely-used reference values.
const (
	bm25K1 = 1.2
	bm25B  = 0.75
)

// BM25 is an in-memory Okapi BM25 index over tokenized documents. It is the
// keyword/lexical retrieval arm — the half that carries the semantic weight the
// lexical embedder cannot, because it matches exact tokens (identifiers, error
// codes, rare proper nouns) that a bag-of-token-hashes embedding blurs away.
//
// Pure algorithm: no external index, no I/O. Callers tokenize with embed.Tokenize
// (the same tokenizer the dense arm uses) so both arms see aligned terms.
type BM25 struct {
	df       map[string]int   // document frequency per term
	postings map[string][]int // term -> [docIdx, tf, docIdx, tf, ...]
	ids      []string         // docIdx -> id
	lengths  []int            // docIdx -> token count
	totalLen int
}

// NewBM25 returns an empty index.
func NewBM25() *BM25 {
	return &BM25{df: map[string]int{}, postings: map[string][]int{}}
}

// Add indexes a document under id with the given tokens. Empty-token documents
// are indexed with zero length (they simply never match). Re-adding an id
// appends a second posting; callers that upsert should build a fresh index.
func (m *BM25) Add(id string, tokens []string) {
	docIdx := len(m.ids)
	m.ids = append(m.ids, id)
	m.lengths = append(m.lengths, len(tokens))
	m.totalLen += len(tokens)
	tf := map[string]int{}
	for _, t := range tokens {
		tf[t]++
	}
	for term, c := range tf {
		m.df[term]++
		m.postings[term] = append(m.postings[term], docIdx, c)
	}
}

// Len reports the number of indexed documents.
func (m *BM25) Len() int { return len(m.ids) }

// Search returns the top-k documents by BM25 score for the query tokens. An
// empty query, an empty index, or k <= 0 returns nil. Ties break by id for a
// deterministic order.
func (m *BM25) Search(queryTokens []string, k int) []Scored {
	if k <= 0 || len(m.ids) == 0 || len(queryTokens) == 0 {
		return nil
	}
	n := float64(len(m.ids))
	avgdl := float64(m.totalLen) / n
	if avgdl == 0 {
		avgdl = 1
	}
	// Deduplicate query terms so a repeated query word does not double-count its
	// IDF contribution.
	seen := map[string]bool{}
	scores := make([]float64, len(m.ids))
	for _, term := range queryTokens {
		if seen[term] {
			continue
		}
		seen[term] = true
		df := m.df[term]
		if df == 0 {
			continue
		}
		// Okapi IDF with the +1 shift, so a term in every document still weighs
		// non-negatively (monotonically decreasing in df).
		idf := math.Log(1 + (n-float64(df)+0.5)/(float64(df)+0.5))
		post := m.postings[term]
		for i := 0; i < len(post); i += 2 {
			docIdx, freq := post[i], float64(post[i+1])
			dl := float64(m.lengths[docIdx])
			denom := freq + bm25K1*(1-bm25B+bm25B*dl/avgdl)
			scores[docIdx] += idf * (freq * (bm25K1 + 1)) / denom
		}
	}
	var out []Scored
	for i, s := range scores {
		if s > 0 {
			out = append(out, Scored{ID: m.ids[i], Score: s})
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		return out[i].ID < out[j].ID
	})
	if len(out) > k {
		out = out[:k]
	}
	return out
}
