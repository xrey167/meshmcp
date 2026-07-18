package main

import (
	"hash/fnv"
	"math"
	"strings"
	"unicode"
)

// Embedder turns text into a fixed-dimension vector. It is an interface so an
// external provider (an embeddings API) can be swapped in later; the default
// is a fully local, deterministic embedder that needs no network — ideal for
// offline use and reproducible tests.
type Embedder interface {
	Embed(text string) []float32
	Dim() int
}

// hashingEmbedder is a local bag-of-tokens embedder: it hashes each token into
// a bucket (the hashing trick), weights by term frequency with a sublinear
// dampening, and L2-normalizes so a dot product is cosine similarity. It has
// no training and no dependencies, yet clusters texts that share vocabulary —
// enough to make retrieval work end-to-end without an external model.
type hashingEmbedder struct{ dim int }

func newHashingEmbedder(dim int) hashingEmbedder {
	if dim <= 0 {
		dim = 256
	}
	return hashingEmbedder{dim: dim}
}

func (e hashingEmbedder) Dim() int { return e.dim }

func (e hashingEmbedder) Embed(text string) []float32 {
	counts := make([]float64, e.dim)
	for _, tok := range tokenize(text) {
		h := fnv.New32a()
		_, _ = h.Write([]byte(tok))
		idx := int(h.Sum32()) % e.dim
		if idx < 0 {
			idx += e.dim
		}
		counts[idx]++
	}
	vec := make([]float32, e.dim)
	var norm float64
	for i, c := range counts {
		if c == 0 {
			continue
		}
		w := 1 + math.Log(c) // sublinear TF
		vec[i] = float32(w)
		norm += w * w
	}
	if norm > 0 {
		inv := float32(1 / math.Sqrt(norm))
		for i := range vec {
			vec[i] *= inv
		}
	}
	return vec
}

// tokenize splits text into lowercased alphanumeric tokens.
func tokenize(text string) []string {
	return strings.FieldsFunc(strings.ToLower(text), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	})
}

// cosine returns the dot product of two vectors (already L2-normalized by the
// embedder, so this is cosine similarity).
func cosine(a, b []float32) float64 {
	if len(a) != len(b) {
		return 0
	}
	var dot float64
	for i := range a {
		dot += float64(a[i]) * float64(b[i])
	}
	return dot
}
