// Package embed is a small, local, deterministic text embedder shared by the
// RAG vector store (cmd/vectors) and the semantic policy layer (insight). It
// needs no external model or network — the hashing trick maps tokens into a
// fixed-dimension, L2-normalized vector, so a dot product is cosine similarity.
// An external provider can be swapped in behind the Embedder interface later.
package embed

import (
	"hash/fnv"
	"math"
	"strings"
	"unicode"
)

// Embedder turns text into a fixed-dimension vector.
type Embedder interface {
	Embed(text string) []float32
	Dim() int
}

// Hashing is a bag-of-tokens embedder using the hashing trick with sublinear
// term-frequency weighting and L2 normalization.
type Hashing struct{ dim int }

// NewHashing returns a hashing embedder of the given dimension (default 256).
func NewHashing(dim int) Hashing {
	if dim <= 0 {
		dim = 256
	}
	return Hashing{dim: dim}
}

func (e Hashing) Dim() int { return e.dim }

func (e Hashing) Embed(text string) []float32 {
	counts := make([]float64, e.dim)
	for _, tok := range Tokenize(text) {
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

// Tokenize splits text into lowercased alphanumeric tokens.
func Tokenize(text string) []string {
	return strings.FieldsFunc(strings.ToLower(text), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	})
}

// Cosine returns the dot product of two vectors (cosine similarity for
// L2-normalized inputs from this package).
func Cosine(a, b []float32) float64 {
	if len(a) != len(b) {
		return 0
	}
	var dot float64
	for i := range a {
		dot += float64(a[i]) * float64(b[i])
	}
	return dot
}
