package rag

import (
	"sort"
	"strings"
	"unicode"

	"github.com/xrey167/meshmcp/embed"
)

// Entity linking to KG nodes (Air Knowledge System, Phase 2) — the real
// replacement for the graphrag doc-ID proxy. Candidate surface forms are
// extracted from the query and the retrieved chunk texts, embedded, and
// cosine-matched against the embedded KG node vocabulary. Three invariants,
// all deny-by-default:
//
//   - below-threshold ⇒ NO link — never a low-confidence guess;
//   - a link's Node is ALWAYS one of the supplied kgNodes — linking can
//     resolve to existing knowledge, never fabricate a node (so a poisoned
//     chunk naming a nonexistent entity steers nothing);
//   - deterministic output order (score desc, then node, then surface), so the
//     same inputs always expand the same KG neighborhoods.
//
// Honesty note: with the mesh's local lexical embedder (embed.NewHashing) the
// match is token-overlap cosine — exact and near-exact surface forms link;
// pure synonyms stay below threshold. A semantic embedder slots in behind the
// same embed.Embedder interface without changing this contract.

// DefaultLinkThreshold is the deny-below cosine floor. High on purpose: under
// the lexical embedder only (near-)exact token-set matches clear it, which is
// the fail-closed posture for a primitive that decides which KG neighborhoods
// an agent's context expands into.
const DefaultLinkThreshold = 0.95

// maxSurfaceTokens caps a capitalized-run candidate so a pathological document
// cannot manufacture unbounded candidate spans.
const maxSurfaceTokens = 6

// EntityLink is one resolved surface form: the text span that matched, the KG
// node it resolved to (always from the supplied vocabulary), and the cosine
// score that cleared the threshold.
type EntityLink struct {
	Surface string  `json:"surface"`
	Node    string  `json:"node"`
	Score   float64 `json:"score"`
}

// LinkEntities extracts candidate surface forms (capitalized spans and quoted
// spans) from the query and chunk texts and resolves each against the KG node
// vocabulary by embedding cosine. threshold <= 0 falls back to
// DefaultLinkThreshold (fail-closed, never link-everything); a nil embedder or
// empty vocabulary links nothing. Pure: no I/O, deterministic for the same
// inputs.
func LinkEntities(emb embed.Embedder, query string, chunkTexts []string, kgNodes []string, threshold float64) []EntityLink {
	if emb == nil || len(kgNodes) == 0 {
		return nil
	}
	if threshold <= 0 {
		threshold = DefaultLinkThreshold
	}

	// Embed the vocabulary once.
	nodes := make([]string, 0, len(kgNodes))
	vecs := make([][]float32, 0, len(kgNodes))
	for _, n := range kgNodes {
		if n == "" {
			continue
		}
		nodes = append(nodes, n)
		vecs = append(vecs, emb.Embed(n))
	}
	if len(nodes) == 0 {
		return nil
	}

	var links []EntityLink
	for _, surface := range candidateSurfaces(query, chunkTexts) {
		sv := emb.Embed(surface)
		bestNode, bestScore := "", 0.0
		for i, node := range nodes {
			c := embed.Cosine(sv, vecs[i])
			if c > bestScore || (c == bestScore && bestNode != "" && node < bestNode) {
				bestNode, bestScore = node, c
			}
		}
		if bestNode == "" || bestScore < threshold {
			continue // deny-by-default: no link below the floor
		}
		links = append(links, EntityLink{Surface: surface, Node: bestNode, Score: bestScore})
	}

	sort.SliceStable(links, func(i, j int) bool {
		if links[i].Score != links[j].Score {
			return links[i].Score > links[j].Score
		}
		if links[i].Node != links[j].Node {
			return links[i].Node < links[j].Node
		}
		return links[i].Surface < links[j].Surface
	})
	return links
}

// candidateSurfaces extracts the candidate entity mentions from the query and
// texts: maximal runs of Capitalized tokens (length-capped) plus double-quoted
// spans. Deduplicated case-insensitively, first occurrence wins, so extraction
// order — and therefore linking — is deterministic in input order.
func candidateSurfaces(query string, texts []string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" {
			return
		}
		key := strings.ToLower(s)
		if !seen[key] {
			seen[key] = true
			out = append(out, s)
		}
	}
	for _, src := range append([]string{query}, texts...) {
		for _, s := range capitalizedSpans(src) {
			add(s)
		}
		for _, s := range quotedSpans(src) {
			add(s)
		}
	}
	return out
}

// capitalizedSpans returns maximal runs of consecutive capitalized words
// (punctuation-trimmed), each run capped at maxSurfaceTokens.
func capitalizedSpans(text string) []string {
	var spans []string
	var run []string
	flush := func() {
		if len(run) > 0 {
			spans = append(spans, strings.Join(run, " "))
			run = nil
		}
	}
	for _, w := range strings.Fields(text) {
		w = strings.TrimFunc(w, func(r rune) bool {
			return !unicode.IsLetter(r) && !unicode.IsDigit(r)
		})
		if isCapitalized(w) && len(run) < maxSurfaceTokens {
			run = append(run, w)
			continue
		}
		flush()
	}
	flush()
	return spans
}

func isCapitalized(w string) bool {
	for _, r := range w {
		return unicode.IsUpper(r)
	}
	return false
}

// quotedSpans returns the contents of double-quoted spans, length-bounded so a
// hostile text cannot smuggle a whole document in as one "surface form".
func quotedSpans(text string) []string {
	var out []string
	for {
		open := strings.IndexByte(text, '"')
		if open < 0 {
			break
		}
		rest := text[open+1:]
		close := strings.IndexByte(rest, '"')
		if close < 0 {
			break
		}
		if span := rest[:close]; span != "" && len(span) <= 80 {
			out = append(out, span)
		}
		text = rest[close+1:]
	}
	return out
}
