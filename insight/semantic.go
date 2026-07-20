package insight

import (
	"sort"

	"github.com/xrey167/meshmcp/embed"
)

// Semantic policy assistance (S5): the recommend/detect passes key on exact
// tool-name strings, so a renamed-but-equivalent tool reads as brand new and a
// glob like "read_*" misses "fetch_report". Embedding tool names/descriptions
// lets insight reason about meaning: cluster semantically similar tools to
// propose one rule for the group, and score a new tool by how close it is to
// tools already seen (a low-similarity tool is the genuinely novel one).

// DefaultSemanticThreshold is the cosine similarity above which two tools are
// treated as belonging to the same semantic group.
const DefaultSemanticThreshold = 0.35

// SemanticGrouper clusters and scores tools by embedding similarity.
type SemanticGrouper struct {
	emb       embed.Embedder
	threshold float64
}

// NewSemanticGrouper builds a grouper with a local embedder. threshold <= 0
// uses DefaultSemanticThreshold.
func NewSemanticGrouper(threshold float64) *SemanticGrouper {
	if threshold <= 0 {
		threshold = DefaultSemanticThreshold
	}
	return &SemanticGrouper{emb: embed.NewHashing(256), threshold: threshold}
}

// Group clusters tool identifiers (name plus optional description text) into
// semantic groups. Returns groups of tool keys, each group's members sorted.
// Single-tool groups are included so callers see every tool.
func (g *SemanticGrouper) Group(tools map[string]string) [][]string {
	keys := make([]string, 0, len(tools))
	for k := range tools {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	vecs := make(map[string][]float32, len(keys))
	for _, k := range keys {
		vecs[k] = g.emb.Embed(k + " " + tools[k])
	}

	assigned := map[string]bool{}
	var groups [][]string
	for _, k := range keys {
		if assigned[k] {
			continue
		}
		group := []string{k}
		assigned[k] = true
		for _, other := range keys {
			if assigned[other] {
				continue
			}
			if embed.Cosine(vecs[k], vecs[other]) >= g.threshold {
				group = append(group, other)
				assigned[other] = true
			}
		}
		sort.Strings(group)
		groups = append(groups, group)
	}
	return groups
}

// Novelty returns how semantically novel tool is relative to a set of known
// tools: 0 = identical to something seen, 1 = unrelated to everything seen.
// Detect can use this to down-weight a "new-tool" anomaly when the tool is
// merely a synonym of one already allowed.
func (g *SemanticGrouper) Novelty(tool string, known []string) float64 {
	if len(known) == 0 {
		return 1
	}
	tv := g.emb.Embed(tool)
	best := 0.0
	for _, k := range known {
		if s := embed.Cosine(tv, g.emb.Embed(k)); s > best {
			best = s
		}
	}
	n := 1 - best
	if n < 0 {
		n = 0
	}
	return n
}
