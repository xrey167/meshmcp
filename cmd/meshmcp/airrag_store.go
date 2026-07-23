package main

import (
	"bufio"
	"encoding/json"
	"os"
	"sync"

	"github.com/xrey167/meshmcp/air/rag"
	"github.com/xrey167/meshmcp/embed"
	"github.com/xrey167/meshmcp/vectors"
)

// ragStore is the served air-rag backend: one owned vector index (dense arm)
// plus a sibling in-memory BM25 index (keyword arm) over the same chunks, with a
// small-to-big parent map. It ingests documents by chunking them and hybrid-
// searches by fusing dense + keyword ranks with RRF. All governance (identity,
// corpus scoping, audit, untrusted-envelope) lives in the HTTP handler around
// it — this type is the retrieval engine only.
type ragStore struct {
	mu          sync.Mutex
	ix          *vectors.Index
	bm          *rag.BM25
	parents     map[string]string // parentID -> full section text
	parentsPath string            // sidecar JSONL persisting parents across restart
	chunkSize   int
	overlap     int
	peer        string
}

// parentLine is one persisted parent-section record in the sidecar file.
type parentLine struct {
	ID   string `json:"id"`
	Text string `json:"text"`
}

// newRagStore opens (or starts) the vector index at indexPath, loads the parent
// sidecar beside it, and rebuilds the BM25 index over every stored chunk so the
// keyword arm survives a restart with no separate postings file. A nil embedder
// selects the local deterministic Hashing default.
func newRagStore(indexPath, peer string, chunkSize, overlap int, embedder embed.Embedder) (*ragStore, error) {
	if embedder == nil {
		embedder = embed.NewHashing(256)
	}
	ix, err := vectors.Open(indexPath, embedder)
	if err != nil {
		return nil, err
	}
	s := &ragStore{
		ix: ix, bm: rag.NewBM25(), parents: map[string]string{},
		chunkSize: chunkSize, overlap: overlap, peer: peer,
	}
	if indexPath != "" {
		s.parentsPath = indexPath + ".parents.jsonl"
		if err := s.loadParents(); err != nil {
			return nil, err
		}
	}
	for _, d := range ix.All() {
		s.bm.Add(d.ID, embed.Tokenize(d.Text))
	}
	return s, nil
}

func (s *ragStore) loadParents() error {
	f, err := os.Open(s.parentsPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 32<<20)
	for sc.Scan() {
		if len(sc.Bytes()) == 0 {
			continue
		}
		var p parentLine
		if err := json.Unmarshal(sc.Bytes(), &p); err != nil {
			return err
		}
		s.parents[p.ID] = p.Text
	}
	return sc.Err()
}

// persistParent appends one parent section to the sidecar (best-effort durable).
func (s *ragStore) persistParent(id, text string) error {
	if s.parentsPath == "" {
		return nil
	}
	f, err := os.OpenFile(s.parentsPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	b, _ := json.Marshal(parentLine{ID: id, Text: text})
	_, err = f.Write(append(b, '\n'))
	return err
}

// ingested reports what one ingest produced, for the audit provenance receipt.
type ingested struct {
	Chunks int      `json:"chunks"`
	Hashes []string `json:"hashes"` // content hashes of each stored chunk
}

// Ingest chunks docText into corpus, embedding + BM25-indexing every chunk and
// recording its parent section. It returns the count and content hashes of the
// stored chunks — the ingest provenance the caller audits. The peer stamped on
// every chunk is the store's own peer (the identity the backend runs as); the
// governed HTTP handler has already authorized the writing corpus by exact grant.
func (s *ragStore) Ingest(corpus, docID, docText string) (ingested, error) {
	chunks, parents := rag.ChunkDocument(docID, corpus, docText, s.chunkSize, s.overlap)
	s.mu.Lock()
	defer s.mu.Unlock()
	out := ingested{}
	for pid, ptext := range parents {
		if _, ok := s.parents[pid]; !ok {
			s.parents[pid] = ptext
			if err := s.persistParent(pid, ptext); err != nil {
				return out, err
			}
		}
	}
	for _, c := range chunks {
		d, err := s.ix.Upsert(c.ID, c.Text, corpus, s.peer)
		if err != nil {
			return out, err
		}
		s.bm.Add(c.ID, embed.Tokenize(c.Text))
		out.Chunks++
		out.Hashes = append(out.Hashes, d.Hash)
	}
	return out, nil
}

// ragHit is one hybrid search result: the chunk id, its fused rank score, the
// content hash + asserting peer (provenance), the chunk text, and its enclosing
// parent-section text (small-to-big). Text/Parent are raw here; the HTTP handler
// wraps them in the untrusted-content envelope before returning them.
type ragHit struct {
	ID     string  `json:"id"`
	Score  float64 `json:"score"`
	Corpus string  `json:"corpus"`
	Hash   string  `json:"hash"`
	Peer   string  `json:"peer"`
	Text   string  `json:"text"`
	Parent string  `json:"parent,omitempty"`
}

// Search runs the hybrid retrieval: the dense arm (cosine over the vector index,
// corpus-scoped) and the keyword arm (BM25 over the same chunks, then filtered to
// the corpus) are each taken to a wide candidate pool, fused with RRF on rank,
// and truncated to k. Every returned hit is resolved back to its stored chunk so
// the content hash and asserting peer ride along as provenance.
func (s *ragStore) Search(corpus, query string, k int) []ragHit {
	if k <= 0 {
		k = 5
	}
	pool := k * 4
	s.mu.Lock()
	defer s.mu.Unlock()

	// Dense arm: cosine, already corpus-scoped by the index.
	denseHits := s.ix.Search(query, pool, corpus)
	dense := make([]rag.Scored, 0, len(denseHits))
	for _, h := range denseHits {
		dense = append(dense, rag.Scored{ID: h.Doc.ID, Score: h.Score})
	}

	// Keyword arm: BM25 over all chunks, then filter to the corpus (the BM25 index
	// is not itself corpus-partitioned, so scoping is enforced on the results).
	lexAll := s.bm.Search(embed.Tokenize(query), pool*2)
	lex := make([]rag.Scored, 0, len(lexAll))
	for _, sc := range lexAll {
		if d := s.ix.Get(sc.ID); d != nil && (corpus == "" || d.Corpus == corpus) {
			lex = append(lex, sc)
			if len(lex) >= pool {
				break
			}
		}
	}

	fused := rag.TopN(rag.FuseRRF([][]rag.Scored{dense, lex}, rag.DefaultRRFK), k)
	out := make([]ragHit, 0, len(fused))
	for _, f := range fused {
		d := s.ix.Get(f.ID)
		if d == nil {
			continue
		}
		hit := ragHit{
			ID: d.ID, Score: f.Score, Corpus: d.Corpus,
			Hash: d.Hash, Peer: d.Peer, Text: d.Text,
		}
		// Recover the parent-section id from the chunk id ("<parent>#c<ord>").
		if p, ok := s.parents[parentIDOf(d.ID)]; ok {
			hit.Parent = p
		}
		out = append(out, hit)
	}
	return out
}

// parentIDOf strips the trailing "#c<ord>" chunk suffix to recover the parent id.
func parentIDOf(chunkID string) string {
	for i := len(chunkID) - 1; i >= 1; i-- {
		if chunkID[i] == 'c' && chunkID[i-1] == '#' {
			return chunkID[:i-1]
		}
	}
	return chunkID
}

// Count returns the number of indexed chunks.
func (s *ragStore) Count() int { return s.ix.Count() }
