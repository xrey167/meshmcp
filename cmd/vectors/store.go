package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"sort"
	"sync"

	"github.com/xrey167/meshmcp/embed"
)

// doc is one stored document: its text, embedding, corpus, and the mesh
// identity that upserted it (provenance for a signed retrieval receipt).
type doc struct {
	ID     string    `json:"id"`
	Corpus string    `json:"corpus,omitempty"`
	Text   string    `json:"text"`
	Vector []float32 `json:"vector"`
	Peer   string    `json:"peer,omitempty"`
	Hash   string    `json:"hash"` // sha256 of Text — a stable provenance ref
}

// index is a flat, cosine-similarity vector store persisted as JSONL. Flat
// search is exact and simple; a larger corpus can swap in an ANN index behind
// the same Upsert/Search API without changing the server.
type index struct {
	mu    sync.Mutex
	path  string
	emb   embed.Embedder
	docs  map[string]*doc // by id
	order []string
}

func openIndex(path string, emb embed.Embedder) (*index, error) {
	ix := &index{path: path, emb: emb, docs: map[string]*doc{}}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return ix, nil
		}
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 32<<20)
	for sc.Scan() {
		if len(sc.Bytes()) == 0 {
			continue
		}
		var d doc
		if err := json.Unmarshal(sc.Bytes(), &d); err != nil {
			return nil, err
		}
		ix.put(&d)
	}
	return ix, sc.Err()
}

func (ix *index) put(d *doc) {
	if _, ok := ix.docs[d.ID]; !ok {
		ix.order = append(ix.order, d.ID)
	}
	ix.docs[d.ID] = d
}

// Upsert embeds text and stores it under id (in corpus), stamped with peer.
func (ix *index) Upsert(id, text, corpus, peer string) (*doc, error) {
	sum := sha256.Sum256([]byte(text))
	d := &doc{
		ID:     id,
		Corpus: corpus,
		Text:   text,
		Vector: ix.emb.Embed(text),
		Peer:   peer,
		Hash:   hex.EncodeToString(sum[:]),
	}
	ix.mu.Lock()
	defer ix.mu.Unlock()
	ix.put(d)
	if ix.path != "" {
		f, err := os.OpenFile(ix.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return nil, err
		}
		b, _ := json.Marshal(d)
		if _, err := f.Write(append(b, '\n')); err != nil {
			f.Close()
			return nil, err
		}
		if err := f.Close(); err != nil {
			return nil, err
		}
	}
	return d, nil
}

// hit is a search result with its similarity score.
type hit struct {
	Doc   *doc
	Score float64
}

// Search returns the top-k documents most similar to query, optionally
// restricted to one corpus.
func (ix *index) Search(query string, k int, corpus string) []hit {
	if k <= 0 {
		k = 5
	}
	qv := ix.emb.Embed(query)
	ix.mu.Lock()
	defer ix.mu.Unlock()
	var hits []hit
	for _, id := range ix.order {
		d := ix.docs[id]
		if corpus != "" && d.Corpus != corpus {
			continue
		}
		hits = append(hits, hit{Doc: d, Score: embed.Cosine(qv, d.Vector)})
	}
	sort.SliceStable(hits, func(i, j int) bool { return hits[i].Score > hits[j].Score })
	if len(hits) > k {
		hits = hits[:k]
	}
	return hits
}

func (ix *index) count() int {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	return len(ix.order)
}
