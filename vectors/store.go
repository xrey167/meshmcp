// Package vectors is the importable core of the mesh RAG vector index: a flat,
// cosine-similarity document store persisted as append-only JSONL. It was
// extracted verbatim from the cmd/vectors binary (mirroring how cmd/kg's store
// became the importable kg package) so that in-process callers — notably the
// governed hybrid retriever in air/rag and the served `air rag` endpoint — can
// own and drive one Index directly instead of forking a subprocess per query.
//
// Every stored Doc carries a provenance ref: the content hash of its text and
// the mesh identity (Peer, a WireGuard public key) that upserted it — the
// substrate for verifiable, taint-contained retrieval. Search is exact (flat
// scan); a larger corpus can swap in an ANN index behind the same Upsert/Search
// API without changing any caller.
//
// The Index's own mutex serializes its mutations, but that is a within-process
// guard only: as with the kg store, the structural fix for concurrent writers
// is to keep exactly one Index owned by one writer, not to rely on this mutex
// across processes.
package vectors

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

// Doc is one stored document: its text, embedding, corpus, and the mesh
// identity that upserted it (provenance for a signed retrieval receipt).
type Doc struct {
	ID     string    `json:"id"`
	Corpus string    `json:"corpus,omitempty"`
	Text   string    `json:"text"`
	Vector []float32 `json:"vector"`
	Peer   string    `json:"peer,omitempty"`
	Hash   string    `json:"hash"` // sha256 of Text — a stable provenance ref
}

// Index is a flat, cosine-similarity vector store persisted as JSONL. Flat
// search is exact and simple; a larger corpus can swap in an ANN index behind
// the same Upsert/Search API without changing the caller.
type Index struct {
	mu    sync.Mutex
	path  string
	emb   embed.Embedder
	docs  map[string]*Doc // by id
	order []string
}

// Open loads (or starts) an Index at path, embedding documents with emb. A
// missing file yields a fresh, empty index; an empty path yields an in-memory
// index that never persists.
func Open(path string, emb embed.Embedder) (*Index, error) {
	ix := &Index{path: path, emb: emb, docs: map[string]*Doc{}}
	if path == "" {
		return ix, nil
	}
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
		var d Doc
		if err := json.Unmarshal(sc.Bytes(), &d); err != nil {
			return nil, err
		}
		ix.put(&d)
	}
	return ix, sc.Err()
}

func (ix *Index) put(d *Doc) {
	if _, ok := ix.docs[d.ID]; !ok {
		ix.order = append(ix.order, d.ID)
	}
	ix.docs[d.ID] = d
}

// Upsert embeds text and stores it under id (in corpus), stamped with peer. An
// existing id is replaced. The document is appended to the JSONL file when the
// index is file-backed.
func (ix *Index) Upsert(id, text, corpus, peer string) (*Doc, error) {
	sum := sha256.Sum256([]byte(text))
	d := &Doc{
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

// Hit is a search result with its cosine similarity score.
type Hit struct {
	Doc   *Doc
	Score float64
}

// Search returns the top-k documents most similar to query, optionally
// restricted to one corpus (empty corpus = search all). k <= 0 defaults to 5.
func (ix *Index) Search(query string, k int, corpus string) []Hit {
	if k <= 0 {
		k = 5
	}
	qv := ix.emb.Embed(query)
	ix.mu.Lock()
	defer ix.mu.Unlock()
	var hits []Hit
	for _, id := range ix.order {
		d := ix.docs[id]
		if corpus != "" && d.Corpus != corpus {
			continue
		}
		hits = append(hits, Hit{Doc: d, Score: embed.Cosine(qv, d.Vector)})
	}
	sort.SliceStable(hits, func(i, j int) bool { return hits[i].Score > hits[j].Score })
	if len(hits) > k {
		hits = hits[:k]
	}
	return hits
}

// Embedder returns the index's embedder (diagnostic / shared tokenization).
func (ix *Index) Embedder() embed.Embedder { return ix.emb }

// All returns a snapshot of every stored document in insertion order. It lets an
// in-process caller (e.g. a hybrid retriever) rebuild a sibling lexical index
// over the same documents without re-reading the file.
func (ix *Index) All() []*Doc {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	out := make([]*Doc, 0, len(ix.order))
	for _, id := range ix.order {
		out = append(out, ix.docs[id])
	}
	return out
}

// Get returns the document stored under id, or nil if absent.
func (ix *Index) Get(id string) *Doc {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	return ix.docs[id]
}

// Count returns the number of documents in the index.
func (ix *Index) Count() int {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	return len(ix.order)
}
