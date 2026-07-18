// memory is a shared agent-memory fabric MCP server (F9): a mesh-wide,
// identity-scoped long-term memory that agents write to and recall from. Each
// memory is stamped with the writing mesh identity (MESHMCP_PEER_KEY) and
// timestamped, and recall is semantic (via the shared local embedder) — so a
// fleet of agents can hand knowledge to each other, governed by the firewall
// in front (who may write, who may read which labels) and audited.
package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"sync"

	"meshmcp/embed"
	"meshmcp/mcp"
)

// memoryItem is one stored memory.
type memoryItem struct {
	ID     string    `json:"id"`
	Text   string    `json:"text"`
	Tags   []string  `json:"tags,omitempty"`
	Peer   string    `json:"peer,omitempty"` // writing WireGuard identity
	Seq    int       `json:"seq"`
	Vector []float32 `json:"vector"`
}

// memStore is an append-only memory log with semantic recall.
type memStore struct {
	mu    sync.Mutex
	path  string
	emb   embed.Embedder
	items []memoryItem
}

func openMemStore(path string, emb embed.Embedder) (*memStore, error) {
	m := &memStore{path: path, emb: emb}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return m, nil
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
		var it memoryItem
		if err := json.Unmarshal(sc.Bytes(), &it); err != nil {
			return nil, err
		}
		m.items = append(m.items, it)
	}
	return m, sc.Err()
}

func (m *memStore) write(text string, tags []string, peer string) (memoryItem, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var b [8]byte
	_, _ = rand.Read(b[:])
	it := memoryItem{
		ID: "m_" + hex.EncodeToString(b[:]), Text: text, Tags: tags, Peer: peer,
		Seq: len(m.items) + 1, Vector: m.emb.Embed(text + " " + joinTags(tags)),
	}
	if m.path != "" {
		f, err := os.OpenFile(m.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return memoryItem{}, err
		}
		bts, _ := json.Marshal(it)
		if _, err := f.Write(append(bts, '\n')); err != nil {
			f.Close()
			return memoryItem{}, err
		}
		if err := f.Close(); err != nil {
			return memoryItem{}, err
		}
	}
	m.items = append(m.items, it)
	return it, nil
}

type memHit struct {
	Item  memoryItem
	Score float64
}

// search returns the k memories most similar to query, optionally filtered to
// a tag.
func (m *memStore) search(query string, k int, tag string) []memHit {
	if k <= 0 {
		k = 5
	}
	qv := m.emb.Embed(query)
	m.mu.Lock()
	defer m.mu.Unlock()
	var hits []memHit
	for _, it := range m.items {
		if tag != "" && !hasTag(it.Tags, tag) {
			continue
		}
		hits = append(hits, memHit{Item: it, Score: embed.Cosine(qv, it.Vector)})
	}
	sort.SliceStable(hits, func(i, j int) bool { return hits[i].Score > hits[j].Score })
	if len(hits) > k {
		hits = hits[:k]
	}
	return hits
}

// recent returns the n most recently written memories (newest first).
func (m *memStore) recent(n int) []memoryItem {
	if n <= 0 {
		n = 10
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]memoryItem, 0, n)
	for i := len(m.items) - 1; i >= 0 && len(out) < n; i-- {
		out = append(out, m.items[i])
	}
	return out
}

func (m *memStore) count() int { m.mu.Lock(); defer m.mu.Unlock(); return len(m.items) }

func main() {
	path, dim := "memory.jsonl", 256
	for i, a := range os.Args {
		if a == "--store" && i+1 < len(os.Args) {
			path = os.Args[i+1]
		}
	}
	st, err := openMemStore(path, embed.NewHashing(dim))
	if err != nil {
		fmt.Fprintln(os.Stderr, "memory:", err)
		os.Exit(1)
	}
	peer := os.Getenv("MESHMCP_PEER_KEY")
	if peer == "" {
		peer = os.Getenv("MESHMCP_PEER")
	}
	fmt.Fprintf(os.Stderr, "memory: started for peer %q, store %s (%d memories)\n", peer, path, st.count())

	s := mcp.New("meshmcp-memory", "0.1.0")
	registerMemory(s, st, peer)
	if err := s.Serve(context.Background(), os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "memory:", err)
		os.Exit(1)
	}
}

func registerMemory(s *mcp.Server, st *memStore, peer string) {
	s.AddTool(mcp.Tool{
		Name:        "mem_write",
		Description: "Store a memory (a fact, an outcome, a note). Stamped with the writing agent's mesh identity and timestamp.",
		InputSchema: objSchema(map[string]any{
			"text": strProp("the memory to store"),
			"tags": map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "optional tags for scoped recall"},
		}, "text"),
		Handler: func(_ context.Context, args json.RawMessage) (mcp.ToolResult, error) {
			var a struct {
				Text string
				Tags []string
			}
			if err := json.Unmarshal(args, &a); err != nil || a.Text == "" {
				return errResult("text is required"), nil
			}
			it, err := st.write(a.Text, a.Tags, peer)
			if err != nil {
				return errResult("%v", err), nil
			}
			return jsonRes(map[string]any{"id": it.ID, "seq": it.Seq}), nil
		},
	})

	s.AddTool(mcp.Tool{
		Name:        "mem_search",
		Description: "Recall the memories most relevant to a query (semantic search), optionally filtered by tag.",
		InputSchema: objSchema(map[string]any{
			"query": strProp("what to recall"),
			"k":     map[string]any{"type": "number", "description": "how many memories (default 5)"},
			"tag":   strProp("restrict to memories with this tag (optional)"),
		}, "query"),
		Handler: func(_ context.Context, args json.RawMessage) (mcp.ToolResult, error) {
			var a struct {
				Query, Tag string
				K          int
			}
			if err := json.Unmarshal(args, &a); err != nil || a.Query == "" {
				return errResult("query is required"), nil
			}
			hits := st.search(a.Query, a.K, a.Tag)
			out := make([]map[string]any, 0, len(hits))
			for _, h := range hits {
				out = append(out, map[string]any{"id": h.Item.ID, "score": h.Score, "text": h.Item.Text, "tags": h.Item.Tags, "peer": h.Item.Peer})
			}
			return jsonRes(map[string]any{"count": len(out), "memories": out}), nil
		},
	})

	s.AddTool(mcp.Tool{
		Name:        "mem_recent",
		Description: "Return the most recently written memories (newest first).",
		InputSchema: objSchema(map[string]any{"n": map[string]any{"type": "number", "description": "how many (default 10)"}}),
		Handler: func(_ context.Context, args json.RawMessage) (mcp.ToolResult, error) {
			var a struct{ N int }
			_ = json.Unmarshal(args, &a)
			items := st.recent(a.N)
			out := make([]map[string]any, 0, len(items))
			for _, it := range items {
				out = append(out, map[string]any{"id": it.ID, "text": it.Text, "tags": it.Tags, "peer": it.Peer, "seq": it.Seq})
			}
			return jsonRes(map[string]any{"count": len(out), "memories": out}), nil
		},
	})
}

func joinTags(tags []string) string {
	out := ""
	for _, t := range tags {
		out += t + " "
	}
	return out
}

func hasTag(tags []string, want string) bool {
	for _, t := range tags {
		if t == want {
			return true
		}
	}
	return false
}

func jsonRes(v any) mcp.ToolResult {
	b, _ := json.MarshalIndent(v, "", "  ")
	return mcp.ToolResult{Content: []mcp.Content{mcp.Text(string(b))}}
}

func errResult(format string, a ...any) mcp.ToolResult {
	return mcp.ToolResult{Content: []mcp.Content{mcp.Text(fmt.Sprintf(format, a...))}, IsError: true}
}

func objSchema(props map[string]any, required ...string) map[string]any {
	m := map[string]any{"type": "object", "properties": props}
	if len(required) > 0 {
		m["required"] = required
	}
	return m
}

func strProp(desc string) map[string]any {
	return map[string]any{"type": "string", "description": desc}
}
