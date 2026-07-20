package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"meshmcp/registry"
)

// F19 · Mesh Spotlight — federated semantic search.
//
// One query, fanned out over the mesh to every search backend the caller's
// identity can reach, merged and ranked, each result provenance-tagged with the
// peer that answered. It invents no transport: it reuses F1 discovery (the file
// registry / explicit peers) and F3 RAG (the `search` tool on cmd/vectors), and
// authorization stays where it belongs — each far gateway enforces its own
// policy on the incoming call, so an unauthorized backend simply refuses and is
// omitted from the ranking. There is no central index and nothing is exposed.

// spotlightResult mirrors the vectors `search` tool JSON output (a superset of
// graphrag.go's searchResult: it also keeps corpus + content hash so Spotlight
// can group and provenance-tag results).
type spotlightResult struct {
	Count   int `json:"count"`
	Results []struct {
		ID     string  `json:"id"`
		Score  float64 `json:"score"`
		Text   string  `json:"text"`
		Corpus string  `json:"corpus"`
		Hash   string  `json:"hash"`
	} `json:"results"`
}

// spotlightHit is one merged, ranked, provenance-tagged result. Peer is the
// backend we dialed (who answered) — deliberately NOT the result body's `peer`
// field, which is who upserted the document, not who served it.
type spotlightHit struct {
	Peer   string  `json:"peer"`
	ID     string  `json:"id"`
	Score  float64 `json:"score"`
	Text   string  `json:"text"`
	Corpus string  `json:"corpus,omitempty"`
	Hash   string  `json:"hash,omitempty"`
}

// mergeSpotlight flattens per-peer results into a single ranking (score desc)
// and keeps the global top-k. Kept pure (no I/O) so it is unit-testable. The
// sort is stable so that, among equal scores, peer discovery order is
// preserved for reproducible output.
func mergeSpotlight(perPeer map[string]spotlightResult, k int) []spotlightHit {
	// Deterministic iteration: walk peers in name order before sorting by score.
	names := make([]string, 0, len(perPeer))
	for name := range perPeer {
		names = append(names, name)
	}
	sort.Strings(names)

	var all []spotlightHit
	for _, name := range names {
		for _, d := range perPeer[name].Results {
			all = append(all, spotlightHit{
				Peer:   name,
				ID:     d.ID,
				Score:  d.Score,
				Text:   d.Text,
				Corpus: d.Corpus,
				Hash:   d.Hash,
			})
		}
	}
	sort.SliceStable(all, func(i, j int) bool { return all[i].Score > all[j].Score })
	if k > 0 && len(all) > k {
		all = all[:k]
	}
	return all
}

// fanoutSpotlight queries every peer concurrently for the same search and
// returns each peer's raw result set. A peer that errors, refuses (policy
// deny), or times out contributes an empty result rather than failing the whole
// query — federated search degrades to the peers that answered.
func fanoutSpotlight(ctx context.Context, dial dialFunc, peers map[string]string, tool, query, corpus string, k int) map[string]spotlightResult {
	args := map[string]any{"query": query, "k": k}
	if corpus != "" {
		args["corpus"] = corpus
	}
	type res struct {
		name string
		r    spotlightResult
	}
	ch := make(chan res, len(peers))
	for name, addr := range peers {
		go func(name, addr string) {
			raw := callJSONRaw(ctx, dial, addr, tool, args)
			var r spotlightResult
			_ = json.Unmarshal(raw, &r)
			ch <- res{name, r}
		}(name, addr)
	}
	out := make(map[string]spotlightResult, len(peers))
	for range peers {
		x := <-ch
		out[x.name] = x.r
	}
	return out
}

// cmdSpotlight implements "meshmcp spotlight [flags] <query>".
func cmdSpotlight(args []string) error {
	fs := flag.NewFlagSet("spotlight", flag.ContinueOnError)
	o := meshFlags(fs)
	var peers stringList
	fs.Var(&peers, "peer", "a search backend to query as name=addr (or just addr); repeatable")
	registryDir := fs.String("registry", "", "discover search backends from a file registry directory (router discovery)")
	tool := fs.String("tool", "search", "the semantic-search tool to call on each peer")
	k := fs.Int("k", 5, "results to keep per peer and in the merged ranking")
	corpus := fs.String("corpus", "", "restrict the search to a named corpus")
	timeout := fs.Duration("timeout", 30*time.Second, "overall deadline for the fan-out")
	asJSON := fs.Bool("json", false, "emit machine-readable JSON instead of a table")
	if err := fs.Parse(args); err != nil {
		return err
	}
	query := strings.TrimSpace(strings.Join(fs.Args(), " "))
	if query == "" {
		return fmt.Errorf("spotlight: a query is required (usage: meshmcp spotlight [flags] <query>)")
	}

	// Resolve the set of backends to query: the file registry (name -> mesh
	// addresses) and/or explicit --peer targets. Registry entries with several
	// addresses use the first; --peer overrides a registry name of the same key.
	targets := map[string]string{}
	if *registryDir != "" {
		reg, err := registry.NewFileRegistry(*registryDir)
		if err != nil {
			return fmt.Errorf("open registry %q: %w", *registryDir, err)
		}
		m, err := reg.Lookup()
		if err != nil {
			return fmt.Errorf("registry lookup: %w", err)
		}
		for name, addrs := range m {
			if len(addrs) > 0 {
				targets[name] = addrs[0]
			}
		}
	}
	for _, p := range peers {
		name, addr := p, p
		if k, v, ok := strings.Cut(p, "="); ok {
			name, addr = k, v
		}
		targets[name] = addr
	}
	if len(targets) == 0 {
		return fmt.Errorf("spotlight: no backends to search — pass --peer name=addr or --registry <dir>")
	}

	o.BlockInbound = true // client-side fan-out only; we accept no inbound
	client, err := startMesh(o, os.Stderr)
	if err != nil {
		return err
	}
	defer stopMesh(client)

	dial := func(ctx context.Context, addr string) (net.Conn, error) { return client.Dial(ctx, "tcp", addr) }
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	perPeer := fanoutSpotlight(ctx, dial, targets, *tool, query, *corpus, *k)
	hits := mergeSpotlight(perPeer, *k)

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(map[string]any{
			"query":   query,
			"peers":   len(targets),
			"count":   len(hits),
			"results": hits,
		})
	}

	if len(hits) == 0 {
		fmt.Fprintf(os.Stderr, "no results for %q across %d backend(s)\n", query, len(targets))
		return nil
	}
	fmt.Printf("Spotlight: %q — %d result(s) across %d backend(s)\n\n", query, len(hits), len(targets))
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "SCORE\tPEER\tID\tCORPUS\tTEXT")
	for _, h := range hits {
		fmt.Fprintf(tw, "%.3f\t%s\t%s\t%s\t%s\n", h.Score, h.Peer, h.ID, dashIfEmpty(h.Corpus), truncate(h.Text, 80))
	}
	return tw.Flush()
}

func dashIfEmpty(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
