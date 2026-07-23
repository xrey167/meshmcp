package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"github.com/xrey167/meshmcp/air/know"
	"github.com/xrey167/meshmcp/policy"
)

// Air · RAG — governed hybrid retrieval as an Air verb.
//
// `air rag` serves a mesh-only knowledge endpoint: it hosts a vector index plus
// a sibling BM25 index, ingests documents by small-to-big chunking, and answers
// hybrid (dense + keyword, RRF-fused) searches. Every request is gated on the
// caller's cryptographic mesh identity, scoped per-corpus by capability claims
// (deny-by-default via air/know.Allowed), row/byte-capped, wrapped in the
// untrusted-content envelope before it could enter any prompt, and audited into
// the shared hash-chained ledger with the know.* verbs. v1 is RETRIEVAL only —
// answer generation and LLM reranking are deferred behind a "requires LLM
// backend" capability (rag.CapLLM) and are not wired to any model.
//
//	meshmcp air rag serve  --port N --index f [--corpus c] [--allow id] [--grant id=c,c] [--audit f]
//	meshmcp air rag ingest <backend-ip:port> --corpus c [PATH ...]
//	meshmcp air rag search <backend-ip:port> --corpus c [--k N] [--json] "query"
func cmdAirRag(args []string) error {
	if len(args) == 0 {
		return ragUsage()
	}
	switch args[0] {
	case "serve":
		return cmdAirRagServe(args[1:])
	case "ingest":
		return cmdAirRagIngest(args[1:])
	case "search":
		return cmdAirRagSearch(args[1:])
	case "-h", "--help", "help":
		return ragUsage()
	default:
		return fmt.Errorf("meshmcp air rag: unknown subcommand %q (want serve | ingest | search)", args[0])
	}
}

func ragUsage() error {
	fmt.Fprintln(os.Stderr, bold("meshmcp air rag")+dim(" — governed hybrid retrieval over the mesh"))
	fmt.Fprintln(os.Stderr, "  "+bold("air rag serve")+"   --port N --index f [--corpus c] [--allow id] [--grant id=c,c] [--audit f]")
	fmt.Fprintln(os.Stderr, "  "+bold("air rag ingest")+"  <backend-ip:port> --corpus c [PATH ...]   "+dim("chunk + index documents (stdin if no PATH)"))
	fmt.Fprintln(os.Stderr, "  "+bold("air rag search")+"  <backend-ip:port> --corpus c [--k N] [--json] \"query\"")
	fmt.Fprintln(os.Stderr, dim("  v1 = governed hybrid RETRIEVAL (dense + BM25 + RRF). Answer generation is deferred (requires an LLM backend)."))
	return nil
}

// --- wire types -----------------------------------------------------------

type ragIngestReq struct {
	Corpus string       `json:"corpus"`
	Docs   []ragWireDoc `json:"docs"`
}

type ragWireDoc struct {
	ID   string `json:"id"`
	Text string `json:"text"`
}

type ragSearchReq struct {
	Corpus string `json:"corpus"`
	Query  string `json:"query"`
	K      int    `json:"k"`
}

// ragResult is one search hit on the wire. Text carries the UNTRUSTED-DATA
// envelope rendering — the chunk is wrapped before it leaves the backend, so a
// client that feeds it to a model gets fenced, labelled data, never instructions.
type ragResult struct {
	ID     string  `json:"id"`
	Score  float64 `json:"score"`
	Corpus string  `json:"corpus"`
	Hash   string  `json:"hash"`
	Peer   string  `json:"peer"`
	Text   string  `json:"text"`
}

// --- served handler -------------------------------------------------------

// ragGrants resolves a caller's corpus capability from its mesh identity. The
// operator configures it (per-identity grants); nothing the client sends can
// widen it. An identity with no configured grant gets empty Corpora, which
// air/know.Allowed treats as deny-by-default (no corpus shared).
type ragGrants func(pubKey, fqdn string) policy.CapabilityClaims

// ragCaps bounds what one search may return, independent of what the caller asks
// for: a hard row cap and a total-byte cap on returned chunk text.
type ragCaps struct {
	MaxRows  int
	MaxBytes int
}

func defaultRagCaps() ragCaps { return ragCaps{MaxRows: 20, MaxBytes: 256 << 10} }

// ragHandler builds the governed HTTP surface over a ragStore. identify resolves
// the caller's (pubKey, fqdn) from the mesh transport; admit gates who may reach
// the endpoint at all (deny-by-default for an unidentifiable peer); grants maps
// an identity to its corpus capability; audit records every retrieval and ingest
// on the shared ledger with the know.* vocabulary.
func ragHandler(store *ragStore, identify func(*http.Request) (pubKey, fqdn string), admit acl, grants ragGrants, caps ragCaps, audit *policy.AuditLog) http.Handler {
	if caps.MaxRows <= 0 {
		caps = defaultRagCaps()
	}
	mux := http.NewServeMux()

	mux.HandleFunc("/v1/rag/search", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		pubKey, fqdn := identify(r)
		if !admit.allows(pubKey, fqdn) {
			ragAudit(audit, know.VerbRetrieve, fqdn, pubKey, "", "deny", "not permitted", nil)
			http.Error(w, "not permitted", http.StatusForbidden)
			return
		}
		var req ragSearchReq
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req) != nil || req.Query == "" || req.Corpus == "" {
			http.Error(w, "corpus and query are required", http.StatusBadRequest)
			return
		}
		claims := grants(pubKey, fqdn)
		// Deny-by-default per-corpus scoping, enforced in the backend against the
		// caller's per-call capability claims (air/know.Allowed, S3).
		if !know.Allowed(claims, know.KnowOp{Corpus: req.Corpus, Write: false}) {
			ragAudit(audit, know.VerbRetrieve, fqdn, pubKey, req.Corpus, "deny", "corpus not granted", nil)
			http.Error(w, "no corpus your identity may query", http.StatusForbidden)
			return
		}
		k := req.K
		if k <= 0 || k > caps.MaxRows {
			k = caps.MaxRows
		}
		hits := store.Search(req.Corpus, req.Query, k)

		results := make([]ragResult, 0, len(hits))
		refs := make([]string, 0, len(hits))
		bytesUsed := 0
		for _, h := range hits {
			// Row/byte caps: stop before exceeding the byte budget.
			wrapped := know.WrapUntrustedFrom(h.Text, h.ID).Render()
			if bytesUsed+len(wrapped) > caps.MaxBytes && len(results) > 0 {
				break
			}
			bytesUsed += len(wrapped)
			results = append(results, ragResult{
				ID: h.ID, Score: roundScore(h.Score), Corpus: h.Corpus,
				Hash: h.Hash, Peer: h.Peer, Text: wrapped,
			})
			refs = append(refs, h.Hash)
		}
		ragAudit(audit, know.VerbRetrieve, fqdn, pubKey, req.Corpus, "allow",
			fmt.Sprintf("hybrid search returned %d chunks", len(results)), refs)
		writeJSONResp(w, http.StatusOK, map[string]any{"count": len(results), "results": results, "you": fqdnOr(fqdn)})
	})

	mux.HandleFunc("/v1/rag/ingest", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		pubKey, fqdn := identify(r)
		if !admit.allows(pubKey, fqdn) {
			ragAudit(audit, know.VerbExtract, fqdn, pubKey, "", "deny", "not permitted", nil)
			http.Error(w, "not permitted", http.StatusForbidden)
			return
		}
		var req ragIngestReq
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<20)).Decode(&req) != nil || req.Corpus == "" || len(req.Docs) == 0 {
			http.Error(w, "corpus and at least one doc are required", http.StatusBadRequest)
			return
		}
		claims := grants(pubKey, fqdn)
		// A WRITE is authorized strictly more narrowly than a read: only an exact,
		// literal corpus grant may ingest (air/know.Allowed Write semantics).
		if !know.Allowed(claims, know.KnowOp{Corpus: req.Corpus, Write: true}) {
			ragAudit(audit, know.VerbExtract, fqdn, pubKey, req.Corpus, "deny", "corpus write not granted", nil)
			http.Error(w, "your identity may not ingest into this corpus", http.StatusForbidden)
			return
		}
		totalChunks := 0
		var allHashes []string
		for _, d := range req.Docs {
			if d.ID == "" || d.Text == "" {
				continue
			}
			ing, err := store.Ingest(req.Corpus, d.ID, d.Text)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			totalChunks += ing.Chunks
			allHashes = append(allHashes, ing.Hashes...)
		}
		ragAudit(audit, know.VerbExtract, fqdn, pubKey, req.Corpus, "allow",
			fmt.Sprintf("ingested %d docs into %d chunks", len(req.Docs), totalChunks), allHashes)
		writeJSONResp(w, http.StatusOK, map[string]any{"corpus": req.Corpus, "docs": len(req.Docs), "chunks": totalChunks, "hashes": allHashes})
	})

	return mux
}

// ragAudit appends one knowledge-op record to the shared ledger using the know.*
// vocabulary, so RAG retrieval/ingest lands on the same verifiable chain as KG
// and agent-graph activity. A nil ledger is a no-op.
func ragAudit(audit *policy.AuditLog, verb know.Verb, fqdn, pubKey, corpus, decision, reason string, provenance []string) {
	if audit == nil {
		return
	}
	ev := know.Event{
		Peer: fqdnOr(fqdn), PeerKey: pubKey, Corpus: corpus,
		Decision: decision, Reason: reason, Provenance: provenance,
	}
	var rec policy.AuditRecord
	switch verb {
	case know.VerbExtract:
		rec = know.Extract(ev)
	default:
		rec = know.Retrieve(ev)
	}
	_ = audit.Append(rec)
}

// --- serve ----------------------------------------------------------------

func cmdAirRagServe(args []string) error {
	fs := flag.NewFlagSet("air rag serve", flag.ExitOnError)
	o := meshFlags(fs)
	port := fs.Int("port", 9140, "mesh port to serve the RAG endpoint on")
	index := fs.String("index", "rag-vectors.jsonl", "path to the vector index (JSONL)")
	chunk := fs.Int("chunk", 200, "chunk size in tokens")
	overlap := fs.Int("overlap", 24, "chunk overlap in tokens")
	allow := multiFlag{}
	fs.Var(&allow, "allow", "identity permitted to reach the endpoint (FQDN glob or pubkey:<key>); repeatable; REQUIRED")
	grantFlags := multiFlag{}
	fs.Var(&grantFlags, "grant", "corpus grant id=corpus[,corpus] (id is an FQDN glob or pubkey:<key>); repeatable")
	auditPath := fs.String("audit", "", "append every retrieval/ingest to this hash-chained JSONL ledger")
	if err := fs.Parse(args); err != nil {
		return err
	}
	// Serving governed knowledge is privileged: refuse to run open, deny-by-default
	// (mirrors air listen / air serve --control requiring --allow).
	if len(allow) == 0 {
		return errors.New("air rag serve: --allow <id> is required (who may reach the endpoint); deny-by-default")
	}
	grants, err := parseRagGrants(grantFlags)
	if err != nil {
		return fmt.Errorf("air rag serve: %w", err)
	}

	o.BlockInbound = false
	client, err := startMesh(o, os.Stderr)
	if err != nil {
		return err
	}
	defer stopMesh(client)

	peer := ""
	if st, err := client.Status(); err == nil {
		peer = st.LocalPeerState.FQDN
	}
	store, err := newRagStore(*index, peer, *chunk, *overlap)
	if err != nil {
		return fmt.Errorf("air rag serve: open store: %w", err)
	}

	var audit *policy.AuditLog
	if *auditPath != "" {
		f, err := os.OpenFile(*auditPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return fmt.Errorf("air rag serve: open audit log: %w", err)
		}
		defer f.Close()
		audit = policy.NewAuditLog(f, func() string { return time.Now().UTC().Format(time.RFC3339) })
	}

	identify := func(r *http.Request) (string, string) { return peerIdentityStr(client, r.RemoteAddr) }
	h := ragHandler(store, identify, newACL(allow), grants, defaultRagCaps(), audit)

	ln, err := client.ListenTCP(fmt.Sprintf(":%d", *port))
	if err != nil {
		return fmt.Errorf("air rag serve: listen on mesh port %d: %w", *port, err)
	}
	defer ln.Close()

	ctx, stop := signal.NotifyContext(context.Background(), shutdownSignals...)
	defer stop()
	go func() { <-ctx.Done(); ln.Close() }()

	fmt.Fprintf(os.Stderr, dim("air rag serving on mesh port ")+bold(fmt.Sprint(*port))+
		dim(" · %d chunks · POST /v1/rag/search · POST /v1/rag/ingest · Ctrl-C to stop\n"), store.Count())
	if err := newLocalHTTPServer("", h).Serve(ln); err != nil && ctx.Err() == nil {
		return err
	}
	return nil
}

// parseRagGrants turns --grant id=c,c flags into a ragGrants resolver. Each grant
// maps an identity pattern (FQDN glob or pubkey:<key>) to a corpus list; a caller
// matching a pattern is issued CapabilityClaims carrying that corpus grant. No
// match => empty Corpora => deny-by-default in air/know.Allowed.
func parseRagGrants(flags []string) (ragGrants, error) {
	type grant struct {
		pattern acl
		corpora []string
	}
	var grants []grant
	for _, g := range flags {
		id, list, ok := strings.Cut(g, "=")
		if !ok || id == "" {
			return nil, fmt.Errorf("bad --grant %q (want id=corpus[,corpus])", g)
		}
		var corpora []string
		for _, c := range strings.Split(list, ",") {
			if c = strings.TrimSpace(c); c != "" {
				corpora = append(corpora, c)
			}
		}
		grants = append(grants, grant{pattern: newACL([]string{id}), corpora: corpora})
	}
	return func(pubKey, fqdn string) policy.CapabilityClaims {
		var corpora []string
		for _, g := range grants {
			if g.pattern.allows(pubKey, fqdn) {
				corpora = append(corpora, g.corpora...)
			}
		}
		return policy.CapabilityClaims{Subject: pubKey, Corpora: corpora}
	}, nil
}

// --- client: ingest -------------------------------------------------------

func cmdAirRagIngest(args []string) error {
	fs := flag.NewFlagSet("air rag ingest", flag.ExitOnError)
	o := meshFlags(fs)
	corpus := fs.String("corpus", "", "corpus to ingest into (required)")
	asJSON := fs.Bool("json", false, "print the raw JSON ingest report")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 1 {
		return errors.New("usage: meshmcp air rag ingest [flags] <backend-ip:port> --corpus <c> [PATH ...]")
	}
	if *corpus == "" {
		return errors.New("air rag ingest: --corpus is required")
	}
	addr := fs.Arg(0)
	paths := fs.Args()[1:]

	docs, err := readIngestDocs(paths)
	if err != nil {
		return fmt.Errorf("air rag ingest: %w", err)
	}
	if len(docs) == 0 {
		return errors.New("air rag ingest: nothing to ingest (no files and empty stdin)")
	}

	hc, cleanup, err := airControlHTTP(o, addr)
	if err != nil {
		return err
	}
	defer cleanup()

	reqBody, _ := json.Marshal(ragIngestReq{Corpus: *corpus, Docs: docs})
	resp, err := hc.Post("http://air-rag/v1/rag/ingest", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		return fmt.Errorf("air rag ingest: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("air rag ingest: %s: %s", resp.Status, bytes.TrimSpace(body))
	}
	if *asJSON {
		fmt.Println(string(bytes.TrimSpace(body)))
		return nil
	}
	var out struct {
		Corpus string `json:"corpus"`
		Docs   int    `json:"docs"`
		Chunks int    `json:"chunks"`
	}
	_ = json.Unmarshal(body, &out)
	fmt.Println(okLine("ingested %d doc(s) into %d chunk(s)", out.Docs, out.Chunks) + dim(" · corpus "+out.Corpus))
	return nil
}

// readIngestDocs reads the given files (or stdin when none) into wire docs. Each
// file becomes one document keyed by its base name; stdin becomes "stdin".
func readIngestDocs(paths []string) ([]ragWireDoc, error) {
	var docs []ragWireDoc
	if len(paths) == 0 {
		b, err := io.ReadAll(io.LimitReader(os.Stdin, 32<<20))
		if err != nil {
			return nil, err
		}
		if len(bytes.TrimSpace(b)) == 0 {
			return nil, nil
		}
		return []ragWireDoc{{ID: "stdin", Text: string(b)}}, nil
	}
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		docs = append(docs, ragWireDoc{ID: filepath.Base(p), Text: string(b)})
	}
	return docs, nil
}

// --- client: search -------------------------------------------------------

func cmdAirRagSearch(args []string) error {
	fs := flag.NewFlagSet("air rag search", flag.ExitOnError)
	o := meshFlags(fs)
	corpus := fs.String("corpus", "", "corpus to search (required)")
	k := fs.Int("k", 5, "number of results to return")
	asJSON := fs.Bool("json", false, "print the raw JSON response")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 2 {
		return errors.New("usage: meshmcp air rag search [flags] <backend-ip:port> --corpus <c> \"query\"")
	}
	if *corpus == "" {
		return errors.New("air rag search: --corpus is required")
	}
	addr := fs.Arg(0)
	query := strings.Join(fs.Args()[1:], " ")

	hc, cleanup, err := airControlHTTP(o, addr)
	if err != nil {
		return err
	}
	defer cleanup()

	reqBody, _ := json.Marshal(ragSearchReq{Corpus: *corpus, Query: query, K: *k})
	resp, err := hc.Post("http://air-rag/v1/rag/search", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		return fmt.Errorf("air rag search: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("air rag search: %s: %s", resp.Status, bytes.TrimSpace(body))
	}
	if *asJSON {
		fmt.Println(string(bytes.TrimSpace(body)))
		return nil
	}
	var out struct {
		Count   int         `json:"count"`
		Results []ragResult `json:"results"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return fmt.Errorf("air rag search: bad response: %w", err)
	}
	if out.Count == 0 {
		fmt.Fprintln(os.Stderr, dim("no results"))
		return nil
	}
	var rows [][]cell
	for _, r := range out.Results {
		rows = append(rows, []cell{
			styled(r.ID, cyan),
			plain(fmt.Sprintf("%.4f", r.Score)),
			styled(shortKey(r.Hash), dim),
			plain(firstLine(r.Text)),
		})
	}
	renderTable(os.Stdout, []string{"chunk", "score", "hash", "text (untrusted)"}, rows)
	fmt.Fprintln(os.Stderr, dim(fmt.Sprintf("%d result(s) · chunks wrapped untrusted before use", out.Count)))
	return nil
}

// roundScore rounds a fused RRF score to 6 decimals for a stable wire value.
func roundScore(f float64) float64 { return float64(int64(f*1e6+0.5)) / 1e6 }

// firstLine returns the first non-empty content line of a rendered untrusted
// envelope, for a compact table cell (the full fenced block rides in --json).
func firstLine(s string) string {
	for _, ln := range strings.Split(s, "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "-----") || strings.HasPrefix(ln, "The block between") || strings.HasPrefix(ln, "Source (untrusted)") {
			continue
		}
		if len(ln) > 80 {
			return ln[:80] + "…"
		}
		return ln
	}
	return ""
}
