package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"

	"github.com/xrey167/meshmcp/air"
	"github.com/xrey167/meshmcp/kg"
)

// cmdAirKG is the umbrella for the governed knowledge-graph verb: assert facts,
// query, read an entity's neighbors, and pull a bounded k-hop subgraph — all over
// the mesh against an air-kg endpoint (air kg serve), every call identity-gated,
// corpus-scoped, and audited by the backend's knowstore facade.
//
//	meshmcp air kg assert    <kg-ip:port> --corpus c --s x --p y --o z [--source u] [--valid-from t]
//	meshmcp air kg query     <kg-ip:port> --corpus c [--s x] [--p y] [--o z] [--as-of n]
//	meshmcp air kg neighbors <kg-ip:port> --corpus c --node e [--as-of n]
//	meshmcp air kg subgraph  <kg-ip:port> --corpus c --seed e [--hops 2] [--max 200] [--as-of n]
//	meshmcp air kg verify    <kg-ip:port>
//	meshmcp air kg serve     --allow <id> [--grant <id>=<corpus>...] [--store f] [--audit f]
func cmdAirKG(args []string) error {
	if len(args) == 0 {
		return kgUsage()
	}
	switch args[0] {
	case "assert", "add":
		return cmdAirKGAssert(args[1:])
	case "query":
		return cmdAirKGQuery(args[1:])
	case "neighbors":
		return cmdAirKGNeighbors(args[1:])
	case "subgraph":
		return cmdAirKGSubgraph(args[1:])
	case "verify":
		return cmdAirKGVerify(args[1:])
	case "serve":
		return cmdAirKGServe(args[1:])
	case "-h", "--help", "help":
		return kgUsage()
	default:
		return fmt.Errorf("meshmcp air kg: unknown subcommand %q (want assert | query | neighbors | subgraph | verify | serve)", args[0])
	}
}

func kgUsage() error {
	b := func(s string) string { return bold(s) }
	fmt.Fprintln(os.Stderr, bold("meshmcp air kg")+dim(" — the mesh's governed, audited knowledge graph"))
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "  "+b("air kg assert")+"    <kg-ip:port> --corpus c --s x --p y --o z [--source u] [--valid-from t] [--json]")
	fmt.Fprintln(os.Stderr, "                   "+dim("write a provenance-stamped fact (needs an exact-literal corpus grant)"))
	fmt.Fprintln(os.Stderr, "  "+b("air kg query")+"     <kg-ip:port> --corpus c [--s x] [--p y] [--o z] [--as-of n] [--json]")
	fmt.Fprintln(os.Stderr, "                   "+dim("pattern read (empty field = wildcard; --as-of time-travels)"))
	fmt.Fprintln(os.Stderr, "  "+b("air kg neighbors")+" <kg-ip:port> --corpus c --node e [--as-of n] [--json]")
	fmt.Fprintln(os.Stderr, "                   "+dim("active triples touching an entity (the k-hop seed)"))
	fmt.Fprintln(os.Stderr, "  "+b("air kg subgraph")+"  <kg-ip:port> --corpus c --seed e [--hops 2] [--max 200] [--as-of n] [--json]")
	fmt.Fprintln(os.Stderr, "                   "+dim("a bounded k-hop neighborhood around a seed entity"))
	fmt.Fprintln(os.Stderr, "  "+b("air kg verify")+"    <kg-ip:port> [--json]")
	fmt.Fprintln(os.Stderr, "                   "+dim("prove the chain is intact — no fact edited, reordered, or truncated"))
	fmt.Fprintln(os.Stderr, "  "+b("air kg serve")+"     --allow <id> [--grant <id>=<corpus>...] [--store f] [--audit f] [--port N]")
	fmt.Fprintln(os.Stderr, "                   "+dim("run the governed KG backend over the mesh (single-writer, deny-by-default)"))
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, dim("Reads and writes are both governed: an empty corpus grant shares nothing, and a"))
	fmt.Fprintln(os.Stderr, dim("write needs the exact-literal corpus named in the caller's grant."))
	return nil
}

// Wire types shared by the air-kg client verbs and the served endpoint
// (airkgserve.go). They are deliberately small: the endpoint returns the spine's
// own know.KnowReceipt for a write and kg.Records for a read, so the client can
// decode into these without duplicating the store's schema.

// kgAssertBody is the JSON a client POSTs to /v1/kg/assert.
type kgAssertBody struct {
	Corpus    string `json:"corpus"`
	S         string `json:"s"`
	P         string `json:"p"`
	O         string `json:"o"`
	Source    string `json:"source,omitempty"`
	ValidFrom string `json:"valid_from,omitempty"`
}

// kgRecordsResp wraps the records a query/neighbors read returns.
type kgRecordsResp struct {
	Records []kg.Record `json:"records"`
}

// kgVerifyResp reports whether the store's hash chain is intact and where its
// head sits.
type kgVerifyResp struct {
	OK    bool   `json:"ok"`
	Head  int    `json:"head"`
	Error string `json:"error,omitempty"`
}

// kgReceiptView decodes the know.KnowReceipt a successful assert returns, without
// importing the whole spine type into the client's display path.
type kgReceiptView struct {
	KnowHash string `json:"know_hash"`
	Triple   struct {
		S, P, O, Peer, Source string
	} `json:"triple"`
}

// cmdAirKGAssert writes one governed fact to a KG endpoint.
func cmdAirKGAssert(args []string) error {
	fs := flag.NewFlagSet("air kg assert", flag.ExitOnError)
	o := meshFlags(fs)
	corpus := fs.String("corpus", "", "corpus/subgraph the write targets (needs an exact-literal grant)")
	subj := fs.String("s", "", "subject")
	pred := fs.String("p", "", "predicate")
	obj := fs.String("o", "", "object")
	source := fs.String("source", "", "optional doc/URI the fact was extracted from")
	validFrom := fs.String("valid-from", "", "optional bi-temporal valid-from (rfc3339)")
	asJSON := fs.Bool("json", false, "print the raw JSON receipt")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: meshmcp air kg assert [flags] <kg-ip:port> --corpus c --s x --p y --o z")
	}
	if *corpus == "" || *subj == "" || *pred == "" || *obj == "" {
		return errors.New("air kg assert: --corpus, --s, --p and --o are required")
	}
	hc, cleanup, err := airControlHTTP(o, fs.Arg(0))
	if err != nil {
		return err
	}
	defer cleanup()

	body, _ := json.Marshal(kgAssertBody{Corpus: *corpus, S: *subj, P: *pred, O: *obj, Source: *source, ValidFrom: *validFrom})
	raw, err := kgDo(hc, http.MethodPost, "/v1/kg/assert", nil, body)
	if err != nil {
		return fmt.Errorf("air kg assert: %w", err)
	}
	if *asJSON {
		fmt.Println(string(bytes.TrimSpace(raw)))
		return nil
	}
	var rcpt kgReceiptView
	if err := json.Unmarshal(raw, &rcpt); err != nil {
		return fmt.Errorf("air kg assert: bad response: %w", err)
	}
	line := okLine("asserted %s %s %s", *subj, *pred, *obj)
	fmt.Println(line + dim(" · "+rcpt.KnowHash))
	return nil
}

// cmdAirKGQuery reads facts matching a pattern (empty field = wildcard).
func cmdAirKGQuery(args []string) error {
	fs := flag.NewFlagSet("air kg query", flag.ExitOnError)
	o := meshFlags(fs)
	corpus := fs.String("corpus", "", "corpus/subgraph to read (needs a covering grant)")
	subj := fs.String("s", "", "subject filter (empty = wildcard)")
	pred := fs.String("p", "", "predicate filter (empty = wildcard)")
	obj := fs.String("o", "", "object filter (empty = wildcard)")
	asOf := fs.Int("as-of", 0, "time-travel: read the graph as of this sequence (0 = now)")
	asJSON := fs.Bool("json", false, "print the raw JSON records")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: meshmcp air kg query [flags] <kg-ip:port> --corpus c")
	}
	if *corpus == "" {
		return errors.New("air kg query: --corpus is required")
	}
	q := url.Values{}
	q.Set("corpus", *corpus)
	setIfNonEmpty(q, "s", *subj)
	setIfNonEmpty(q, "p", *pred)
	setIfNonEmpty(q, "o", *obj)
	if *asOf > 0 {
		q.Set("as_of", strconv.Itoa(*asOf))
	}
	return kgReadRecords(o, fs.Arg(0), "/v1/kg/query", q, *asJSON, "air kg query")
}

// cmdAirKGNeighbors reads the active triples touching one entity.
func cmdAirKGNeighbors(args []string) error {
	fs := flag.NewFlagSet("air kg neighbors", flag.ExitOnError)
	o := meshFlags(fs)
	corpus := fs.String("corpus", "", "corpus/subgraph to read (needs a covering grant)")
	node := fs.String("node", "", "entity whose neighbors to fetch")
	asOf := fs.Int("as-of", 0, "time-travel: read as of this sequence (0 = now)")
	asJSON := fs.Bool("json", false, "print the raw JSON records")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: meshmcp air kg neighbors [flags] <kg-ip:port> --corpus c --node e")
	}
	if *corpus == "" || *node == "" {
		return errors.New("air kg neighbors: --corpus and --node are required")
	}
	q := url.Values{}
	q.Set("corpus", *corpus)
	q.Set("node", *node)
	if *asOf > 0 {
		q.Set("as_of", strconv.Itoa(*asOf))
	}
	return kgReadRecords(o, fs.Arg(0), "/v1/kg/neighbors", q, *asJSON, "air kg neighbors")
}

// cmdAirKGSubgraph pulls a bounded k-hop neighborhood around a seed entity.
func cmdAirKGSubgraph(args []string) error {
	fs := flag.NewFlagSet("air kg subgraph", flag.ExitOnError)
	o := meshFlags(fs)
	corpus := fs.String("corpus", "", "corpus/subgraph to read (needs a covering grant)")
	seed := fs.String("seed", "", "entity to seed the traversal from")
	hops := fs.Int("hops", kgDefaultHops, "traversal depth")
	maxEdges := fs.Int("max", kgDefaultMax, "max edges to return (fan-out cap)")
	asOf := fs.Int("as-of", 0, "time-travel: read as of this sequence (0 = now)")
	asJSON := fs.Bool("json", false, "print the raw JSON subgraph")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: meshmcp air kg subgraph [flags] <kg-ip:port> --corpus c --seed e")
	}
	if *corpus == "" || *seed == "" {
		return errors.New("air kg subgraph: --corpus and --seed are required")
	}
	q := url.Values{}
	q.Set("corpus", *corpus)
	q.Set("seed", *seed)
	q.Set("hops", strconv.Itoa(*hops))
	q.Set("max", strconv.Itoa(*maxEdges))
	if *asOf > 0 {
		q.Set("as_of", strconv.Itoa(*asOf))
	}
	hc, cleanup, err := airControlHTTP(o, fs.Arg(0))
	if err != nil {
		return err
	}
	defer cleanup()

	raw, err := kgDo(hc, http.MethodGet, "/v1/kg/subgraph", q, nil)
	if err != nil {
		return fmt.Errorf("air kg subgraph: %w", err)
	}
	if *asJSON {
		fmt.Println(string(bytes.TrimSpace(raw)))
		return nil
	}
	var sg air.KGSubgraph
	if err := json.Unmarshal(raw, &sg); err != nil {
		return fmt.Errorf("air kg subgraph: bad response: %w", err)
	}
	if len(sg.Triples) == 0 {
		fmt.Fprintln(os.Stderr, dim("no facts within "+strconv.Itoa(sg.Hops)+" hop(s) of "+sg.Seed))
		return nil
	}
	var rows [][]cell
	for _, t := range sg.Triples {
		rows = append(rows, []cell{styled(t.S, bold), styled(t.P, cyan), plain(t.O), styled(t.Peer, dim)})
	}
	renderTable(os.Stdout, []string{"subject", "predicate", "object", "by"}, rows)
	note := fmt.Sprintf("%d edge(s) within %d hop(s) of %s", len(sg.Triples), sg.Hops, sg.Seed)
	if sg.Truncated {
		note += amber(" · truncated at --max")
	}
	fmt.Fprintln(os.Stderr, dim(note))
	return nil
}

// cmdAirKGVerify proves a KG endpoint's chain is intact.
func cmdAirKGVerify(args []string) error {
	fs := flag.NewFlagSet("air kg verify", flag.ExitOnError)
	o := meshFlags(fs)
	asJSON := fs.Bool("json", false, "print the raw JSON result")
	if err := fs.Parse(args); err != nil {
		return err
	}
	control, err := resolveControlPositional(fs.NArg(), fs.Arg(0), "usage: meshmcp air kg verify [flags] <kg-ip:port>")
	if err != nil {
		return err
	}
	hc, cleanup, err := airControlHTTP(o, control)
	if err != nil {
		return err
	}
	defer cleanup()

	raw, err := kgDo(hc, http.MethodGet, "/v1/kg/verify", nil, nil)
	if err != nil {
		return fmt.Errorf("air kg verify: %w", err)
	}
	if *asJSON {
		fmt.Println(string(bytes.TrimSpace(raw)))
		return nil
	}
	var v kgVerifyResp
	if err := json.Unmarshal(raw, &v); err != nil {
		return fmt.Errorf("air kg verify: bad response: %w", err)
	}
	if v.OK {
		fmt.Println(okLine("chain intact") + dim(fmt.Sprintf(" · %d record(s)", v.Head)))
		return nil
	}
	return fmt.Errorf("air kg verify: chain broken: %s", v.Error)
}

// kgReadRecords runs a governed read verb (query/neighbors), rendering the
// returned triples as a table (or raw JSON). Shared by the two read subcommands.
func kgReadRecords(o *meshOptions, addr, path string, q url.Values, asJSON bool, label string) error {
	hc, cleanup, err := airControlHTTP(o, addr)
	if err != nil {
		return err
	}
	defer cleanup()

	raw, err := kgDo(hc, http.MethodGet, path, q, nil)
	if err != nil {
		return fmt.Errorf("%s: %w", label, err)
	}
	if asJSON {
		fmt.Println(string(bytes.TrimSpace(raw)))
		return nil
	}
	var out kgRecordsResp
	if err := json.Unmarshal(raw, &out); err != nil {
		return fmt.Errorf("%s: bad response: %w", label, err)
	}
	if len(out.Records) == 0 {
		fmt.Fprintln(os.Stderr, dim("no matching facts"))
		return nil
	}
	var rows [][]cell
	for _, r := range out.Records {
		rows = append(rows, []cell{styled(r.S, bold), styled(r.P, cyan), plain(r.O), styled(r.Peer, dim)})
	}
	renderTable(os.Stdout, []string{"subject", "predicate", "object", "by"}, rows)
	fmt.Fprintln(os.Stderr, dim(fmt.Sprintf("%d fact(s)", len(out.Records))))
	return nil
}

// kgDo issues one request to the air-kg endpoint over the mesh and returns the
// response body, turning a non-2xx into an error carrying the server's message.
// The URL host is a placeholder — the mesh transport dials the endpoint the
// client was built for (see airControlHTTP), exactly as the other Air verbs do.
func kgDo(hc *http.Client, method, path string, q url.Values, body []byte) ([]byte, error) {
	u := "http://air-kg" + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, u, rdr)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", resp.Status, bytes.TrimSpace(raw))
	}
	return raw, nil
}

// setIfNonEmpty adds a query param only when the value is set, so an empty filter
// stays a wildcard rather than an explicit "match empty".
func setIfNonEmpty(q url.Values, key, val string) {
	if val != "" {
		q.Set(key, val)
	}
}

// decodeJSONBody reads a bounded JSON request body into v, writing a 400 and
// returning false on a malformed or oversized payload.
func decodeJSONBody(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(v); err != nil {
		http.Error(w, "invalid JSON body: "+err.Error(), http.StatusBadRequest)
		return false
	}
	return true
}
