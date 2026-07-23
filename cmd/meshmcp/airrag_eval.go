package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/xrey167/meshmcp/air/rag"
)

// air rag eval — the deterministic CI gate over the served retrieval backend:
// run every gold case's question as a governed search, score context
// precision/recall (air/rag, pure, no LLM), and exit non-zero when a
// configured threshold is missed. Fail-closed: a denied or failing search is a
// hard error, never silently scored as 0.
//
//	meshmcp air rag eval <backend-ip:port> --corpus c --gold gold.jsonl [--k N]
//	                     [--min-precision F] [--min-recall F] [--json]
//
// gold.jsonl carries one case per line: {"question":"...","gold":["chunk-id",...]}
// where chunk ids are exactly the ids `air rag search` returns.
func cmdAirRagEval(args []string) error {
	fs := flag.NewFlagSet("air rag eval", flag.ExitOnError)
	o := meshFlags(fs)
	corpus := fs.String("corpus", "", "corpus to evaluate against (required)")
	goldPath := fs.String("gold", "", "gold-set JSONL file (required)")
	k := fs.Int("k", 5, "results to retrieve per question")
	minPrecision := fs.Float64("min-precision", 0, "fail (exit non-zero) when mean context precision falls below this (0 = no gate)")
	minRecall := fs.Float64("min-recall", 0, "fail (exit non-zero) when mean context recall falls below this (0 = no gate)")
	asJSON := fs.Bool("json", false, "emit the metrics as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: meshmcp air rag eval [flags] <backend-ip:port> --corpus <c> --gold <gold.jsonl>")
	}
	if *corpus == "" || *goldPath == "" {
		return errors.New("air rag eval: --corpus and --gold are required")
	}
	cases, err := readGoldCases(*goldPath)
	if err != nil {
		return fmt.Errorf("air rag eval: %w", err)
	}

	hc, cleanup, err := airControlHTTP(o, fs.Arg(0))
	if err != nil {
		return err
	}
	defer cleanup()
	search := func(query string, k int) ([]string, error) {
		return ragSearchIDs(hc, *corpus, query, k)
	}
	return runRagEval(cases, search, *k, *minPrecision, *minRecall, *asJSON, os.Stdout)
}

// readGoldCases loads the JSONL gold set (blank lines skipped; a malformed
// line is a hard error so a typo'd gold set never silently shrinks the suite).
func readGoldCases(path string) ([]rag.EvalCase, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var cases []rag.EvalCase
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 8<<20)
	line := 0
	for sc.Scan() {
		line++
		b := bytes.TrimSpace(sc.Bytes())
		if len(b) == 0 {
			continue
		}
		var c rag.EvalCase
		if err := json.Unmarshal(b, &c); err != nil {
			return nil, fmt.Errorf("gold line %d: %w", line, err)
		}
		if c.Question == "" {
			return nil, fmt.Errorf("gold line %d: question is required", line)
		}
		cases = append(cases, c)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return cases, nil
}

// ragSearchIDs runs one governed search and returns the hit ids. Any non-200
// (including a 403 corpus deny) is an error — the eval fails closed rather
// than recording a fake zero score.
func ragSearchIDs(hc *http.Client, corpus, query string, k int) ([]string, error) {
	body, _ := json.Marshal(ragSearchReq{Corpus: corpus, Query: query, K: k})
	resp, err := hc.Post("http://air-rag/v1/rag/search", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", resp.Status, bytes.TrimSpace(raw))
	}
	var out struct {
		Results []ragResult `json:"results"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("bad response: %w", err)
	}
	ids := make([]string, 0, len(out.Results))
	for _, r := range out.Results {
		ids = append(ids, r.ID)
	}
	return ids, nil
}

// runRagEval scores every case through search and gates on the thresholds. It
// is the seam the tests drive with an in-process backend: pure metrics from
// air/rag, fail-closed on any search error, non-nil error when a gate misses.
func runRagEval(cases []rag.EvalCase, search func(query string, k int) ([]string, error), k int, minPrecision, minRecall float64, jsonOut bool, w io.Writer) error {
	if len(cases) == 0 {
		return errors.New("air rag eval: gold set is empty")
	}
	results := make([]rag.EvalResult, 0, len(cases))
	for _, c := range cases {
		retrieved, err := search(c.Question, k)
		if err != nil {
			return fmt.Errorf("air rag eval: search %q: %w", c.Question, err)
		}
		results = append(results, rag.Evaluate(c, retrieved))
	}
	summary := rag.Summarize(results)

	if jsonOut {
		b, err := json.MarshalIndent(map[string]any{"summary": summary, "results": results}, "", "  ")
		if err != nil {
			return err
		}
		fmt.Fprintln(w, string(b))
	} else {
		for _, r := range results {
			fmt.Fprintf(w, "  %-50.50s precision %.3f · recall %.3f\n", r.Case.Question, r.Precision, r.Recall)
		}
		fmt.Fprintf(w, "%d case(s) · mean precision %.3f · mean recall %.3f\n", summary.Cases, summary.MeanPrecision, summary.MeanRecall)
	}

	if minPrecision > 0 && summary.MeanPrecision < minPrecision {
		return fmt.Errorf("air rag eval: mean context precision %.3f below threshold %.3f", summary.MeanPrecision, minPrecision)
	}
	if minRecall > 0 && summary.MeanRecall < minRecall {
		return fmt.Errorf("air rag eval: mean context recall %.3f below threshold %.3f", summary.MeanRecall, minRecall)
	}
	return nil
}
