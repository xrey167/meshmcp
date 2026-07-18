package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	"meshmcp/policy"
)

// cmdBudget is the cost/quota read side (F29): it sums the cost/quota units each
// identity has consumed from an audit ledger — FinOps for an agent fleet. The
// cost is charged by cost-weighted rate rules (rate.cost) and recorded per call;
// this rolls it up per peer (and per tool with --by-tool). Enforcement is the
// existing denied-by-budget rate limit; this is the visibility that pairs with it.
func cmdBudget(args []string) error {
	fs := flag.NewFlagSet("budget", flag.ContinueOnError)
	in := fs.String("audit", "", "audit log (JSONL) to total costs from (required)")
	byTool := fs.Bool("by-tool", false, "break the total down by tool instead of by peer")
	asJSON := fs.Bool("json", false, "emit JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *in == "" {
		return fmt.Errorf("usage: meshmcp budget --audit <file> [--by-tool] [--json]")
	}
	data, err := os.ReadFile(*in)
	if err != nil {
		return err
	}

	type acc struct {
		Cost    int `json:"cost"`
		Calls   int `json:"calls"`
		Allowed int `json:"allowed"`
	}
	totals := map[string]*acc{}
	grand := 0
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var r policy.AuditRecord
		if json.Unmarshal([]byte(line), &r) != nil {
			continue
		}
		key := r.Peer
		if *byTool {
			key = r.Tool
		}
		if key == "" {
			continue
		}
		a := totals[key]
		if a == nil {
			a = &acc{}
			totals[key] = a
		}
		a.Calls++
		a.Cost += r.Cost
		grand += r.Cost
		if r.Decision == "allow" {
			a.Allowed++
		}
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(map[string]any{"total_cost": grand, "by": map[string]bool{"tool": *byTool}, "rows": totals})
	}

	keys := make([]string, 0, len(totals))
	for k := range totals {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return totals[keys[i]].Cost > totals[keys[j]].Cost })
	col := "PEER"
	if *byTool {
		col = "TOOL"
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintf(tw, "%s\tCOST\tCALLS\tALLOWED\n", col)
	for _, k := range keys {
		a := totals[k]
		fmt.Fprintf(tw, "%s\t%d\t%d\t%d\n", k, a.Cost, a.Calls, a.Allowed)
	}
	tw.Flush()
	fmt.Printf("\ntotal cost: %d units across %d %ss\n", grand, len(keys), strings.ToLower(col))
	return nil
}
