package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"text/tabwriter"

	"meshmcp/policy"
)

// cmdStatus is the observability plane's read side (F15): it rolls up an audit
// ledger into per-peer, per-tool, and per-backend activity plus the tamper-chain
// verdict, and prints it as a table or JSON. It reuses policy.Analyze — the same
// aggregation the dashboard reads — so "who called what, from where, how often"
// is one command, no mesh join required.
func cmdStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	auditPath := fs.String("audit", "", "audit log (JSONL) to summarize (required)")
	asJSON := fs.Bool("json", false, "emit the full summary as JSON")
	recent := fs.Int("recent", 0, "include N most-recent events (0 = none)")
	top := fs.Int("top", 10, "show the top-N peers and tools")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *auditPath == "" {
		return fmt.Errorf("meshmcp status: --audit <file> is required")
	}
	f, err := os.Open(*auditPath)
	if err != nil {
		return fmt.Errorf("open audit log: %w", err)
	}
	defer f.Close()

	sum, err := policy.Analyze(f, *recent)
	if err != nil {
		return err
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(sum)
	}

	chain := "no records"
	if sum.Records > 0 {
		if sum.Chain.OK {
			chain = fmt.Sprintf("intact (%d records)", sum.Chain.Count)
		} else {
			chain = fmt.Sprintf("TAMPERED at seq %d", sum.Chain.BreakSeq)
		}
	}
	fmt.Printf("audit: %s\n", *auditPath)
	fmt.Printf("chain: %s\n", chain)
	fmt.Printf("calls: %d total — %d allow · %d deny · %d cosign\n", sum.Records, sum.Allowed, sum.Denied, sum.Cosign)

	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	if len(sum.BackendStats) > 0 {
		fmt.Fprintln(tw, "\nBACKEND\tCALLS\tALLOW\tDENY\tCOSIGN\tPEERS")
		for _, b := range sum.BackendStats {
			fmt.Fprintf(tw, "%s\t%d\t%d\t%d\t%d\t%d\n", b.Backend, b.Calls, b.Allowed, b.Denied, b.Cosign, b.Peers)
		}
	}
	peers := append([]policy.PeerStat(nil), sum.Peers...)
	sort.Slice(peers, func(i, j int) bool { return peers[i].Calls > peers[j].Calls })
	fmt.Fprintln(tw, "\nPEER\tCALLS\tALLOW\tDENY\tCOSIGN\tLAST TOOL")
	for i, p := range peers {
		if i >= *top {
			break
		}
		fmt.Fprintf(tw, "%s\t%d\t%d\t%d\t%d\t%s\n", p.Peer, p.Calls, p.Allowed, p.Denied, p.Cosign, p.LastTool)
	}
	tools := append([]policy.ToolStat(nil), sum.Tools...)
	sort.Slice(tools, func(i, j int) bool { return tools[i].Calls > tools[j].Calls })
	fmt.Fprintln(tw, "\nTOOL\tCALLS\tALLOW\tDENY")
	for i, t := range tools {
		if i >= *top {
			break
		}
		fmt.Fprintf(tw, "%s\t%d\t%d\t%d\n", t.Tool, t.Calls, t.Allowed, t.Denied)
	}
	return tw.Flush()
}
