package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"

	"gopkg.in/yaml.v3"

	"meshmcp/insight"
	"meshmcp/policy"
)

// cmdInsight implements "meshmcp insight <subcommand>": the read side of the
// firewall that turns the audit stream into policy.
func cmdInsight(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: meshmcp insight <profile|recommend|simulate|detect> ...")
	}
	switch args[0] {
	case "profile":
		return insightProfile(args[1:])
	case "recommend":
		return insightRecommend(args[1:])
	case "simulate":
		return insightSimulate(args[1:])
	case "detect":
		return insightDetect(args[1:])
	default:
		return fmt.Errorf("meshmcp insight: unknown subcommand %q (want: profile, recommend, simulate, detect)", args[0])
	}
}

// loadPolicyFile reads a POLICY-DSL YAML file into a policy.Policy.
func loadPolicyFile(path string) (*policy.Policy, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var p policy.Policy
	if err := yaml.Unmarshal(b, &p); err != nil {
		return nil, fmt.Errorf("parse policy %s: %w", path, err)
	}
	return &p, nil
}

// firstArg pulls the leading positional (audit-log path) out before flags, so
// `insight <sub> <log> --flags` parses regardless of Go's flag ordering.
func firstArg(args []string) (string, []string, bool) {
	if len(args) == 0 || args[0] == "" || args[0][0] == '-' {
		return "", args, false
	}
	return args[0], args[1:], true
}

func insightProfile(args []string) error {
	logPath, rest, ok := firstArg(args)
	if !ok {
		return fmt.Errorf("usage: meshmcp insight profile <audit-log> [--policy p] [--json]")
	}
	fs := flag.NewFlagSet("insight profile", flag.ContinueOnError)
	polPath := fs.String("policy", "", "policy in effect (attributes emitted labels)")
	asJSON := fs.Bool("json", false, "emit JSON")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	var pol *policy.Policy
	if *polPath != "" {
		var err error
		if pol, err = loadPolicyFile(*polPath); err != nil {
			return err
		}
	}
	f, err := os.Open(logPath)
	if err != nil {
		return err
	}
	defer f.Close()
	c, err := insight.Profile(f, pol)
	if err != nil {
		return err
	}
	if *asJSON {
		return json.NewEncoder(os.Stdout).Encode(c)
	}
	fmt.Printf("%d records, chain %s, %d identities\n", c.Records, okWord(c.ChainOK), len(c.Identities))
	keys := make([]string, 0, len(c.Identities))
	for k := range c.Identities {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		ip := c.Identities[k]
		fmt.Printf("\n▸ %s  (%d calls: %d allow / %d deny / %d cosign)\n", ip.Peer, ip.Calls, ip.Allowed, ip.Denied, ip.Cosign)
		if len(ip.EmittedLabels) > 0 {
			fmt.Printf("  labels: %v\n", ip.EmittedLabels)
		}
		for _, tp := range ip.Tools {
			fmt.Printf("  %-24s calls=%-4d allow=%-4d deny=%-4d p99/min=%d\n", tp.Tool, tp.Calls, tp.Allowed, tp.Denied, tp.PerMinP99)
		}
	}
	return nil
}

func insightRecommend(args []string) error {
	logPath, rest, ok := firstArg(args)
	if !ok {
		return fmt.Errorf("usage: meshmcp insight recommend <audit-log> [--policy p] [--generalize] [--rate-safety f]")
	}
	fs := flag.NewFlagSet("insight recommend", flag.ContinueOnError)
	polPath := fs.String("policy", "", "policy in effect (attributes emitted labels)")
	generalize := fs.Bool("generalize", false, "collapse tools sharing a prefix into globs (widens; flagged in notes)")
	rateSafety := fs.Float64("rate-safety", 2.0, "rate cap = observed p99 × this factor")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	var pol *policy.Policy
	if *polPath != "" {
		var err error
		if pol, err = loadPolicyFile(*polPath); err != nil {
			return err
		}
	}
	f, err := os.Open(logPath)
	if err != nil {
		return err
	}
	defer f.Close()
	c, err := insight.Profile(f, pol)
	if err != nil {
		return err
	}
	recommended, notes := insight.Recommend(c, insight.RecommendOptions{Generalize: *generalize, RateSafety: *rateSafety})

	// Notes to stderr (so stdout is a clean, pipeable policy).
	fmt.Fprintf(os.Stderr, "# recommended from %d records across %d identities (chain %s)\n", c.Records, len(c.Identities), okWord(c.ChainOK))
	for _, n := range notes {
		fmt.Fprintf(os.Stderr, "# - %s\n", n)
	}
	out, err := yaml.Marshal(recommended)
	if err != nil {
		return err
	}
	fmt.Print(string(out))
	return nil
}

func insightSimulate(args []string) error {
	logPath, rest, ok := firstArg(args)
	if !ok {
		return fmt.Errorf("usage: meshmcp insight simulate <audit-log> --policy <candidate>")
	}
	fs := flag.NewFlagSet("insight simulate", flag.ContinueOnError)
	polPath := fs.String("policy", "", "candidate policy to test (required)")
	asJSON := fs.Bool("json", false, "emit JSON")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	if *polPath == "" {
		return fmt.Errorf("insight simulate: --policy <candidate> is required")
	}
	pol, err := loadPolicyFile(*polPath)
	if err != nil {
		return err
	}
	f, err := os.Open(logPath)
	if err != nil {
		return err
	}
	defer f.Close()
	res, err := insight.Simulate(f, pol)
	if err != nil {
		return err
	}
	if *asJSON {
		_ = json.NewEncoder(os.Stdout).Encode(res)
	} else {
		fmt.Printf("simulated %d decisions: %d unchanged, coverage %.0f%%\n", res.Total, res.Matched, res.Coverage*100)
		printChanges("REGRESSIONS (were allowed, now blocked)", res.Regressions)
		printChanges("NEW CO-SIGN (were allowed, now held for a human)", res.NowCosign)
		printChanges("LOOSENED (were denied, now allowed)", res.Loosened)
	}
	if !res.OK() {
		return fmt.Errorf("policy %s introduces %d regression(s)", *polPath, len(res.Regressions))
	}
	return nil
}

func insightDetect(args []string) error {
	newPath, rest, ok := firstArg(args)
	if !ok {
		return fmt.Errorf("usage: meshmcp insight detect <new-audit-log> --baseline <baseline-audit>")
	}
	fs := flag.NewFlagSet("insight detect", flag.ContinueOnError)
	basePath := fs.String("baseline", "", "baseline audit log to learn normal behavior from (required)")
	polPath := fs.String("policy", "", "policy in effect (attributes labels in the baseline)")
	asJSON := fs.Bool("json", false, "emit JSON")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	if *basePath == "" {
		return fmt.Errorf("insight detect: --baseline <audit> is required")
	}
	var pol *policy.Policy
	if *polPath != "" {
		var err error
		if pol, err = loadPolicyFile(*polPath); err != nil {
			return err
		}
	}
	bf, err := os.Open(*basePath)
	if err != nil {
		return err
	}
	defer bf.Close()
	base, err := insight.Profile(bf, pol)
	if err != nil {
		return err
	}
	if !base.ChainOK {
		fmt.Fprintln(os.Stderr, "warning: baseline audit chain did not verify — learning from a possibly-tampered log")
	}
	nf, err := os.Open(newPath)
	if err != nil {
		return err
	}
	defer nf.Close()
	anomalies, err := insight.Detect(base, nf, insight.DetectOptions{})
	if err != nil {
		return err
	}
	if *asJSON {
		return json.NewEncoder(os.Stdout).Encode(anomalies)
	}
	if len(anomalies) == 0 {
		fmt.Println("no anomalies: new traffic matches the baseline")
		return nil
	}
	fmt.Printf("%d anomaly(ies):\n", len(anomalies))
	for _, a := range anomalies {
		who := a.Peer
		if a.Tool != "" {
			who += " " + a.Tool
		}
		fmt.Printf("  [%.2f] %-16s %s — %s\n        → %s\n", a.Score, a.Kind, who, a.Detail, a.Response)
	}
	return nil
}

func printChanges(title string, cs []insight.Change) {
	if len(cs) == 0 {
		return
	}
	fmt.Printf("\n%s:\n", title)
	for _, c := range cs {
		what := c.Tool
		if what == "" {
			what = c.Method
		}
		fmt.Printf("  %-22s %s→%s  ×%d  %s  (%s)\n", c.Peer+" "+what, c.Was, c.Now, c.Count, c.Reason, c.Example)
	}
}

func okWord(ok bool) string {
	if ok {
		return "OK"
	}
	return "TAMPERED"
}
