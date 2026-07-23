package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/xrey167/meshmcp/federation"
)

// cmdFederateUsage implements `meshmcp federate usage` (S58): the metering /
// billing-export read side of the federation boundary. It replays the crossing
// audit log the boundary already writes — every record is org-attributed — so
// usage export needs no new hot-path state and its numbers are backed by the
// tamper-evident ledger itself. When audit rotation (S51) has sealed archive
// segments (<path>.<UTC timestamp>[-NNN]), they are included automatically:
// a billing window must never silently under-count because the ledger rotated.
func cmdFederateUsage(args []string) error {
	fs := flag.NewFlagSet("federate usage", flag.ContinueOnError)
	auditPath := fs.String("audit", "", "crossing audit log (JSONL) the boundary writes; rotated archive segments beside it are included automatically (required)")
	asJSON := fs.Bool("json", false, "emit the usage report as JSON")
	since := fs.String("since", "", "count only crossings at/after this RFC3339 UTC time (inclusive)")
	until := fs.String("until", "", "count only crossings before this RFC3339 UTC time (exclusive)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *auditPath == "" {
		return fmt.Errorf("meshmcp federate usage: --audit <file> is required")
	}
	sinceUTC, err := normalizeUsageBound("since", *since)
	if err != nil {
		return err
	}
	untilUTC, err := normalizeUsageBound("until", *until)
	if err != nil {
		return err
	}

	segments, err := auditSegmentPaths(*auditPath)
	if err != nil {
		return err
	}
	readers := make([]io.Reader, 0, 2*len(segments))
	for _, p := range segments {
		f, err := os.Open(p)
		if err != nil {
			return fmt.Errorf("open audit log segment: %w", err)
		}
		defer f.Close()
		// A separator newline guards against a segment whose final record lacks
		// a trailing newline gluing onto the next segment's first record; blank
		// lines are skipped by the aggregator.
		readers = append(readers, f, strings.NewReader("\n"))
	}
	report, err := federation.AggregateUsage(io.MultiReader(readers...), sinceUTC, untilUTC)
	if err != nil {
		return err
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(report)
	}

	window := ""
	if sinceUTC != "" || untilUTC != "" {
		window = fmt.Sprintf(" (window %s .. %s)", orAny(sinceUTC), orAny(untilUTC))
	}
	source := *auditPath
	if len(segments) > 1 {
		source = fmt.Sprintf("%s (+%d rotated segment(s))", *auditPath, len(segments)-1)
	}
	fmt.Printf("federation usage: %s — %d crossing(s)%s\n", source, report.Crossings, window)
	if len(report.Orgs) == 0 {
		fmt.Println("no federation crossings recorded")
		return nil
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "\nORG\tKIND\tNAME\tALLOW\tDENY")
	for _, o := range report.Orgs {
		for _, t := range o.Tools {
			fmt.Fprintf(tw, "%s\ttool\t%s\t%d\t%d\n", o.Org, t.Name, t.Allowed, t.Denied)
		}
		for _, c := range o.Corpora {
			fmt.Fprintf(tw, "%s\tcorpus\t%s\t%d\t%d\n", o.Org, c.Name, c.Allowed, c.Denied)
		}
		fmt.Fprintf(tw, "%s\ttotal\t\t%d\t%d\n", o.Org, o.Allowed, o.Denied)
	}
	return tw.Flush()
}

// normalizeUsageBound validates a --since/--until value and normalizes it to
// the exact form the boundary writes (second-precision RFC3339 UTC, "Z"), so
// the aggregator's lexicographic comparison is order-correct. A non-UTC offset
// is converted; fractional seconds are rejected rather than silently truncated
// (the ledger's timestamps are second-precision, so a sub-second bound cannot
// be honored exactly).
func normalizeUsageBound(name, v string) (string, error) {
	if v == "" {
		return "", nil
	}
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		return "", fmt.Errorf("federate usage: --%s must be RFC3339 (e.g. 2026-07-01T00:00:00Z): %w", name, err)
	}
	if t.Nanosecond() != 0 {
		return "", fmt.Errorf("federate usage: --%s: fractional seconds are not supported (audit timestamps are second-precision)", name)
	}
	return t.UTC().Format(time.RFC3339), nil
}

// auditSegmentPaths returns the ledger's sealed rotation archives (oldest
// first, by their lexicographically chronological names) followed by the
// active file. Billing must cover the whole ledger: reading only the active
// segment would silently drop every crossing rotated into an archive.
func auditSegmentPaths(active string) ([]string, error) {
	if _, err := os.Stat(active); err != nil {
		return nil, fmt.Errorf("open audit log: %w", err)
	}
	matches, err := filepath.Glob(active + ".*")
	if err != nil {
		return nil, fmt.Errorf("scan audit archives: %w", err)
	}
	var segments []string
	for _, m := range matches {
		if auditArchivePattern.MatchString(m) {
			segments = append(segments, m)
		}
	}
	sort.Strings(segments)
	return append(segments, active), nil
}

func orAny(s string) string {
	if s == "" {
		return "*"
	}
	return s
}
