package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"time"
)

// cmdAirStream tails a meshmcp audit ledger and renders each governed action as
// it lands — a live, terminal-native counterpart to the served Receipts page
// and the first step of the Air · Stream vision (docs/AIR-VISION.md). It reads a
// local JSONL audit file (append-only, rotation-aware); the deeper form —
// subscribing to the governed event bus over the mesh — is the next step.
func cmdAirStream(args []string) error {
	fs := flag.NewFlagSet("air stream", flag.ExitOnError)
	fromStart := fs.Bool("from-start", false, "render existing records first, then follow (default: only new)")
	interval := fs.Duration("interval", 500*time.Millisecond, "poll interval for new records")
	asJSON := fs.Bool("json", false, "print each matched record as its raw JSONL line instead of a rendered row")
	// Field filters — the same glob matcher `air bind` triggers on, so a terminal
	// tail can narrow to "only denials", "only this peer", "only this tool".
	var m bindMatch
	fs.StringVar(&m.Decision, "decision", "", "show only records with this decision (allow|deny|cosign; glob)")
	fs.StringVar(&m.Backend, "backend", "", "show only records for this backend (glob)")
	fs.StringVar(&m.Method, "method", "", "show only records for this method (glob)")
	fs.StringVar(&m.Tool, "tool", "", "show only records for this tool (glob)")
	fs.StringVar(&m.Peer, "peer", "", "show only records for this peer (glob)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: meshmcp air stream [flags] <audit.jsonl>")
	}
	path := fs.Arg(0)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	fmt.Fprintln(os.Stderr, dim("streaming ")+bold(path)+dim(" · Ctrl-C to stop"))
	if err := streamAudit(ctx, path, *fromStart, m, *asJSON, *interval, os.Stdout); err != nil {
		return fmt.Errorf("air stream: %w", err)
	}
	return nil
}

// streamAudit follows an append-only audit file, rendering each new audit record
// that matches filter — as a coloured row, or (asJSON) its raw JSONL line for a
// scripting consumer. It is rotation-aware and stops when ctx is cancelled.
func streamAudit(ctx context.Context, path string, fromStart bool, filter bindMatch, asJSON bool, interval time.Duration, w io.Writer) error {
	return followAudit(ctx, path, fromStart, interval, func(line []byte) {
		r, ok := parseStreamRecord(line)
		if !ok || !matchRecord(filter, r) {
			return
		}
		if asJSON {
			fmt.Fprintln(w, string(bytes.TrimSpace(line)))
			return
		}
		fmt.Fprintln(w, formatStreamRow(r))
	})
}

// followAudit tails an append-only audit ledger, invoking handle once per
// complete newline-terminated line as records land. It is rotation-aware (a file
// that shrank below our offset is reopened from the start) and stops when ctx is
// cancelled. This is the shared engine under `air stream` (which renders each
// line) and `air bind` (which matches each line against reaction rules).
func followAudit(ctx context.Context, path string, fromStart bool, interval time.Duration, handle func(line []byte)) error {
	// time.NewTicker panics on a non-positive interval; a bad --interval (0 or
	// negative) must degrade to a sane default, never crash the follower.
	if interval <= 0 {
		interval = 500 * time.Millisecond
	}
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	// Close via a closure, not `defer f.Close()`: a rotation reopen reassigns f,
	// and a bound method value would keep closing the ORIGINAL handle, leaking the
	// reopened one (an fd leak on every rotation).
	defer func() { f.Close() }()

	var offset int64
	if !fromStart {
		if offset, err = f.Seek(0, io.SeekEnd); err != nil {
			return err
		}
	}
	reader := bufio.NewReader(f)

	drain := func() {
		for {
			line, err := reader.ReadBytes('\n')
			offset += int64(len(line))
			if err != nil {
				// Put an incomplete trailing line back by rewinding to before it.
				offset -= int64(len(line))
				_, _ = f.Seek(offset, io.SeekStart)
				reader.Reset(f)
				return
			}
			handle(line)
		}
	}
	drain()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			// Rotation / truncation: the file shrank below our offset — reopen.
			if fi, err := os.Stat(path); err == nil && fi.Size() < offset {
				if nf, err := os.Open(path); err == nil {
					f.Close()
					f = nf
					offset = 0
					reader.Reset(f)
				}
			}
			drain()
		}
	}
}

// streamRecord is the subset of a policy.AuditRecord the stream renders.
type streamRecord struct {
	Time     string `json:"time"`
	Backend  string `json:"backend"`
	Peer     string `json:"peer"`
	Method   string `json:"method"`
	Tool     string `json:"tool"`
	Decision string `json:"decision"`
	Reason   string `json:"reason"`
}

// parseStreamRecord decodes one audit JSONL line into the subset that air stream
// and air bind care about, reporting false if the line is not a renderable audit
// record (bad JSON, or no decision — the field that marks a policy record).
func parseStreamRecord(line []byte) (streamRecord, bool) {
	line = bytes.TrimSpace(line)
	if len(line) == 0 {
		return streamRecord{}, false
	}
	var r streamRecord
	if json.Unmarshal(line, &r) != nil || r.Decision == "" {
		return streamRecord{}, false
	}
	return r, true
}

// formatAuditLine renders one audit JSONL line as a coloured stream row, or
// ("", false) if the line is not a renderable audit record or is filtered out by
// backend. The decision drives the colour: allow green, deny red, cosign amber.
func formatAuditLine(line []byte, backend string) (string, bool) {
	r, ok := parseStreamRecord(line)
	if !ok {
		return "", false
	}
	if backend != "" && r.Backend != backend {
		return "", false
	}
	return formatStreamRow(r), true
}

// formatStreamRow renders a parsed audit record as a coloured, escape-safe row.
// Every dynamic field goes through sanitizeCell so a hostile peer/tool/reason
// cannot inject terminal escapes; the decision drives the colour.
func formatStreamRow(r streamRecord) string {
	var dec string
	switch r.Decision {
	case "allow":
		dec = green("allow ")
	case "deny":
		dec = red("deny  ")
	case "cosign":
		dec = amber("cosign")
	default:
		dec = sanitizeCell(r.Decision)
	}
	what := r.Method
	if r.Tool != "" {
		what += " · " + r.Tool
	}
	row := fmt.Sprintf("%s  %s  %s  %s",
		dim(streamTime(r.Time)), dec, bold(sanitizeCell(r.Peer)), sanitizeCell(what))
	if r.Backend != "" {
		row += "  " + cyan(sanitizeCell(r.Backend))
	}
	if r.Reason != "" {
		row += "  " + dim(sanitizeCell(r.Reason))
	}
	return row
}

// streamTime shortens an RFC3339 timestamp to HH:MM:SS for a compact row,
// leaving anything unexpected untouched.
func streamTime(t string) string {
	if i := strings.IndexByte(t, 'T'); i >= 0 && len(t) >= i+9 {
		return t[i+1 : i+9]
	}
	return t
}
