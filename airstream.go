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
	backend := fs.String("backend", "", "show only records for this backend")
	interval := fs.Duration("interval", 500*time.Millisecond, "poll interval for new records")
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
	return streamAudit(ctx, path, *fromStart, *backend, *interval, os.Stdout)
}

// streamAudit follows an append-only audit file, rendering each new audit record
// through formatAuditLine. It is rotation-aware (a file that shrank is reopened
// from the start) and stops when ctx is cancelled. Factored out so the follow
// loop is exercisable without a real terminal.
func streamAudit(ctx context.Context, path string, fromStart bool, backend string, interval time.Duration, w io.Writer) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("air stream: %w", err)
	}
	defer f.Close()

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
			if s, ok := formatAuditLine(bytes.TrimSpace(line), backend); ok {
				fmt.Fprintln(w, s)
			}
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

// formatAuditLine renders one audit JSONL line as a coloured stream row, or
// (‑, false) if the line is not a renderable audit record or is filtered out by
// backend. The decision drives the colour: allow green, deny red, cosign amber.
func formatAuditLine(line []byte, backend string) (string, bool) {
	if len(line) == 0 {
		return "", false
	}
	var r streamRecord
	if json.Unmarshal(line, &r) != nil || r.Decision == "" {
		return "", false
	}
	if backend != "" && r.Backend != backend {
		return "", false
	}
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
	return row, true
}

// streamTime shortens an RFC3339 timestamp to HH:MM:SS for a compact row,
// leaving anything unexpected untouched.
func streamTime(t string) string {
	if i := strings.IndexByte(t, 'T'); i >= 0 && len(t) >= i+9 {
		return t[i+1 : i+9]
	}
	return t
}
