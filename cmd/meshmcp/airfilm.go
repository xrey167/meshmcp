package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/xrey167/meshmcp/policy"
)

// Air · Film — record & replay governed activity.
//
// A "film" is a portable capture of the hash-chained audit ledger — the exact
// record bytes for a chosen window plus a manifest header — that plays back
// through the SAME renderer the live `air stream` uses, so a captured incident
// looks identical to watching it live, but repeatable, shareable, and speed-
// controllable. Uses: incident forensics (hand an auditor one verifiable file),
// demos (replay a governed session at 8×), and review (scrub a decision window
// without live gateway access). `air play` is a shortcut for `air film play`.
//
//	air film record <out> --audit <ledger> [--last N|--since DUR] [filters] [--redact]
//	air film play   <film> [--speed N] [--max-gap DUR] [--json] [filters] [--no-verify]
//	air film verify <film>
//	air play        <film> [--speed N] ...            (alias for `air film play`)

// filmVersion is the film-format version written into every manifest.
const filmVersion = 1

// maxFilmRecords bounds a capture so a single film can't grow unbounded.
const maxFilmRecords = 1_000_000

// filmManifest is the first line of a film: what it captured and how strongly it
// can be verified. Because a film preserves the EXACT original record bytes, a
// full-ledger film verifies end-to-end via policy.VerifyChain; a windowed or
// redacted film keeps a content_sha256 seal over its own bytes but is labelled
// verifiable:false for full body-crypto until re-anchored against a live ledger.
type filmManifest struct {
	Film       string `json:"film"`    // always "meshmcp"
	Version    int    `json:"version"` // filmVersion
	Created    string `json:"created"` // RFC3339 (stamped by the caller, not in tests)
	Records    int    `json:"records"`
	ContentSHA string `json:"content_sha256"`
	FullChain  bool   `json:"full_chain"` // captured the whole ledger from seq 1
	Redacted   bool   `json:"redacted"`
	Verifiable bool   `json:"verifiable"` // full hash-chain verification possible
	AnchorPrev string `json:"anchor_prev_hash,omitempty"`
	HeadHash   string `json:"head_hash,omitempty"`
}

// filmLink is the subset of an audit record a film reads for chain anchoring.
type filmLink struct {
	Seq      int    `json:"seq"`
	PrevHash string `json:"prev_hash"`
	Hash     string `json:"hash"`
}

// cmdAirFilm dispatches the record/play/verify sub-verbs.
func cmdAirFilm(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: meshmcp air film <record|play|verify> ...")
	}
	switch args[0] {
	case "record":
		return filmRecord(args[1:])
	case "play":
		return filmPlay(args[1:])
	case "verify":
		return filmVerify(args[1:])
	default:
		return fmt.Errorf("air film: unknown sub-verb %q (want record | play | verify)", args[0])
	}
}

// cmdAirPlay is the top-level shortcut `air play <film>` for `air film play`.
func cmdAirPlay(args []string) error { return filmPlay(args) }

// matchFlags registers the shared five glob field filters (the same air stream
// and air bind expose) on fs and returns the bindMatch they populate.
func matchFlags(fs *flag.FlagSet) *bindMatch {
	var m bindMatch
	fs.StringVar(&m.Decision, "decision", "", "only records with this decision (glob)")
	fs.StringVar(&m.Backend, "backend", "", "only records for this backend (glob)")
	fs.StringVar(&m.Method, "method", "", "only records for this method (glob)")
	fs.StringVar(&m.Tool, "tool", "", "only records for this tool (glob)")
	fs.StringVar(&m.Peer, "peer", "", "only records for this peer (glob)")
	return &m
}

// filmRecord captures a window of an audit ledger into a film.
func filmRecord(args []string) error {
	fs := flag.NewFlagSet("air film record", flag.ExitOnError)
	audit := fs.String("audit", "", "audit JSONL ledger to capture from (required)")
	last := fs.Int("last", 0, "capture only the last N records (a windowed film)")
	since := fs.Duration("since", 0, "capture only records within this age, e.g. 1h (a windowed film)")
	redact := fs.Bool("redact", false, "mask peer_key, peer_addr and reason (breaks chain verification by design)")
	m := matchFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: meshmcp air film record [flags] <out.film> --audit <ledger>")
	}
	if *audit == "" {
		return fmt.Errorf("air film record: --audit <ledger> is required")
	}
	out := fs.Arg(0)

	// Gather candidate raw record bytes: a bounded tail, or the whole ledger.
	var lines [][]byte
	if *last > 0 {
		recs, err := tailAuditRecords(*audit, *last)
		if err != nil {
			return fmt.Errorf("air film record: %w", err)
		}
		for _, r := range recs {
			lines = append(lines, []byte(r))
		}
	} else {
		got, err := readAllRecords(*audit)
		if err != nil {
			return fmt.Errorf("air film record: %w", err)
		}
		lines = got
	}

	windowed := *last > 0 || *since > 0 || !isZeroMatch(*m)
	cutoff := time.Time{}
	if *since > 0 {
		// The caller stamps "now"; compute the cutoff from the newest record's
		// own timestamp so record has no dependency on a wall clock (testable).
		cutoff = newestRecordTime(lines).Add(-*since)
	}

	kept := make([][]byte, 0, len(lines))
	for _, line := range lines {
		r, ok := parseStreamRecord(line)
		if !ok || !matchRecord(*m, r) {
			continue
		}
		if *since > 0 && recordBefore(r.Time, cutoff) {
			continue
		}
		if *redact {
			line = redactLine(line)
		}
		kept = append(kept, line)
		if len(kept) > maxFilmRecords {
			return fmt.Errorf("air film record: capture exceeds %d records", maxFilmRecords)
		}
	}
	if len(kept) == 0 {
		return fmt.Errorf("air film record: no records matched — nothing to capture")
	}

	// A full-chain film is the whole ledger, unfiltered, un-redacted, starting at
	// seq 1 — only then can policy.VerifyChain prove it end to end.
	firstSeq := recordSeq(kept[0])
	fullChain := !windowed && !*redact && firstSeq == 1
	man := filmManifest{
		Film:       "meshmcp",
		Version:    filmVersion,
		Records:    len(kept),
		ContentSHA: contentHash(kept),
		FullChain:  fullChain,
		Redacted:   *redact,
		Verifiable: fullChain,
		AnchorPrev: recordPrevHash(kept[0]),
		HeadHash:   recordHash(kept[len(kept)-1]),
	}
	man.Created = time.Now().UTC().Format(time.RFC3339)
	if err := writeFilm(out, man, kept); err != nil {
		return fmt.Errorf("air film record: %w", err)
	}

	note := fmt.Sprintf("captured %d record(s) → %s", len(kept), out)
	fmt.Println(okLine("%s", note))
	if man.Verifiable {
		fmt.Fprintln(os.Stderr, dim("full-chain film · verify with ")+bold("air film verify "+out))
	} else {
		fmt.Fprintln(os.Stderr, amber("windowed/redacted film")+dim(" · content-sealed but not full-chain verifiable"))
	}
	fmt.Fprintln(os.Stderr, dim("⚠ a film is a copy of identity-attributed, governed records — share with care")+
		func() string {
			if *redact {
				return dim(" (peer_key/peer_addr/reason redacted)")
			}
			return ""
		}())
	return nil
}

// filmPlay replays a film through the live stream renderer, honouring the
// recorded inter-record timing scaled by --speed.
func filmPlay(args []string) error {
	fs := flag.NewFlagSet("air film play", flag.ExitOnError)
	speed := fs.Float64("speed", 1.0, "playback speed multiplier (0 = no delay, dump instantly)")
	maxGap := fs.Duration("max-gap", 2*time.Second, "cap idle time between records so a demo never stalls")
	asJSON := fs.Bool("json", false, "print each record's raw JSONL line instead of a rendered row")
	noVerify := fs.Bool("no-verify", false, "skip the film's integrity check before playing")
	m := matchFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: meshmcp air film play [flags] <film>")
	}
	man, records, err := readFilm(fs.Arg(0))
	if err != nil {
		return fmt.Errorf("air film play: %w", err)
	}
	if !*noVerify {
		if err := checkFilmIntegrity(man, records); err != nil {
			return fmt.Errorf("air film play: %w", err)
		}
		fmt.Fprintln(os.Stderr, filmStatusLine(man))
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	var prev time.Time
	for i, line := range records {
		r, ok := parseStreamRecord(line)
		if !ok || !matchRecord(*m, r) {
			continue
		}
		if t, perr := time.Parse(time.RFC3339, r.Time); perr == nil {
			if !prev.IsZero() && *speed > 0 {
				gap := t.Sub(prev)
				if gap > 0 {
					d := time.Duration(float64(gap) / *speed)
					if d > *maxGap {
						d = *maxGap
					}
					if !sleepCtx(ctx, d) {
						return nil
					}
				}
			}
			prev = t
		}
		if *asJSON {
			fmt.Println(string(bytes.TrimSpace(line)))
		} else {
			fmt.Println(formatStreamRow(r))
		}
		_ = i
	}
	return nil
}

// filmVerify checks a film's integrity and prints the verdict.
func filmVerify(args []string) error {
	fs := flag.NewFlagSet("air film verify", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "print the verdict as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: meshmcp air film verify <film>")
	}
	man, records, err := readFilm(fs.Arg(0))
	if err != nil {
		return fmt.Errorf("air film verify: %w", err)
	}
	err = checkFilmIntegrity(man, records)
	if *asJSON {
		return printDeltaJSON(map[string]any{
			"records": man.Records, "full_chain": man.FullChain, "redacted": man.Redacted,
			"verifiable": man.Verifiable, "ok": err == nil,
			"error": func() string {
				if err != nil {
					return err.Error()
				}
				return ""
			}(),
		})
	}
	if err != nil {
		return fmt.Errorf("air film verify: %w", err)
	}
	fmt.Println(okLine("film intact") + dim(fmt.Sprintf(" · %d record(s)", man.Records)))
	fmt.Fprintln(os.Stderr, filmStatusLine(man))
	return nil
}

// checkFilmIntegrity always verifies the content seal, and additionally proves
// the hash chain for a full-chain film via policy.VerifyChain.
func checkFilmIntegrity(man filmManifest, records [][]byte) error {
	if got := contentHash(records); got != man.ContentSHA {
		return fmt.Errorf("film content hash mismatch: the film was modified after capture")
	}
	if man.FullChain && !man.Redacted {
		res, err := policy.VerifyChain(bytes.NewReader(joinLines(records)))
		if err != nil {
			return err
		}
		if !res.OK {
			return fmt.Errorf("hash chain broken at seq %d: %s", res.BreakSeq, res.Reason)
		}
	}
	return nil
}

// filmStatusLine renders a one-line verifiability summary for stderr.
func filmStatusLine(man filmManifest) string {
	switch {
	case man.Redacted:
		return amber("redacted") + dim(" · content-sealed, not chain-verifiable")
	case man.Verifiable:
		return green("full-chain verified") + dim(" · tamper-evident end to end")
	default:
		return amber("windowed") + dim(" · content-sealed; re-anchor against a live ledger for full proof")
	}
}

// --- film IO + record helpers ---

// writeFilm writes the manifest line followed by the exact record lines.
func writeFilm(path string, man filmManifest, records [][]byte) error {
	var buf bytes.Buffer
	mb, err := json.Marshal(man)
	if err != nil {
		return err
	}
	buf.Write(mb)
	buf.WriteByte('\n')
	for _, line := range records {
		buf.Write(bytes.TrimSpace(line))
		buf.WriteByte('\n')
	}
	return os.WriteFile(path, buf.Bytes(), 0o644)
}

// readFilm parses a film into its manifest and record lines.
func readFilm(path string) (filmManifest, [][]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return filmManifest{}, nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	var man filmManifest
	var records [][]byte
	first := true
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		if first {
			if err := json.Unmarshal(line, &man); err != nil || man.Film != "meshmcp" {
				return filmManifest{}, nil, fmt.Errorf("%s is not a film (bad manifest)", path)
			}
			first = false
			continue
		}
		records = append(records, append([]byte(nil), line...))
	}
	if err := sc.Err(); err != nil {
		return filmManifest{}, nil, err
	}
	if first {
		return filmManifest{}, nil, fmt.Errorf("%s is empty", path)
	}
	return man, records, nil
}

// readAllRecords reads every valid JSON line from an audit ledger.
func readAllRecords(path string) ([][]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	var out [][]byte
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 || !json.Valid(line) {
			continue
		}
		out = append(out, append([]byte(nil), line...))
	}
	return out, sc.Err()
}

// contentHash is a sha256 over the newline-joined record block, sealing the
// film's own bytes so any post-capture edit is detected.
func contentHash(records [][]byte) string {
	h := sha256.New()
	h.Write(joinLines(records))
	return hex.EncodeToString(h.Sum(nil))
}

func joinLines(records [][]byte) []byte {
	var buf bytes.Buffer
	for _, line := range records {
		buf.Write(bytes.TrimSpace(line))
		buf.WriteByte('\n')
	}
	return buf.Bytes()
}

// redactLine masks the identity- and reason-bearing fields of a record. It
// rewrites bytes, so a redacted film is deliberately not chain-verifiable.
func redactLine(line []byte) []byte {
	var m map[string]json.RawMessage
	if json.Unmarshal(line, &m) != nil {
		return line
	}
	delete(m, "peer_key")
	delete(m, "peer_addr")
	if _, ok := m["reason"]; ok {
		m["reason"] = json.RawMessage(`"[redacted]"`)
	}
	out, err := json.Marshal(m)
	if err != nil {
		return line
	}
	return out
}

func isZeroMatch(m bindMatch) bool { return m == bindMatch{} }

func recordSeq(line []byte) int         { return recordLink(line).Seq }
func recordPrevHash(line []byte) string { return recordLink(line).PrevHash }
func recordHash(line []byte) string     { return recordLink(line).Hash }

func recordLink(line []byte) filmLink {
	var l filmLink
	_ = json.Unmarshal(line, &l)
	return l
}

// recordBefore reports whether an RFC3339 time string is before cutoff. An
// unparseable time is kept (returns false), never silently dropped.
func recordBefore(ts string, cutoff time.Time) bool {
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return false
	}
	return t.Before(cutoff)
}

// newestRecordTime returns the latest parseable record timestamp, or the zero
// time if none parse — the anchor for a --since window.
func newestRecordTime(lines [][]byte) time.Time {
	var newest time.Time
	for _, line := range lines {
		r, ok := parseStreamRecord(line)
		if !ok {
			continue
		}
		if t, err := time.Parse(time.RFC3339, r.Time); err == nil && t.After(newest) {
			newest = t
		}
	}
	return newest
}

// sleepCtx sleeps for d unless ctx is cancelled first; returns false if cancelled.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
