package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"time"

	"github.com/xrey167/meshmcp/air"
	"github.com/xrey167/meshmcp/pubsub"
	"github.com/xrey167/meshmcp/session"
)

// cmdAirStream renders each governed action as it lands — a live,
// terminal-native counterpart to the served Receipts page and the Air · Stream
// vision (docs/AIR-VISION.md). Two sources feed one renderer: a local JSONL
// audit file (append-only, rotation-aware tail), or — with --bus — the
// gateway-hooks event bus, subscribed over the mesh through the identity-gated
// pub/sub client. On the bus the broker still decides admission (its
// connection ACL and per-topic policy), and it carries only the hook events
// the gateway is configured to publish (default deny + cosign).
func cmdAirStream(args []string) error {
	fs := flag.NewFlagSet("air stream", flag.ExitOnError)
	fromStart := fs.Bool("from-start", false, "file mode: render existing records first, then follow (default: only new)")
	interval := fs.Duration("interval", 500*time.Millisecond, "file mode: poll interval for new records")
	asJSON := fs.Bool("json", false, "print each matched record as its raw JSONL line instead of a rendered row")
	bus := fs.String("bus", "", "subscribe to a gateway hook bus at <peer-ip:port> over the mesh instead of tailing a file (identity-gated; the broker's ACL and topic policy decide admission)")
	var topics stringList
	fs.Var(&topics, "topic", "bus mode: topic glob to subscribe (repeatable; default gateway.*)")
	since := fs.Uint64("since", 0, "bus mode: replay retained events with sequence greater than this first")
	capFlag := fs.String("capability", "", "bus mode: present a signed capability grant; @file reads the token from a file")
	o := meshFlags(fs)
	// Field filters — the same glob matcher `air bind` triggers on, so a terminal
	// tail can narrow to "only denials", "only this peer", "only this tool".
	// Note: over the bus, only the gateway's configured hooks.events are
	// published (default deny + cosign), so --decision allow shows nothing
	// unless the gateway emits allow events.
	var m bindMatch
	fs.StringVar(&m.Decision, "decision", "", "show only records with this decision (allow|deny|cosign; glob)")
	fs.StringVar(&m.Backend, "backend", "", "show only records for this backend (glob)")
	fs.StringVar(&m.Method, "method", "", "show only records for this method (glob)")
	fs.StringVar(&m.Tool, "tool", "", "show only records for this tool (glob)")
	fs.StringVar(&m.Peer, "peer", "", "show only records for this peer (glob)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	// A flag from the other mode is a mistake, not a no-op: reject it so the
	// user is not silently missing the behaviour they asked for (mirrors
	// cmdSubscribe rejecting --group with --since).
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	if *bus != "" {
		if fs.NArg() != 0 {
			return fmt.Errorf("air stream: --bus and a local <audit.jsonl> are mutually exclusive — pass exactly one source")
		}
		if set["from-start"] || set["interval"] {
			return fmt.Errorf("air stream: --from-start and --interval are file-mode flags and have no effect with --bus (use --since to replay retained events)")
		}
		capToken, err := readCapabilityToken(*capFlag)
		if err != nil {
			return err
		}
		if len(topics) == 0 {
			topics = stringList{"gateway.*"}
		}
		if err := streamBus(o, *bus, topics, *since, capToken, m, *asJSON, os.Stdout); err != nil {
			return fmt.Errorf("air stream: %w", err)
		}
		return nil
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: meshmcp air stream [flags] <audit.jsonl>  |  meshmcp air stream --bus <peer-ip:port> [flags]")
	}
	if set["topic"] || set["since"] || set["capability"] {
		return fmt.Errorf("air stream: --topic, --since, and --capability are bus-mode flags; pass --bus <peer-ip:port> to subscribe")
	}
	path := fs.Arg(0)

	ctx, stop := signal.NotifyContext(context.Background(), shutdownSignals...)
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

// streamBus subscribes to a gateway's hook bus over the mesh and renders each
// decision event through the same filter + row model as the file tail. It
// reuses the pub/sub subscribe client (helloFrame + clientStream over the
// resumable session channel): the connection is identity-gated by WireGuard
// key, and the broker's connection ACL and per-topic policy decide admission —
// this command only asks. Ctrl-C ends the subscription cleanly.
func streamBus(o *meshOptions, target string, topics []string, since uint64, capToken string, filter bindMatch, asJSON bool, w io.Writer) error {
	hello, _ := json.Marshal(helloFrame{Role: "sub", Topics: topics, Since: since, Backpressure: "drop_oldest", Capability: capToken})
	stream := &clientStream{out: append(hello, '\n'), done: make(chan struct{})}

	// subErr is written in the session inbound goroutine (via onLine) and read
	// here after Run returns; guard it since that goroutine is not joined.
	var mu sync.Mutex
	var subErr error
	stream.onLine = busLineHandler(filter, asJSON, w, func(ack ackFrame) {
		if ack.Error != "" {
			mu.Lock()
			subErr = fmt.Errorf("broker rejected subscribe: %s", ack.Error)
			mu.Unlock()
			stream.finish()
			return
		}
		if ack.Truncated {
			fmt.Fprintln(os.Stderr, dim(fmt.Sprintf("replay from seq %d was truncated; some events aged out of retention", since)))
		}
		fmt.Fprintln(os.Stderr, dim("streaming ")+bold(strings.Join(topics, " "))+dim(" on ")+bold(target)+dim(" · Ctrl-C to stop"))
	})

	o.BlockInbound = true
	client, err := startMesh(o, os.Stderr)
	if err != nil {
		return err
	}
	defer stopMesh(client)

	ctx, stop := signal.NotifyContext(context.Background(), shutdownSignals...)
	defer stop()
	go func() {
		<-ctx.Done()
		stream.finish()
	}()

	dial := func(ctx context.Context) (net.Conn, error) { return client.Dial(ctx, "tcp", target) }
	err = session.NewClient(dial, log.Printf).Run(ctx, stream)
	mu.Lock()
	se := subErr
	mu.Unlock()
	if se != nil {
		return se
	}
	if err != nil && ctx.Err() == nil {
		return fmt.Errorf("subscribe to %s: %w", target, err)
	}
	return nil
}

// busLineHandler builds the inbound-line handler for a hook-bus subscription:
// the first line is the broker's subscribe ack (handed to onAck), every later
// line is a bus event decoded and rendered through the shared row model. It is
// the seam under streamBus, so tests can feed synthetic wire lines through the
// exact handler — no live mesh needed.
func busLineHandler(filter bindMatch, asJSON bool, w io.Writer, onAck func(ackFrame)) func(line []byte) {
	first := true
	return func(line []byte) {
		if first {
			first = false
			var ack ackFrame
			_ = json.Unmarshal(line, &ack)
			onAck(ack)
			return
		}
		streamBusLine(line, filter, asJSON, w)
	}
}

// streamBusLine renders one bus-carried event line that matches filter — as a
// coloured row, or (asJSON) its raw event line for a scripting consumer.
// Non-decision lines (foreign payloads, junk) are skipped silently.
func streamBusLine(line []byte, filter bindMatch, asJSON bool, w io.Writer) {
	r, ok := parseBusRecord(line)
	if !ok || !matchRecord(filter, r) {
		return
	}
	if asJSON {
		fmt.Fprintln(w, string(bytes.TrimSpace(line)))
		return
	}
	fmt.Fprintln(w, formatStreamRow(r))
}

// parseBusRecord decodes one bus event line — a pubsub.Event whose payload is
// a gateway hookPayload — into the shared stream row model. The hook payload
// names the decision `event` and carries no timestamp, so the row takes its
// time from the broker-stamped event envelope. Unknown fields in either layer
// are tolerated (ignored), so a newer gateway can add fields without breaking
// an older stream. Reports false for lines that are not decision events.
func parseBusRecord(line []byte) (streamRecord, bool) {
	var ev pubsub.Event
	if err := json.Unmarshal(line, &ev); err != nil || len(ev.Payload) == 0 {
		return streamRecord{}, false
	}
	var p hookPayload
	if err := json.Unmarshal(ev.Payload, &p); err != nil || p.Event == "" {
		return streamRecord{}, false
	}
	return streamRecord{
		Time:     ev.Time,
		Decision: p.Event,
		Backend:  p.Backend,
		Peer:     p.Peer,
		Method:   p.Method,
		Tool:     p.Tool,
		Reason:   p.Reason,
	}, true
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

// streamRecord is the subset of a policy.AuditRecord the stream renders. It is
// air.Receipt — the same shape the aggregated home view tails — so both faces
// decode governed activity through one shared parser (air.ParseReceipt).
type streamRecord = air.Receipt

// parseStreamRecord decodes one audit JSONL line into the subset that air stream
// and air bind care about, reporting false if the line is not a renderable audit
// record (bad JSON, or no decision — the field that marks a policy record).
func parseStreamRecord(line []byte) (streamRecord, bool) { return air.ParseReceipt(line) }

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
		dim(sanitizeCell(streamTime(r.Time))), dec, bold(sanitizeCell(r.Peer)), sanitizeCell(what))
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
