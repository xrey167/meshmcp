package pubsub

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
)

// EventLog is an append-only sink for the sealed event stream. Persisting the
// hash-chained events makes the bus durable — it survives a broker restart
// (the sequence and hash chain continue, and `--since` replay is backed by the
// log) — and makes the chain externally verifiable (VerifyChain / `meshmcp
// pubsub verify` over the file), the same guarantee the audit ledger gives.
//
// The broker appends in strict sequence order under its own lock, so EventLog
// needs no internal synchronization. Like the audit ledger, appends are direct
// writes (no fsync): durable across a process restart, not across power loss.
type EventLog struct {
	w io.Writer
}

// NewEventLog returns an EventLog that appends sealed events to w (typically an
// os.File opened for append).
func NewEventLog(w io.Writer) *EventLog { return &EventLog{w: w} }

// append writes one sealed event as a JSON line. Errors are returned to the
// caller, which treats persistence as best-effort per-event (a failed append
// degrades durability for that event but never blocks delivery), mirroring the
// audit ledger.
func (e *EventLog) append(ev Event) error {
	if e == nil || e.w == nil {
		return nil
	}
	b, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	_, err = e.w.Write(b)
	return err
}

// maxEventLogLine bounds a single line read from a persisted log, so a
// corrupted file cannot force unbounded buffering on load.
const maxEventLogLine = 16 << 20 // 16 MiB (well above the wire payload cap)

// LoadEvents reads a persisted event log and returns its events. The chain is
// verified with VerifyChain, so a tampered or reordered log is rejected. A
// single torn trailing line — a crash mid-append that left an unparseable last
// record — is tolerated and dropped; any *interior* unparseable line or chain
// break is an error (a tamper or corruption signal).
func LoadEvents(r io.Reader) ([]Event, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), maxEventLogLine)

	var events []Event
	sawBad := false
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var ev Event
		if err := json.Unmarshal(line, &ev); err != nil {
			// Tolerate an unparseable line only if it is the tail. If any
			// further data follows, it was not a torn tail — fail.
			sawBad = true
			continue
		}
		if sawBad {
			return nil, fmt.Errorf("event log: unparseable record before end of file")
		}
		events = append(events, ev)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("event log: read: %w", err)
	}
	if err := VerifyChain(events); err != nil {
		return nil, fmt.Errorf("event log: chain broken: %w", err)
	}
	return events, nil
}
