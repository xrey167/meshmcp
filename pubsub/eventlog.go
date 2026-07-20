package pubsub

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"

	"github.com/xrey167/meshmcp/policy"
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

	cp       *policy.Checkpointer // optional signed Merkle checkpoints
	lastSeq  uint64
	lastHash string
}

// NewEventLog returns an EventLog that appends sealed events to w (typically an
// os.File opened for append).
func NewEventLog(w io.Writer) *EventLog { return &EventLog{w: w} }

// WithCheckpointer attaches a signed-checkpoint sink: the log periodically
// emits an Ed25519-signed Merkle commitment over its events, making the
// persisted stream non-repudiable (an insider who controls the file cannot
// rewrite history without the signature disagreeing). Call Flush before
// shutdown to seal the final partial batch.
func (e *EventLog) WithCheckpointer(cp *policy.Checkpointer) *EventLog {
	e.cp = cp
	return e
}

// append writes one sealed event as a JSON line and feeds its hash to the
// checkpointer. Errors are returned to the caller, which treats persistence as
// best-effort per-event (a failed append degrades durability for that event but
// never blocks delivery), mirroring the audit ledger.
func (e *EventLog) append(ev Event) error {
	if e == nil || e.w == nil {
		return nil
	}
	b, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if _, err = e.w.Write(b); err != nil {
		return err
	}
	e.lastSeq, e.lastHash = ev.Seq, ev.Hash
	if e.cp != nil {
		e.cp.Add(int(ev.Seq), ev.Hash)
	}
	return nil
}

// Flush seals any buffered records into a final signed checkpoint. Call it on a
// clean shutdown (after the broker has stopped, so no append races). No-op
// without a checkpointer.
func (e *EventLog) Flush() {
	if e == nil || e.cp == nil {
		return
	}
	e.cp.Flush(int(e.lastSeq), e.lastHash)
}

// VerifyCheckpoints verifies signed Merkle checkpoints over a persisted event
// stream: each checkpoint's Ed25519 signature (pinned to expectPub if non-empty),
// its Merkle root over the covered events' hashes, and the checkpoint-to-
// checkpoint linkage and coverage. events is the chain-verified stream returned
// by LoadEvents. It returns the number of checkpoints verified.
func VerifyCheckpoints(events []Event, checkpointR io.Reader, expectPub string) (int, error) {
	hashBySeq := make(map[int][]byte, len(events))
	for _, ev := range events {
		raw, err := hex.DecodeString(ev.Hash)
		if err != nil {
			return 0, fmt.Errorf("event seq %d: bad hash", ev.Seq)
		}
		hashBySeq[int(ev.Seq)] = raw
	}

	sc := bufio.NewScanner(checkpointR)
	sc.Buffer(make([]byte, 0, 64*1024), maxEventLogLine)
	prevCP := ""
	prevTo := 0
	n := 0
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var cp policy.Checkpoint
		if err := json.Unmarshal(line, &cp); err != nil {
			return n, fmt.Errorf("checkpoint %d: not valid JSON", n+1)
		}
		n++
		if err := policy.VerifyCheckpoint(cp, expectPub); err != nil {
			return n, fmt.Errorf("checkpoint %d: %w", cp.Seq, err)
		}
		if cp.PrevCP != prevCP {
			return n, fmt.Errorf("checkpoint %d does not link to the previous (chain of checkpoints broken)", cp.Seq)
		}
		if cp.FromSeq != prevTo+1 {
			return n, fmt.Errorf("checkpoint %d coverage gap (starts %d, previous ended %d)", cp.Seq, cp.FromSeq, prevTo)
		}
		// The coverage span comes from the (untrusted) checkpoints file — bound
		// it before allocating, so a hostile file can't cause a negative-cap
		// panic or a huge allocation.
		if cp.ToSeq < cp.FromSeq || cp.ToSeq-cp.FromSeq+1 > len(events) {
			return n, fmt.Errorf("checkpoint %d: implausible coverage span [%d,%d]", cp.Seq, cp.FromSeq, cp.ToSeq)
		}
		leaves := make([][]byte, 0, cp.ToSeq-cp.FromSeq+1)
		for s := cp.FromSeq; s <= cp.ToSeq; s++ {
			h, ok := hashBySeq[s]
			if !ok {
				return n, fmt.Errorf("checkpoint %d covers missing event seq %d", cp.Seq, s)
			}
			leaves = append(leaves, h)
		}
		root := policy.MerkleRoot(leaves)
		if hex.EncodeToString(root[:]) != cp.MerkleRoot {
			return n, fmt.Errorf("checkpoint %d Merkle root mismatch (events were altered)", cp.Seq)
		}
		prevCP = cp.Hash()
		prevTo = cp.ToSeq
	}
	if err := sc.Err(); err != nil {
		return n, err
	}
	return n, nil
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
