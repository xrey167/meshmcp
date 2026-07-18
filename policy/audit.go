package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sync"
)

// AuditRecord is one structured audit entry for a tool invocation.
//
// The last three fields make the log tamper-evident: every record carries a
// monotonic Seq, the Hash of the previous record (PrevHash), and its own
// Hash = sha256(json(record with Hash cleared)). Because PrevHash is folded
// into each record's own bytes, the records form a hash chain — editing,
// reordering, or deleting any record breaks every hash after it, and the
// break is detectable without the original (see VerifyChain). This is the
// difference between "a log" and "a log you can prove wasn't edited".
type AuditRecord struct {
	Time     string `json:"time"`
	Backend  string `json:"backend"`
	Peer     string `json:"peer"`
	PeerKey  string `json:"peer_key,omitempty"`
	PeerAddr string `json:"peer_addr,omitempty"`
	Method   string `json:"method"`
	Tool     string `json:"tool,omitempty"`
	RPCID    string `json:"rpc_id,omitempty"`
	Decision string `json:"decision"` // "allow" | "deny" | "cosign"
	Reason   string `json:"reason,omitempty"`
	Rule     int    `json:"rule"` // matching rule index, -1 for default

	// Provenance carries the content refs (e.g. retrieved document / triple
	// hashes) that produced an answer — a signed provenance receipt for
	// verifiable AI answers. Optional and omitempty, so it is covered by the
	// hash chain and signed checkpoints without changing existing records.
	Provenance []string `json:"provenance,omitempty"`

	// Tamper-evidence chain (always present once written).
	Seq      int    `json:"seq"`
	PrevHash string `json:"prev_hash"`
	Hash     string `json:"hash,omitempty"`
}

// AuditLog writes audit records as newline-delimited JSON to a sink, chaining
// each record's hash to the previous one.
type AuditLog struct {
	mu   sync.Mutex
	w    io.Writer
	nowf func() string // injectable clock for deterministic tests

	seq  int
	prev string // hash of the last written record ("" before the genesis record)

	cp       *Checkpointer // optional: signed Merkle checkpoints
	lastSeq  int
	lastHash string

	failClosed bool // when set, a failed write is surfaced to deny the call
}

// WithFailClosed makes the log a hard control: when the underlying sink cannot
// accept a record (a full disk, an I/O error), the enforcement point denies the
// call rather than letting it proceed unrecorded. Off by default so existing
// deployments keep best-effort behavior until they opt in.
func (a *AuditLog) WithFailClosed(on bool) *AuditLog {
	a.failClosed = on
	return a
}

// FailClosed reports whether a write failure should deny the call.
func (a *AuditLog) FailClosed() bool { return a != nil && a.failClosed }

// WithCheckpointer attaches a signed-checkpoint sink: the log periodically
// emits an Ed25519-signed Merkle commitment over its records, making it
// non-repudiable and externally verifiable. Call Flush before shutdown to seal
// the final partial batch.
func (a *AuditLog) WithCheckpointer(cp *Checkpointer) *AuditLog {
	a.cp = cp
	return a
}

// Flush seals any buffered records into a final checkpoint.
func (a *AuditLog) Flush() {
	a.mu.Lock()
	cp, seq, hash := a.cp, a.lastSeq, a.lastHash
	a.mu.Unlock()
	cp.Flush(seq, hash)
}

// NewAuditLog writes records to w. now supplies timestamps; if nil, records
// carry an empty time (the caller can inject a real clock).
func NewAuditLog(w io.Writer, now func() string) *AuditLog {
	if now == nil {
		now = func() string { return "" }
	}
	return &AuditLog{w: w, nowf: now}
}

// SeedFrom continues an existing chain: the next record written gets sequence
// seq+1 and links to prevHash. Use it when appending to an audit file whose
// tail was read with LastLink, so restarts don't reset the chain.
func (a *AuditLog) SeedFrom(seq int, prevHash string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.seq = seq
	a.prev = prevHash
}

// chainHash computes the record's hash over its JSON with the Hash field
// cleared. PrevHash is already a field of rec, so it is covered by the hash.
func chainHash(rec AuditRecord) (string, []byte, error) {
	rec.Hash = ""
	b, err := json.Marshal(rec)
	if err != nil {
		return "", nil, err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), b, nil
}

// Append writes one audit record, extending the hash chain. It is the public
// entry point for code outside the filter (e.g. the control plane) that needs
// to contribute to the same tamper-evident log. The returned error is nil on a
// nil/no-op log; callers that treat audit as a control should propagate it.
func (a *AuditLog) Append(rec AuditRecord) error { return a.write(rec) }

// write emits one record and extends the hash chain. The sequence number and
// PrevHash cursor advance ONLY after the record's bytes are successfully
// written, so a marshal or I/O failure leaves no gap in the chain (which
// verification would otherwise report as tamper) and does not silently drop a
// record while claiming a higher sequence. The returned error lets the
// enforcement point fail closed ("audit is a control, not best-effort").
func (a *AuditLog) write(rec AuditRecord) error {
	if a == nil || a.w == nil {
		return nil
	}
	rec.Time = a.nowf()

	a.mu.Lock()
	defer a.mu.Unlock()

	// Build the candidate record against the NEXT sequence without committing
	// the cursor yet.
	nextSeq := a.seq + 1
	rec.Seq = nextSeq
	rec.PrevHash = a.prev
	h, _, err := chainHash(rec)
	if err != nil {
		return fmt.Errorf("audit: hash record: %w", err)
	}
	rec.Hash = h
	b, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("audit: marshal record: %w", err)
	}
	b = append(b, '\n')
	if n, err := a.w.Write(b); err != nil || n != len(b) {
		if err == nil {
			err = io.ErrShortWrite
		}
		return fmt.Errorf("audit: write record: %w", err)
	}

	// Commit: the record is durably queued, so advance the chain cursor.
	a.seq = nextSeq
	a.prev = h
	a.lastSeq, a.lastHash = rec.Seq, h
	if a.cp != nil {
		a.cp.add(rec.Seq, h)
	}
	return nil
}
