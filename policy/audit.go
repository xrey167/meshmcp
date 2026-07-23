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
	Rule     int    `json:"rule"`           // matching rule index, -1 for default
	Cost     int    `json:"cost,omitempty"` // cost/quota units this call consumed (F29)

	// Provenance carries the content refs (e.g. retrieved document / triple
	// hashes) that produced an answer — a signed provenance receipt for
	// verifiable AI answers. Optional and omitempty, so it is covered by the
	// hash chain and signed checkpoints without changing existing records.
	Provenance []string `json:"provenance,omitempty"`

	// Tamper-evidence chain (always present once written).
	Seq      int    `json:"seq"`
	PrevHash string `json:"prev_hash"`
	Hash     string `json:"hash,omitempty"`

	// PeerSpiffeID is a derived, additive SPIFFE identity label (Feature A);
	// appended after Hash (never inserted) so the hash chain for existing
	// deployments is unaffected by its addition. Emitted from exactly two
	// places: Filter.record (local gateway path, from Caller.SpiffeID, derived
	// via Config.TrustDomain) plus the httpEnforcer equivalent, and
	// federation/boundary.go crossings (from Mapping.TrustDomain). Those trust
	// domains are deliberately separate — a local record never carries a
	// federation org's domain, and vice versa. A label only: enforcement keys
	// on PeerKey, never on this field. See docs/spec/OAUTH-STANDARDS.md
	// Feature A and docs/spec/AUDIT-RECORD.md §1.1/§1.4.
	PeerSpiffeID SpiffeLabel `json:"peer_spiffe_id,omitempty"`

	// SchemaVersion self-describes the record's on-disk format so a log written
	// by a newer build (a future incompatible format) is refused by an older one
	// rather than silently misread — VerifyChain/VerifyForRepair fail closed on a
	// version they do not understand. Additive and omitempty: a record from before
	// this field existed decodes as 0 (treated as the current version), so its
	// bytes — and therefore its hash — are unchanged, and existing chains keep
	// verifying. Written records carry the current version; the chain covers it
	// like any other field.
	SchemaVersion int `json:"schema_version,omitempty"`
}

// auditSchemaVersion is the current audit-record on-disk format version. A
// record whose SchemaVersion exceeds this was written by a newer build and is
// refused (fail closed) rather than misinterpreted. A record with version 0 (or
// the field absent) predates versioning and is accepted as the current version.
const auditSchemaVersion = 1

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

	failClosed bool        // when set, a failed write is surfaced to deny the call
	sync       bool        // when set, fsync each record so it survives power loss
	secondary  []AuditSink // observer sinks (SIEM, webhook, OTel) — best-effort
}

// AuditSink receives finalized audit records. *AuditLog is the primary sink
// (the tamper-evident hash chain); plugins can register additional observer
// sinks (a SIEM, a webhook, an OTel exporter) via AuditLog.AddSink. Observer
// sinks see each record AFTER it commits to the chain and their errors never
// affect the call — the chain, not the observer, is the control.
type AuditSink interface {
	Append(rec AuditRecord) error
}

// AddSink registers an observer sink that receives every committed record. It
// is not safe to call concurrently with writes; register sinks at setup time.
func (a *AuditLog) AddSink(s AuditSink) *AuditLog {
	if s != nil {
		a.secondary = append(a.secondary, s)
	}
	return a
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

// WithSync makes each committed record durable before write returns: after the
// record is written and the chain cursor advances, the underlying sink is
// fsync'd (when it supports Sync — a real *os.File does; test buffers/pipes do
// not, and are silently skipped). Without it, a committed record survives a
// process crash (it is in the page cache) but not power loss. A sink whose
// Sync fails is surfaced like a write failure, so a fail-closed enforcement
// point denies the call rather than proceed on a record it could not make
// durable. On by default at the production call sites (opt out via config);
// off for the raw NewAuditLog constructor so tests and in-memory sinks are
// unaffected. It costs one fsync per audited decision — see the throughput note
// where it is wired.
func (a *AuditLog) WithSync(on bool) *AuditLog {
	a.sync = on
	return a
}

// WithCheckpointer attaches a signed-checkpoint sink: the log periodically
// emits an Ed25519-signed Merkle commitment over its records, making it
// non-repudiable and externally verifiable. Call Flush before shutdown to seal
// the final partial batch.
func (a *AuditLog) WithCheckpointer(cp *Checkpointer) *AuditLog {
	a.cp = cp
	return a
}

// Flush seals any buffered records into a final checkpoint. Nil-safe (like
// write), so shutdown paths can flush an optional log unconditionally.
func (a *AuditLog) Flush() {
	if a == nil {
		return
	}
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

// maxReasonBytes bounds the audit record's free-form Reason so no single record
// can approach the verifier's 16 MiB line cap.
const maxReasonBytes = 8192

// maxFieldBytes bounds the other caller-influenced free-form fields (Tool,
// Method, RPCID) taken verbatim from the JSON-RPC line. Without a cap, a peer
// could send a tools/call with a multi-megabyte name; the (even denied)
// record would then exceed the verifier's 16 MiB scanner buffer, making the
// whole hash chain unverifiable and wedging the gateway on the next restart
// (seedAuditFromExisting re-verifies the file). Kept well under the line cap.
const maxFieldBytes = 4096

// clipField truncates s to at most maxFieldBytes, marking the truncation so a
// reader knows the value is not the original. Truncation must happen before the
// record is hashed so the hash covers exactly what is written.
func clipField(s string) string {
	if len(s) > maxFieldBytes {
		return s[:maxFieldBytes] + "…(truncated)"
	}
	return s
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
	// Bound the one free-form field so a single record can never approach the
	// 16 MiB line cap the verifier (chain.go) and analyzer read with — an
	// over-long record would otherwise be unverifiable. Truncation happens
	// before hashing, so the hash covers exactly what is written.
	if len(rec.Reason) > maxReasonBytes {
		rec.Reason = rec.Reason[:maxReasonBytes] + "…(truncated)"
	}
	// The remaining caller-influenced fields come verbatim from the JSON-RPC
	// line (Tool = params.name, Method, RPCID = id) and are otherwise unbounded.
	rec.Tool = clipField(rec.Tool)
	rec.Method = clipField(rec.Method)
	rec.RPCID = clipField(rec.RPCID)

	// Self-describe the record's format so a future incompatible format is
	// refused by an older verifier rather than misread. Set before hashing so the
	// chain covers it.
	rec.SchemaVersion = auditSchemaVersion

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

	// Commit: the record is written, so advance the chain cursor. (The cursor
	// advances BEFORE the fsync below so a fsync failure cannot desync the
	// in-memory cursor from the record already on disk — the record is part of
	// the chain; fsync only concerns its power-loss durability.)
	a.seq = nextSeq
	a.prev = h
	a.lastSeq, a.lastHash = rec.Seq, h
	if a.cp != nil {
		a.cp.add(rec.Seq, h)
	}
	// Durability: fsync the committed record when enabled and the sink supports
	// it. A Sync failure is surfaced (fail-closed denies the call) rather than
	// silently accepting a record we could not make durable.
	if a.sync {
		if f, ok := a.w.(interface{ Sync() error }); ok {
			if err := f.Sync(); err != nil {
				return fmt.Errorf("audit: fsync record: %w", err)
			}
		}
	}
	// Fan out to observer sinks (best-effort — the chain above is the control).
	for _, s := range a.secondary {
		_ = s.Append(rec)
	}
	return nil
}
