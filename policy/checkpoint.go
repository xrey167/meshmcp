package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sync"
)

// Anchor publishes a checkpoint to an external, independent witness (a
// transparency log, a notary, another org's mesh). Anchoring is what defends
// against an insider who controls the whole audit file AND the signing key:
// once a checkpoint head is witnessed elsewhere, they can no longer roll the
// log back to before it without the witness disagreeing.
type Anchor interface {
	Anchor(c Checkpoint) error
}

// AnchorRecord is one anchor-file line: a witness's commitment to a single
// checkpoint. Checkpoint is the anchored checkpoint's own hash (Checkpoint.Hash,
// which commits to span, Merkle root, chain head, prev-checkpoint link, signer
// key, and signature). PrevAnchor self-links the anchor file: it is the SHA-256
// (hex) of the previous line's exact JSON bytes (without the trailing newline),
// "" for the first line — so an edited or dropped anchor line breaks linkage.
// Signer is set by a witness that accepts checkpoints from peer gateways, naming
// the pinned signer key the record was verified against. Legacy anchor records
// (the pre-v1 format) lack v/prev_anchor and carried checkpoint_seq as a JSON
// string; verifiers accept them, but linkage is only enforced on records that
// carry it.
type AnchorRecord struct {
	V          int    `json:"v"`
	Seq        int    `json:"checkpoint_seq"`
	ChainHead  string `json:"chain_head"`
	Checkpoint string `json:"checkpoint"`
	Time       string `json:"time"`
	Signer     string `json:"signer,omitempty"`
	PrevAnchor string `json:"prev_anchor"`
}

// AnchorLineHash is the self-linkage hash of one anchor line: SHA-256 over the
// line's exact bytes without the trailing newline, hex encoded. The next
// record's PrevAnchor must equal it.
func AnchorLineHash(line []byte) string {
	sum := sha256.Sum256(line)
	return hex.EncodeToString(sum[:])
}

// FileAnchor appends each checkpoint to a separate append-only file — the
// simplest external witness. Records are self-linked via PrevAnchor, so the
// anchor file is itself tamper-evident. In production this is an RFC 6962 log,
// a notary API, or a peer gateway's anchor endpoint.
type FileAnchor struct {
	mu   sync.Mutex
	W    io.Writer
	prev string // AnchorLineHash of the last written line ("" for a fresh file)
}

// NewFileAnchor builds a FileAnchor whose next record links to prevAnchorHash —
// the AnchorLineHash of the existing file's last line, or "" for a new file —
// so restarts continue one self-linked witness chain.
func NewFileAnchor(w io.Writer, prevAnchorHash string) *FileAnchor {
	return &FileAnchor{W: w, prev: prevAnchorHash}
}

func (a *FileAnchor) Anchor(c Checkpoint) error {
	return a.append(c, "")
}

// Witness appends an anchor record on behalf of a witness that verified the
// checkpoint against the pinned signer key, recording that key in the line.
func (a *FileAnchor) Witness(c Checkpoint, signer string) error {
	return a.append(c, signer)
}

func (a *FileAnchor) append(c Checkpoint, signer string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	rec := AnchorRecord{
		V:          1,
		Seq:        c.Seq,
		ChainHead:  c.ChainHead,
		Checkpoint: c.Hash(),
		Time:       c.Time,
		Signer:     signer,
		PrevAnchor: a.prev,
	}
	b, _ := json.Marshal(rec)
	if _, err := a.W.Write(append(b, '\n')); err != nil {
		return err
	}
	a.prev = AnchorLineHash(b)
	return nil
}

// Checkpointer batches record hashes and, every N records (and on Flush),
// emits a signed Merkle checkpoint to its sink and optional anchor.
type Checkpointer struct {
	signer  *Signer
	w       io.Writer
	anchor  Anchor
	every   int
	now     func() string
	onError func(error) // optional: surface a checkpoint/anchor I/O failure

	mu      sync.Mutex
	leaves  [][]byte
	fromSeq int
	cpSeq   int
	prevCP  string
}

// NewCheckpointer writes signed checkpoints to w, one every `every` records
// (<=0 defaults to 128). anchor may be nil.
func NewCheckpointer(signer *Signer, w io.Writer, every int, now func() string, anchor Anchor) *Checkpointer {
	if every <= 0 {
		every = 128
	}
	if now == nil {
		now = func() string { return "" }
	}
	return &Checkpointer{signer: signer, w: w, anchor: anchor, every: every, now: now}
}

// WithErrorHandler surfaces checkpoint/anchor I/O failures (otherwise swallowed)
// so a caller can log or alert on them — the anchor is the one control that
// defends against an insider, so a silent anchor failure is dangerous.
func (c *Checkpointer) WithErrorHandler(fn func(error)) *Checkpointer {
	c.onError = fn
	return c
}

func (c *Checkpointer) reportErr(err error) {
	if err != nil && c.onError != nil {
		c.onError(err)
	}
}

// add records a leaf (a record's hash bytes) at seq; it flushes a checkpoint
// when the batch reaches the interval. chainHead is the record's hash hex.
func (c *Checkpointer) add(seq int, hashHex string) {
	if c == nil {
		return
	}
	raw, err := hex.DecodeString(hashHex)
	if err != nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fromSeq == 0 {
		c.fromSeq = seq
	}
	c.leaves = append(c.leaves, raw)
	if len(c.leaves) >= c.every {
		c.flushLocked(seq, hashHex)
	}
}

// Add records a record's hash (hex) at seq into the current checkpoint batch,
// emitting a signed checkpoint when the batch reaches the interval. It is the
// exported entry point for hash-chained logs outside this package — e.g. the
// pubsub event log — that want the same signed Merkle checkpoints.
func (c *Checkpointer) Add(seq int, hashHex string) { c.add(seq, hashHex) }

// SeedFrom resumes a checkpoint chain after a restart: the next emitted
// checkpoint takes ordinal cpSeq+1 and links to prevCPHash. Seed it from the
// tail of an existing checkpoints file so restarts continue one verifiable
// chain of checkpoints.
func (c *Checkpointer) SeedFrom(cpSeq int, prevCPHash string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cpSeq = cpSeq
	c.prevCP = prevCPHash
}

// Flush emits a checkpoint for any buffered records. lastSeq/lastHash identify
// the final record; if nothing is buffered it is a no-op.
func (c *Checkpointer) Flush(lastSeq int, lastHash string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.leaves) == 0 {
		return
	}
	c.flushLocked(lastSeq, lastHash)
}

func (c *Checkpointer) flushLocked(toSeq int, chainHead string) {
	root := MerkleRoot(c.leaves)
	c.cpSeq++
	cp := Checkpoint{
		Version:    1,
		Seq:        c.cpSeq,
		FromSeq:    c.fromSeq,
		ToSeq:      toSeq,
		Count:      len(c.leaves),
		MerkleRoot: hex.EncodeToString(root[:]),
		ChainHead:  chainHead,
		PrevCP:     c.prevCP,
		Time:       c.now(),
	}
	cp = c.signer.sign(cp)
	b, err := json.Marshal(cp)
	if err != nil {
		// The checkpoint could not be produced. Do NOT advance prevCP or clear
		// the leaves: rolling the state forward here would drop this batch from
		// all signed-checkpoint coverage and link the next checkpoint's PrevCP
		// to one absent from the file. Retain the batch so the next flush
		// retries exactly these records, keeping coverage contiguous.
		c.cpSeq--
		c.reportErr(fmt.Errorf("checkpoint marshal: %w", err))
		return
	}
	b = append(b, '\n')
	if n, werr := c.w.Write(b); werr != nil || n != len(b) {
		if werr == nil {
			werr = io.ErrShortWrite
		}
		c.cpSeq--
		c.reportErr(fmt.Errorf("checkpoint write: %w", werr))
		return
	}
	// The checkpoint is durably written; the anchor is a best-effort external
	// witness, so an anchor failure is reported but does not un-commit the
	// checkpoint that already landed in the file.
	if c.anchor != nil {
		if aerr := c.anchor.Anchor(cp); aerr != nil {
			c.reportErr(fmt.Errorf("checkpoint anchor: %w", aerr))
		}
	}
	c.prevCP = cp.Hash()
	c.leaves = c.leaves[:0]
	c.fromSeq = 0
}
