package policy

import (
	"encoding/hex"
	"encoding/json"
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

// FileAnchor appends each checkpoint to a separate append-only file — the
// simplest external witness. In production this is an RFC 6962 log, a notary
// API, or a peer gateway's anchor endpoint.
type FileAnchor struct {
	mu sync.Mutex
	W  io.Writer
}

func (a *FileAnchor) Anchor(c Checkpoint) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	rec := map[string]string{
		"checkpoint_seq": itoaCP(c.Seq),
		"chain_head":     c.ChainHead,
		"checkpoint":     c.Hash(),
		"time":           c.Time,
	}
	b, _ := json.Marshal(rec)
	_, err := a.W.Write(append(b, '\n'))
	return err
}

// Checkpointer batches record hashes and, every N records (and on Flush),
// emits a signed Merkle checkpoint to its sink and optional anchor.
type Checkpointer struct {
	signer *Signer
	w      io.Writer
	anchor Anchor
	every  int
	now    func() string

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
	if err == nil {
		c.w.Write(b)
		c.w.Write([]byte{'\n'})
	}
	if c.anchor != nil {
		_ = c.anchor.Anchor(cp)
	}
	c.prevCP = cp.Hash()
	c.leaves = c.leaves[:0]
	c.fromSeq = 0
}

func itoaCP(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}
