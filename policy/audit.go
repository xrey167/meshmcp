package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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
// to contribute to the same tamper-evident log.
func (a *AuditLog) Append(rec AuditRecord) { a.write(rec) }

func (a *AuditLog) write(rec AuditRecord) {
	if a == nil || a.w == nil {
		return
	}
	rec.Time = a.nowf()

	a.mu.Lock()
	defer a.mu.Unlock()

	a.seq++
	rec.Seq = a.seq
	rec.PrevHash = a.prev
	h, _, err := chainHash(rec)
	if err != nil {
		return
	}
	rec.Hash = h
	b, err := json.Marshal(rec)
	if err != nil {
		return
	}
	a.prev = h
	a.w.Write(b)
	a.w.Write([]byte{'\n'})
}
