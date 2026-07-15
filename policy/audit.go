package policy

import (
	"encoding/json"
	"io"
	"sync"
)

// AuditRecord is one structured audit entry for a tool invocation.
type AuditRecord struct {
	Time     string `json:"time"`
	Backend  string `json:"backend"`
	Peer     string `json:"peer"`
	PeerKey  string `json:"peer_key,omitempty"`
	PeerAddr string `json:"peer_addr,omitempty"`
	Method   string `json:"method"`
	Tool     string `json:"tool,omitempty"`
	RPCID    string `json:"rpc_id,omitempty"`
	Decision string `json:"decision"` // "allow" | "deny"
	Rule     int    `json:"rule"`     // matching rule index, -1 for default
}

// AuditLog writes audit records as newline-delimited JSON to a sink.
type AuditLog struct {
	mu   sync.Mutex
	w    io.Writer
	nowf func() string // injectable clock for deterministic tests
}

// NewAuditLog writes records to w. now supplies timestamps; if nil, records
// carry an empty time (the caller can inject a real clock).
func NewAuditLog(w io.Writer, now func() string) *AuditLog {
	if now == nil {
		now = func() string { return "" }
	}
	return &AuditLog{w: w, nowf: now}
}

func (a *AuditLog) write(rec AuditRecord) {
	if a == nil || a.w == nil {
		return
	}
	rec.Time = a.nowf()
	b, err := json.Marshal(rec)
	if err != nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.w.Write(b)
	a.w.Write([]byte{'\n'})
}
