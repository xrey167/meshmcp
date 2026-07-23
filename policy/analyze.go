package policy

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
)

// PeerStat aggregates one caller identity's activity in an audit log.
type PeerStat struct {
	Peer     string `json:"peer"`
	PeerKey  string `json:"peer_key,omitempty"`
	Calls    int    `json:"calls"`
	Allowed  int    `json:"allowed"`
	Denied   int    `json:"denied"`
	Cosign   int    `json:"cosign"`
	LastSeen string `json:"last_seen,omitempty"` // timestamp of the most recent record
	LastTool string `json:"last_tool,omitempty"`
}

// BackendStat aggregates activity against one backend (MCP server).
type BackendStat struct {
	Backend  string `json:"backend"`
	Calls    int    `json:"calls"`
	Allowed  int    `json:"allowed"`
	Denied   int    `json:"denied"`
	Cosign   int    `json:"cosign"`
	Peers    int    `json:"peers"` // distinct callers
	LastSeen string `json:"last_seen,omitempty"`
}

// ToolStat aggregates one tool's usage across all callers.
type ToolStat struct {
	Tool    string `json:"tool"`
	Calls   int    `json:"calls"`
	Allowed int    `json:"allowed"`
	Denied  int    `json:"denied"`
}

// EdgeStat is one caller->tool edge of the call graph.
type EdgeStat struct {
	Peer    string `json:"peer"`
	Tool    string `json:"tool"`
	Backend string `json:"backend"`
	Calls   int    `json:"calls"`
	Denied  int    `json:"denied"`
}

// Summary is the analyzed view of an audit log for the dashboard.
type Summary struct {
	Records  int           `json:"records"`
	Allowed  int           `json:"allowed"`
	Denied   int           `json:"denied"`
	Cosign   int           `json:"cosign"`
	Chain    VerifyResult  `json:"chain"`
	Peers    []PeerStat    `json:"peers"`
	Tools    []ToolStat    `json:"tools"`
	Edges    []EdgeStat    `json:"edges"`
	Recent   []AuditRecord `json:"recent"` // most-recent-first, capped
	Backends []string      `json:"backends"`
	// BackendStats is the per-backend rollup (the "server tiles" of the room).
	BackendStats []BackendStat `json:"backend_stats"`
}

// Accumulator folds audit JSONL lines into running rollups plus an incremental
// chain-verification verdict, so a live consumer (the dashboard) can feed only
// NEW lines on each poll instead of re-reading the whole file (S21). Analyze is
// the one-shot wrapper over the same fold. Not safe for concurrent use.
type Accumulator struct {
	recentCap int

	records, allowed, denied, cosign int

	peers    map[string]*PeerStat
	tools    map[string]*ToolStat
	edges    map[string]*EdgeStat
	backends map[string]bool
	bstats   map[string]*BackendStat
	bpeers   map[string]map[string]bool // backend -> distinct peer set
	recent   []AuditRecord

	// Incremental chain verification (mirrors VerifyChain record-by-record;
	// once broken it stays broken, while stats keep folding — same behavior as
	// running VerifyChain and the stats scan separately over the full stream).
	chainPrev   string
	chainSeq    int
	chainCount  int
	chainBroken bool
	chainBreak  int
	chainReason string
}

// NewAccumulator returns an empty accumulator. recentCap bounds the
// recent-events tail (<=0 uses 100).
func NewAccumulator(recentCap int) *Accumulator {
	if recentCap <= 0 {
		recentCap = 100
	}
	return &Accumulator{
		recentCap: recentCap,
		peers:     map[string]*PeerStat{},
		tools:     map[string]*ToolStat{},
		edges:     map[string]*EdgeStat{},
		backends:  map[string]bool{},
		bstats:    map[string]*BackendStat{},
		bpeers:    map[string]map[string]bool{},
	}
}

// AddLine folds one JSONL line (blank lines are ignored; a trailing newline is
// tolerated) into the rollups and the chain verdict.
func (a *Accumulator) AddLine(line []byte) {
	line = bytes.TrimSpace(line)
	if len(line) == 0 {
		return
	}
	var rec AuditRecord
	parseErr := json.Unmarshal(line, &rec)

	// Chain leg (counts and checks every non-blank line until the first break).
	if !a.chainBroken {
		a.chainCount++
		a.checkChain(rec, parseErr)
	}

	// Stats leg (skips unparsable lines, like the original scan).
	if parseErr != nil {
		return
	}
	a.fold(rec)
}

// checkChain applies VerifyChain's per-record checks to the next record.
func (a *Accumulator) checkChain(rec AuditRecord, parseErr error) {
	expectSeq := a.chainSeq + 1
	fail := func(seq int, reason string) {
		a.chainBroken = true
		a.chainBreak = seq
		a.chainReason = reason
	}
	if parseErr != nil {
		fail(expectSeq, fmt.Sprintf("record %d is not valid JSON: %v", expectSeq, parseErr))
		return
	}
	if rec.SchemaVersion > auditSchemaVersion {
		fail(expectSeq, fmt.Sprintf("record %d has schema version %d, newer than this build supports (%d) — upgrade meshmcp", expectSeq, rec.SchemaVersion, auditSchemaVersion))
		return
	}
	if rec.Seq != expectSeq {
		fail(rec.Seq, fmt.Sprintf("record #%d has seq %d (expected %d): a record was inserted or removed", a.chainCount, rec.Seq, expectSeq))
		return
	}
	if rec.PrevHash != a.chainPrev {
		fail(rec.Seq, fmt.Sprintf("record seq %d prev_hash %q does not link to prior hash %q", rec.Seq, short(rec.PrevHash), short(a.chainPrev)))
		return
	}
	want, _, err := chainHash(rec)
	if err != nil {
		fail(rec.Seq, fmt.Sprintf("record seq %d could not be re-hashed: %v", rec.Seq, err))
		return
	}
	if rec.Hash != want {
		fail(rec.Seq, fmt.Sprintf("record seq %d was edited: stored hash %q != recomputed %q", rec.Seq, short(rec.Hash), short(want)))
		return
	}
	a.chainPrev = rec.Hash
	a.chainSeq = expectSeq
}

// fold merges one parsed record into the rollups.
func (a *Accumulator) fold(rec AuditRecord) {
	a.records++
	switch rec.Decision {
	case "allow":
		a.allowed++
	case "deny":
		a.denied++
	case "cosign":
		a.cosign++
	}
	if rec.Backend != "" {
		a.backends[rec.Backend] = true
		bs := a.bstats[rec.Backend]
		if bs == nil {
			bs = &BackendStat{Backend: rec.Backend}
			a.bstats[rec.Backend] = bs
			a.bpeers[rec.Backend] = map[string]bool{}
		}
		bs.Calls++
		switch rec.Decision {
		case "allow":
			bs.Allowed++
		case "deny":
			bs.Denied++
		case "cosign":
			bs.Cosign++
		}
		if rec.Time != "" && rec.Time >= bs.LastSeen {
			bs.LastSeen = rec.Time
		}
		a.bpeers[rec.Backend][rec.Peer+"\x00"+rec.PeerKey] = true
	}

	pk := rec.Peer + "\x00" + rec.PeerKey
	ps := a.peers[pk]
	if ps == nil {
		ps = &PeerStat{Peer: rec.Peer, PeerKey: rec.PeerKey}
		a.peers[pk] = ps
	}
	ps.Calls++
	switch rec.Decision {
	case "allow":
		ps.Allowed++
	case "deny":
		ps.Denied++
	case "cosign":
		ps.Cosign++
	}
	if rec.Time != "" && rec.Time >= ps.LastSeen {
		ps.LastSeen = rec.Time
		if rec.Tool != "" {
			ps.LastTool = rec.Tool
		}
	}

	if rec.Tool != "" {
		ts := a.tools[rec.Tool]
		if ts == nil {
			ts = &ToolStat{Tool: rec.Tool}
			a.tools[rec.Tool] = ts
		}
		ts.Calls++
		if rec.Decision == "deny" {
			ts.Denied++
		} else {
			ts.Allowed++
		}

		ek := rec.Peer + "\x00" + rec.Tool + "\x00" + rec.Backend
		es := a.edges[ek]
		if es == nil {
			es = &EdgeStat{Peer: rec.Peer, Tool: rec.Tool, Backend: rec.Backend}
			a.edges[ek] = es
		}
		es.Calls++
		if rec.Decision == "deny" {
			es.Denied++
		}
	}

	a.recent = append(a.recent, rec)
	if len(a.recent) > a.recentCap {
		a.recent = a.recent[1:]
	}
}

// Summary snapshots the current rollups as a sorted Summary. The accumulator
// keeps folding after a snapshot; the snapshot does not alias internal state.
func (a *Accumulator) Summary() Summary {
	s := Summary{
		Records: a.records, Allowed: a.allowed, Denied: a.denied, Cosign: a.cosign,
	}
	s.Chain = VerifyResult{Count: a.chainCount}
	if a.chainBroken {
		s.Chain.BreakSeq = a.chainBreak
		s.Chain.Reason = a.chainReason
	} else {
		s.Chain.OK = true
		s.Chain.LastHash = a.chainPrev
	}

	for _, p := range a.peers {
		s.Peers = append(s.Peers, *p)
	}
	sort.Slice(s.Peers, func(i, j int) bool { return s.Peers[i].Calls > s.Peers[j].Calls })
	for _, t := range a.tools {
		s.Tools = append(s.Tools, *t)
	}
	sort.Slice(s.Tools, func(i, j int) bool { return s.Tools[i].Calls > s.Tools[j].Calls })
	for _, e := range a.edges {
		s.Edges = append(s.Edges, *e)
	}
	sort.Slice(s.Edges, func(i, j int) bool { return s.Edges[i].Calls > s.Edges[j].Calls })
	for b := range a.backends {
		s.Backends = append(s.Backends, b)
	}
	sort.Strings(s.Backends)
	for name, bs := range a.bstats {
		cp := *bs
		cp.Peers = len(a.bpeers[name])
		s.BackendStats = append(s.BackendStats, cp)
	}
	sort.Slice(s.BackendStats, func(i, j int) bool { return s.BackendStats[i].Calls > s.BackendStats[j].Calls })

	// recent most-recent-first (copy, so the ring keeps appending in order).
	s.Recent = make([]AuditRecord, len(a.recent))
	for i, r := range a.recent {
		s.Recent[len(a.recent)-1-i] = r
	}
	return s
}

// Analyze reads an audit JSONL stream and builds a Summary: per-peer and
// per-tool rollups, the caller->tool call graph, the tail of recent events,
// and — crucially — the chain-verification verdict, so the dashboard shows at
// a glance whether the record it is displaying can be trusted. recentCap
// bounds the recent-events tail (<=0 uses 100). It is the one-shot form of
// Accumulator; a live consumer holds an Accumulator and feeds only new lines.
func Analyze(r io.Reader, recentCap int) (Summary, error) {
	acc := NewAccumulator(recentCap)
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for sc.Scan() {
		acc.AddLine(sc.Bytes())
	}
	if err := sc.Err(); err != nil {
		return Summary{}, err
	}
	return acc.Summary(), nil
}
