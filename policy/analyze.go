package policy

import (
	"bufio"
	"bytes"
	"encoding/json"
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
	Records  int          `json:"records"`
	Allowed  int          `json:"allowed"`
	Denied   int          `json:"denied"`
	Cosign   int          `json:"cosign"`
	Chain    VerifyResult `json:"chain"`
	Peers    []PeerStat   `json:"peers"`
	Tools    []ToolStat   `json:"tools"`
	Edges    []EdgeStat   `json:"edges"`
	Recent   []AuditRecord `json:"recent"` // most-recent-first, capped
	Backends []string      `json:"backends"`
	// BackendStats is the per-backend rollup (the "server tiles" of the room).
	BackendStats []BackendStat `json:"backend_stats"`
}

// Analyze reads an audit JSONL stream and builds a Summary: per-peer and
// per-tool rollups, the caller->tool call graph, the tail of recent events,
// and — crucially — the chain-verification verdict, so the dashboard shows at
// a glance whether the record it is displaying can be trusted. recentCap
// bounds the recent-events tail (<=0 uses 100).
func Analyze(r io.Reader, recentCap int) (Summary, error) {
	if recentCap <= 0 {
		recentCap = 100
	}
	var s Summary

	// Re-read for chain verification requires the whole stream, so buffer it.
	data, err := io.ReadAll(r)
	if err != nil {
		return s, err
	}
	s.Chain, _ = VerifyChain(bytes.NewReader(data))

	peers := map[string]*PeerStat{}
	tools := map[string]*ToolStat{}
	edges := map[string]*EdgeStat{}
	backends := map[string]bool{}
	bstats := map[string]*BackendStat{}
	bpeers := map[string]map[string]bool{} // backend -> distinct peer set
	var recent []AuditRecord

	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var rec AuditRecord
		if json.Unmarshal(line, &rec) != nil {
			continue
		}
		s.Records++
		switch rec.Decision {
		case "allow":
			s.Allowed++
		case "deny":
			s.Denied++
		case "cosign":
			s.Cosign++
		}
		if rec.Backend != "" {
			backends[rec.Backend] = true
			bs := bstats[rec.Backend]
			if bs == nil {
				bs = &BackendStat{Backend: rec.Backend}
				bstats[rec.Backend] = bs
				bpeers[rec.Backend] = map[string]bool{}
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
			bpeers[rec.Backend][rec.Peer+"\x00"+rec.PeerKey] = true
		}

		pk := rec.Peer + "\x00" + rec.PeerKey
		ps := peers[pk]
		if ps == nil {
			ps = &PeerStat{Peer: rec.Peer, PeerKey: rec.PeerKey}
			peers[pk] = ps
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
			ts := tools[rec.Tool]
			if ts == nil {
				ts = &ToolStat{Tool: rec.Tool}
				tools[rec.Tool] = ts
			}
			ts.Calls++
			if rec.Decision == "deny" {
				ts.Denied++
			} else {
				ts.Allowed++
			}

			ek := rec.Peer + "\x00" + rec.Tool + "\x00" + rec.Backend
			es := edges[ek]
			if es == nil {
				es = &EdgeStat{Peer: rec.Peer, Tool: rec.Tool, Backend: rec.Backend}
				edges[ek] = es
			}
			es.Calls++
			if rec.Decision == "deny" {
				es.Denied++
			}
		}

		recent = append(recent, rec)
		if len(recent) > recentCap {
			recent = recent[1:]
		}
	}
	if err := sc.Err(); err != nil {
		return s, err
	}

	for _, p := range peers {
		s.Peers = append(s.Peers, *p)
	}
	sort.Slice(s.Peers, func(i, j int) bool { return s.Peers[i].Calls > s.Peers[j].Calls })
	for _, t := range tools {
		s.Tools = append(s.Tools, *t)
	}
	sort.Slice(s.Tools, func(i, j int) bool { return s.Tools[i].Calls > s.Tools[j].Calls })
	for _, e := range edges {
		s.Edges = append(s.Edges, *e)
	}
	sort.Slice(s.Edges, func(i, j int) bool { return s.Edges[i].Calls > s.Edges[j].Calls })
	for b := range backends {
		s.Backends = append(s.Backends, b)
	}
	sort.Strings(s.Backends)
	for name, bs := range bstats {
		bs.Peers = len(bpeers[name])
		s.BackendStats = append(s.BackendStats, *bs)
	}
	sort.Slice(s.BackendStats, func(i, j int) bool { return s.BackendStats[i].Calls > s.BackendStats[j].Calls })

	// recent most-recent-first
	for i, j := 0, len(recent)-1; i < j; i, j = i+1, j-1 {
		recent[i], recent[j] = recent[j], recent[i]
	}
	s.Recent = recent
	return s, nil
}
