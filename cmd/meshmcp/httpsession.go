package main

import (
	"sync"
	"time"

	"github.com/xrey167/meshmcp/policy"
)

// mcpSessionHeader is the MCP Streamable HTTP session header. The gateway
// reads it to key per-session taint state; it otherwise transits opaquely.
const mcpSessionHeader = "Mcp-Session-Id"

// Bounds for the HTTP enforcer's per-session state. On a cap the affected
// call is DENIED — never evicted, because evicting a label set would silently
// de-taint a live session (fail open). Idle expiry approximates the stdio
// analogue (labels there live for the connection's lifetime).
const (
	httpSessionMaxIDLen   = 512
	httpSessionsPerPeer   = 256
	httpSessionsGlobal    = 65536
	httpSessionIdleTTL    = 24 * time.Hour
	httpSessionSweepEvery = time.Minute
	// httpRedactorMaxValues caps the distinct secret values remembered per
	// peer for response scrubbing. An injection that would exceed it is
	// DENIED (a value we cannot remember cannot be scrubbed — fail closed).
	httpRedactorMaxValues = 1024
)

// labelState is one (peer, session)'s accumulated data-flow labels.
type labelState struct {
	labels   map[string]bool
	lastSeen time.Time
}

// peerRedactor is one peer's response redactor plus its idle cursor.
type peerRedactor struct {
	red     *policy.Redactor
	lastUse time.Time
}

// httpSessionStore holds the Streamable-HTTP enforcer's per-session taint
// labels and per-peer response redactors.
//
// Labels are keyed by (peerKey, sessionID): the session id is a
// CLIENT-SUPPLIED header, so the transport-proven peer key must be part of the
// key — one peer can never read or poison another peer's session labels by
// guessing its id.
//
// Redactors are keyed by peerKey ONLY (not session): a client that injected a
// secret under one session id could otherwise fetch the echo header-less or
// under a fresh id and evade a session-scoped redactor, and per-peer (not
// global) scoping prevents a cross-peer probe oracle (peer B echoing a guessed
// string to learn whether peer A's credential matches). This is strictly a
// superset of stdio's per-connection redactor scope: over-redaction only.
type httpSessionStore struct {
	mu        sync.Mutex
	now       func() time.Time
	perPeer   int
	global    int
	idleTTL   time.Duration
	redCap    int
	lastSweep time.Time
	labels    map[string]map[string]*labelState // peerKey -> sessionID -> state
	redactors map[string]*peerRedactor          // peerKey -> redactor
}

func newHTTPSessionStore(now func() time.Time) *httpSessionStore {
	if now == nil {
		now = time.Now
	}
	return &httpSessionStore{
		now:       now,
		perPeer:   httpSessionsPerPeer,
		global:    httpSessionsGlobal,
		idleTTL:   httpSessionIdleTTL,
		redCap:    httpRedactorMaxValues,
		labels:    map[string]map[string]*labelState{},
		redactors: map[string]*peerRedactor{},
	}
}

// validSessionID reports whether sid is a usable Mcp-Session-Id: non-empty,
// bounded, and visible ASCII (0x21-0x7E), the character set the MCP spec
// allows for session ids. Anything else on a governed call is denied.
func validSessionID(sid string) bool {
	if sid == "" || len(sid) > httpSessionMaxIDLen {
		return false
	}
	for i := 0; i < len(sid); i++ {
		if sid[i] < 0x21 || sid[i] > 0x7e {
			return false
		}
	}
	return true
}

// sweepLocked drops idle label entries and redactors, at most once per
// httpSessionSweepEvery. Caller holds s.mu.
func (s *httpSessionStore) sweepLocked() {
	now := s.now()
	if now.Sub(s.lastSweep) < httpSessionSweepEvery {
		return
	}
	s.lastSweep = now
	for pk, sess := range s.labels {
		for id, st := range sess {
			if now.Sub(st.lastSeen) > s.idleTTL {
				delete(sess, id)
			}
		}
		if len(sess) == 0 {
			delete(s.labels, pk)
		}
	}
	for pk, pr := range s.redactors {
		if now.Sub(pr.lastUse) > s.idleTTL {
			delete(s.redactors, pk)
		}
	}
}

// ensure creates or touches the (peerKey, sid) label entry, enforcing the
// per-peer and global caps. ok=false (with a denial reason) means the caller
// must deny the governed call — capacity is never made by evicting another
// session's labels.
func (s *httpSessionStore) ensure(peerKey, sid string) (ok bool, reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked()
	sess := s.labels[peerKey]
	if st := sess[sid]; st != nil {
		st.lastSeen = s.now()
		return true, ""
	}
	if len(sess) >= s.perPeer {
		return false, "session-state capacity for this peer is exhausted (labels cannot be tracked for a new session; retry after idle sessions expire)"
	}
	total := 0
	for _, m := range s.labels {
		total += len(m)
	}
	if total >= s.global {
		return false, "gateway session-state capacity is exhausted (labels cannot be tracked for a new session)"
	}
	if sess == nil {
		sess = map[string]*labelState{}
		s.labels[peerKey] = sess
	}
	sess[sid] = &labelState{labels: map[string]bool{}, lastSeen: s.now()}
	return true, ""
}

// snapshot copies the (peerKey, sid) label set for a decision (nil when empty
// or unknown, matching the stdio filter's labelSnapshot).
func (s *httpSessionStore) snapshot(peerKey, sid string) map[string]bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.labels[peerKey][sid]
	if st == nil || len(st.labels) == 0 {
		return nil
	}
	out := make(map[string]bool, len(st.labels))
	for k := range st.labels {
		out[k] = true
	}
	return out
}

// addLabels records labels an allowed call contributed to the session.
func (s *httpSessionStore) addLabels(peerKey, sid string, ls []string) {
	if len(ls) == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.labels[peerKey][sid]
	if st == nil {
		return
	}
	st.lastSeen = s.now()
	for _, l := range ls {
		st.labels[l] = true
	}
}

// drop removes the (peerKey, sid) label entry — the spec session-teardown
// DELETE frees its state (a fresh session starts label-clean, like a stdio
// reconnect).
func (s *httpSessionStore) drop(peerKey, sid string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess := s.labels[peerKey]
	delete(sess, sid)
	if len(sess) == 0 {
		delete(s.labels, peerKey)
	}
}

// redactorFor returns the peer's redactor, creating it on first use
// (injection path).
func (s *httpSessionStore) redactorFor(peerKey string) *policy.Redactor {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked()
	pr := s.redactors[peerKey]
	if pr == nil {
		pr = &peerRedactor{red: &policy.Redactor{}}
		s.redactors[peerKey] = pr
	}
	pr.lastUse = s.now()
	return pr.red
}

// lookupRedactor returns the peer's redactor if one exists (response path),
// never creating one — a peer that never had a secret injected pays nothing.
func (s *httpSessionStore) lookupRedactor(peerKey string) *policy.Redactor {
	s.mu.Lock()
	defer s.mu.Unlock()
	pr := s.redactors[peerKey]
	if pr == nil {
		return nil
	}
	pr.lastUse = s.now()
	return pr.red
}
