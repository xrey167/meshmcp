package edge

import (
	"encoding/json"
	"sync"
	"time"
)

// mcpSession is one Streamable-HTTP session, bound to the OAuth client and grant
// family that created it — the analogue of the resumable transport's creatorKey
// binding. A request presenting a session owned by a different client or family
// is rejected (404), and revoking the client tears its sessions down.
type mcpSession struct {
	id       string
	clientID string
	familyID string
	bridge   *bridge

	mu       sync.Mutex
	sse      chan sseEvent // non-nil while a GET stream is attached
	lastSeen time.Time
}

// sseEvent is one server-sent event queued for a session's live stream.
type sseEvent struct {
	event string
	data  []byte
}

// sessionTable holds live sessions in memory (v1: not persisted; a restart makes
// clients re-initialize, which the MCP spec requires them to handle).
type sessionTable struct {
	mu       sync.Mutex
	byID     map[string]*mcpSession
	perLimit int
	bufLimit int
	now      func() time.Time
}

func newSessionTable(maxPerClient, bufLimit int, now func() time.Time) *sessionTable {
	return &sessionTable{
		byID:     map[string]*mcpSession{},
		perLimit: maxPerClient,
		bufLimit: bufLimit,
		now:      now,
	}
}

// create registers a new session for (clientID, familyID) with an attached
// bridge. It enforces the per-client session cap, evicting nothing — the caller
// gets ok=false when the cap is reached.
func (t *sessionTable) create(clientID, familyID string, br *bridge) (*mcpSession, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	n := 0
	for _, s := range t.byID {
		if s.clientID == clientID {
			n++
		}
	}
	if t.perLimit > 0 && n >= t.perLimit {
		return nil, false
	}
	s := &mcpSession{
		id:       randHex(16),
		clientID: clientID,
		familyID: familyID,
		bridge:   br,
		lastSeen: t.now(),
	}
	t.byID[s.id] = s
	return s, true
}

// get returns the session for id iff it is owned by clientID (family match is
// checked by the caller against the presented token's family). A mismatch
// returns nil so the handler can 404 — never leak another client's session.
func (t *sessionTable) get(id, clientID string) *mcpSession {
	t.mu.Lock()
	defer t.mu.Unlock()
	s := t.byID[id]
	if s == nil || s.clientID != clientID {
		return nil
	}
	s.lastSeen = t.now()
	return s
}

// delete removes and closes a session.
func (t *sessionTable) delete(id string) {
	t.mu.Lock()
	s := t.byID[id]
	delete(t.byID, id)
	t.mu.Unlock()
	if s != nil {
		s.detachStream()
		s.bridge.close()
	}
}

// deleteFamily tears down every session belonging to a revoked token family (or
// a revoked client). Returns the number torn down.
func (t *sessionTable) deleteFamily(familyID string) int {
	t.mu.Lock()
	var victims []*mcpSession
	for id, s := range t.byID {
		if s.familyID == familyID {
			victims = append(victims, s)
			delete(t.byID, id)
		}
	}
	t.mu.Unlock()
	for _, s := range victims {
		s.detachStream()
		s.bridge.close()
	}
	return len(victims)
}

// deleteClient tears down every session belonging to a client.
func (t *sessionTable) deleteClient(clientID string) int {
	t.mu.Lock()
	var victims []*mcpSession
	for id, s := range t.byID {
		if s.clientID == clientID {
			victims = append(victims, s)
			delete(t.byID, id)
		}
	}
	t.mu.Unlock()
	for _, s := range victims {
		s.detachStream()
		s.bridge.close()
	}
	return len(victims)
}

// reap closes and removes every session idle (no request) for longer than ttl,
// freeing its backend bridge and its per-client slot. Returns the count reaped.
// A restart-safe, bounded alternative to relying on explicit DELETE — a client
// that abandons a session (or hit its cap and vanished) no longer pins a bridge
// forever. ttl <= 0 disables reaping.
func (t *sessionTable) reap(ttl time.Duration) int {
	if ttl <= 0 {
		return 0
	}
	cutoff := t.now().Add(-ttl)
	t.mu.Lock()
	var victims []*mcpSession
	// lastSeen is written under t.mu (create/get), so read it under t.mu too.
	for id, s := range t.byID {
		if s.lastSeen.Before(cutoff) {
			victims = append(victims, s)
			delete(t.byID, id)
		}
	}
	t.mu.Unlock()
	for _, s := range victims {
		s.detachStream()
		s.bridge.close()
	}
	return len(victims)
}

// attachStream opens the session's single SSE channel and routes backend
// notifications onto it. A second GET replaces the first (spec MAY).
func (s *mcpSession) attachStream(buf int) chan sseEvent {
	s.mu.Lock()
	if s.sse != nil {
		close(s.sse)
	}
	ch := make(chan sseEvent, buf)
	s.sse = ch
	s.mu.Unlock()

	s.bridge.setNotifyHandler(func(method string, params json.RawMessage) {
		env, _ := json.Marshal(map[string]json.RawMessage{
			"jsonrpc": json.RawMessage(`"2.0"`),
			"method":  mustJSONString(method),
			"params":  orNull(params),
		})
		s.enqueue(sseEvent{event: "message", data: env})
	})
	return ch
}

// enqueue pushes an event, returning false if the buffer is full (the caller
// then closes the overflowing session — bounded, never unbounded growth).
func (s *mcpSession) enqueue(ev sseEvent) bool {
	s.mu.Lock()
	ch := s.sse
	s.mu.Unlock()
	if ch == nil {
		return true
	}
	select {
	case ch <- ev:
		return true
	default:
		return false
	}
}

// detachStream closes and clears the SSE channel and stops routing.
func (s *mcpSession) detachStream() {
	s.mu.Lock()
	if s.sse != nil {
		close(s.sse)
		s.sse = nil
	}
	s.mu.Unlock()
	s.bridge.setNotifyHandler(nil)
}

func mustJSONString(s string) json.RawMessage {
	b, _ := json.Marshal(s)
	return b
}

func orNull(p json.RawMessage) json.RawMessage {
	if len(p) == 0 {
		return json.RawMessage("null")
	}
	return p
}
