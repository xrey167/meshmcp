package session

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/json"
	"net"
	"sync"
	"time"
)

// Server manages resumable sessions for one backend definition. Each
// session keeps its backend subprocess alive across client reconnects for
// up to TTL, buffering both directions so no MCP message is lost.
type Server struct {
	factory  BackendFactory
	ttl      time.Duration
	logf     func(string, ...any)
	store    SessionStore  // optional: enables cross-gateway session migration
	migMode  MigrationMode // how a resumed backend is reconstructed
	instance string        // this gateway's lease owner id

	mu       sync.Mutex
	sessions map[sessionID]*serverSession
}

// WithStore enables session migration: session state is checkpointed to the
// store and a session unknown to this gateway is rehydrated from it (failover
// from the gateway that created it). mode selects how the backend state is
// reconstructed (handshake replay, full replay, or backend-managed).
func (s *Server) WithStore(store SessionStore, mode MigrationMode) *Server {
	s.store = store
	s.migMode = mode
	return s
}

// NewServer creates a session server. logf may be nil.
func NewServer(factory BackendFactory, ttl time.Duration, logf func(string, ...any)) *Server {
	if ttl <= 0 {
		ttl = DefaultSessionTTL
	}
	if logf == nil {
		logf = func(string, ...any) {}
	}
	inst, _ := randID()
	return &Server{
		factory:  factory,
		ttl:      ttl,
		logf:     logf,
		instance: inst.String(),
		sessions: make(map[sessionID]*serverSession),
	}
}

type serverSession struct {
	ep      *endpoint
	backend Backend
	reader  *bufio.Reader // backend output reader (survives handshake pre-read)
	reaper  *time.Timer   // fires when a detached session's TTL expires
	active  int           // number of live Handle goroutines for this session

	cmu         sync.Mutex // guards replay / captureDone
	replay      []byte     // captured client->backend bytes to replay on migration
	captureDone bool       // handshake captured (handshake mode)
}

// Handle takes ownership of one accepted mesh connection: it reads the
// ATTACH handshake, creates or resumes the session, and pumps until the
// connection drops. It returns when this connection is done; the session
// itself may live on awaiting reattach. meta identifies the caller.
func (s *Server) Handle(conn net.Conn, meta Meta) {
	defer conn.Close()

	r := bufio.NewReaderSize(conn, maxPayload+64)
	_ = conn.SetReadDeadline(time.Now().Add(idleTimeout))
	att, err := readFrame(r)
	if err != nil {
		s.logf("session: read ATTACH: %v", err)
		return
	}
	if att.typ != frameAttack {
		writeErr(conn, "expected ATTACH")
		return
	}

	sess, resumed, err := s.attach(att.id, meta)
	if err != nil {
		writeErr(conn, "attach: "+err.Error())
		s.logf("session: attach: %v", err)
		return
	}
	// attach registered this Handle as active; releasing it arms the TTL
	// reaper only when the last live Handle for the session exits.
	defer s.handleExit(sess)

	// Tell the client its session id and our receive cursor so it can
	// replay anything we never saw. The ATTACH's own cursor acknowledges
	// our outbound buffer.
	if err := writeControlConn(conn, frame{typ: frameAttachOK, id: sess.ep.id, seq: sess.ep.recvCursor()}); err != nil {
		return
	}
	gen := sess.ep.bind(conn, att.seq)
	if resumed {
		s.logf("session %s: resumed by %s", sess.ep.id, meta.PeerFQDN)
	}

	// Reuse the reader we already buffered the ATTACH from.
	_ = sess.ep.pumpReader(conn, r, gen)
}

// handleExit releases one live Handle. When the session is closed it is
// removed; otherwise the TTL reaper is armed only once no Handle remains,
// so a concurrent reattach never leaves a live session being reaped.
func (s *Server) handleExit(sess *serverSession) {
	if sess.ep.isClosed() {
		s.remove(sess.ep.id)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sess.active--
	_, present := s.sessions[sess.ep.id]
	if present && sess.active <= 0 && sess.reaper == nil {
		id := sess.ep.id
		sess.reaper = time.AfterFunc(s.ttl, func() {
			s.logf("session %s: expired after %s detached", id, s.ttl)
			s.remove(id)
		})
	}
}

// attach returns an existing session for id, or creates a new one when id
// is zero or unknown.
func (s *Server) attach(id sessionID, meta Meta) (*serverSession, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !id.isZero() {
		if sess, ok := s.sessions[id]; ok {
			if sess.reaper != nil {
				sess.reaper.Stop()
				sess.reaper = nil
			}
			sess.active++
			return sess, true, nil
		}
		// Unknown here but known to the store: another gateway created it.
		// Rehydrate and take over (session migration / failover).
		if s.store != nil {
			if ps, ok, _ := s.store.Load(id.String()); ok {
				sess, err := s.rehydrate(ps, meta)
				if err != nil {
					return nil, false, err
				}
				return sess, true, nil
			}
		}
	}

	newID, err := randID()
	if err != nil {
		return nil, false, err
	}
	meta.SessionID = newID.String()
	backend, err := s.factory(meta)
	if err != nil {
		return nil, false, err
	}
	sess := &serverSession{
		ep:      newEndpoint(newID),
		backend: backend,
		reader:  bufio.NewReaderSize(backend, maxPayload+64),
		active:  1,
	}
	s.sessions[newID] = sess
	s.pump(sess)
	s.logf("session %s: opened by %s", newID, meta.PeerFQDN)
	return sess, false, nil
}

// rehydrate resumes a session created by another gateway: it restores the
// transport state, spawns a fresh backend, replays the client->backend
// handshake against it (discarding the already-delivered initialize reply),
// and starts pumping. Caller holds s.mu. Stateless backends only.
func (s *Server) rehydrate(ps PersistedSession, meta Meta) (*serverSession, error) {
	ep, err := restoreEndpoint(ps)
	if err != nil {
		return nil, err
	}
	// Tell the fresh backend which session it is, so a backend-managed
	// (EventStore) backend can restore its own state.
	meta.SessionID = ps.ID
	backend, err := s.factory(meta)
	if err != nil {
		return nil, err
	}
	reader := bufio.NewReaderSize(backend, maxPayload+64)
	// Replay the captured client->backend log against the fresh backend and
	// discard the responses it re-produces (the client already has them).
	// MigrateBackend skips this entirely — the backend restored itself.
	if s.migMode != MigrateBackend && len(ps.Replay) > 0 {
		if _, err := backend.Write(ps.Replay); err != nil {
			backend.Close()
			return nil, err
		}
		for i := 0; i < ps.ReplayResponses; i++ {
			if _, err := reader.ReadString('\n'); err != nil {
				backend.Close()
				return nil, err
			}
		}
	}
	sess := &serverSession{
		ep:          ep,
		backend:     backend,
		reader:      reader,
		active:      1,
		replay:      ps.Replay,
		captureDone: true,
	}
	s.sessions[ep.id] = sess
	s.pump(sess)
	s.checkpoint(sess) // claim the lease under this gateway's instance id
	s.logf("session %s: rehydrated from store (gateway failover, mode=%d)", ep.id, s.migMode)
	return sess, nil
}

// checkpoint persists the session's state (with this gateway's lease) so
// another gateway can resume it.
func (s *Server) checkpoint(sess *serverSession) {
	if s.store == nil {
		return
	}
	sess.cmu.Lock()
	replay := append([]byte(nil), sess.replay...)
	sess.cmu.Unlock()
	ps := sess.ep.snapshot(replay, countRequests(replay))
	ps.Owner = s.instance
	_ = s.store.Save(ps)
}

// countRequests counts complete newline-delimited JSON-RPC lines that carry a
// non-null id — i.e. how many responses replaying those lines will produce.
func countRequests(buf []byte) int {
	n, start := 0, 0
	for i := 0; i < len(buf); i++ {
		if buf[i] != '\n' {
			continue
		}
		line := bytes.TrimSpace(buf[start:i])
		start = i + 1
		if len(line) == 0 {
			continue
		}
		var m struct {
			ID *json.RawMessage `json:"id"`
		}
		if json.Unmarshal(line, &m) == nil && m.ID != nil && string(*m.ID) != "null" {
			n++
		}
	}
	return n
}

// pump wires the backend to the endpoint for the life of the session.
func (s *Server) pump(sess *serverSession) {
	// Checkpoint on every ack (the consistent point for migration).
	if s.store != nil {
		sess.ep.afterAck = func() { s.checkpoint(sess) }
	}
	// backend stdout -> peer
	go func() {
		buf := make([]byte, maxPayload)
		for {
			n, err := sess.reader.Read(buf)
			if n > 0 {
				if serr := sess.ep.Send(buf[:n]); serr != nil {
					return
				}
			}
			if err != nil {
				sess.ep.sendClose()
				s.remove(sess.ep.id)
				return
			}
		}
	}()
	// peer -> backend stdin (also captures the handshake and checkpoints
	// state so another gateway can resume this session)
	go func() {
		for {
			select {
			case p, ok := <-sess.ep.Inbound():
				if !ok {
					return
				}
				if s.store != nil && s.migMode != MigrateBackend {
					sess.cmu.Lock()
					if s.migMode == MigrateFull || !sess.captureDone {
						sess.replay = append(sess.replay, p...)
						if s.migMode == MigrateHandshake &&
							bytes.Contains(sess.replay, []byte("notifications/initialized")) {
							sess.captureDone = true
						}
					}
					sess.cmu.Unlock()
				}
				if _, err := sess.backend.Write(p); err != nil {
					sess.ep.sendClose()
					s.remove(sess.ep.id)
					return
				}
				// Persist the replay log early; ack-driven checkpoints keep
				// the transport cursors consistent thereafter.
				s.checkpoint(sess)
			case <-sess.ep.Done():
				return
			}
		}
	}()
}



// remove tears down a session and its backend.
func (s *Server) remove(id sessionID) {
	s.mu.Lock()
	sess, ok := s.sessions[id]
	if ok {
		delete(s.sessions, id)
		if sess.reaper != nil {
			sess.reaper.Stop()
		}
	}
	s.mu.Unlock()
	if ok {
		sess.ep.closeWith(nil)
		_ = sess.backend.Close()
		// Drop persisted state only if this gateway still holds the lease —
		// a reaper here must not delete a session another gateway resumed.
		if s.store != nil {
			_ = s.store.DeleteIfOwner(id.String(), s.instance)
		}
	}
}

// Count returns the number of live sessions (for tests / status).
func (s *Server) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.sessions)
}

func randID() (sessionID, error) {
	var id sessionID
	_, err := rand.Read(id[:])
	return id, err
}

// --- small connection helpers ---

// writeControlConn writes a single frame directly to a raw connection.
func writeControlConn(conn net.Conn, f frame) error {
	w := bufio.NewWriter(conn)
	return writeFrame(w, f)
}

func writeErr(conn net.Conn, msg string) {
	_ = writeControlConn(conn, frame{typ: frameError, payload: []byte(msg)})
}
