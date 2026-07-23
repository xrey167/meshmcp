package session

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

// errSessionIdentity is returned by attach when a reattach is presented by a
// cryptographic identity other than the one that opened the session. The
// session id alone can never authorize a takeover.
var errSessionIdentity = errors.New("session: reattach identity does not match the session's creator")

// errSessionNotFound refuses to turn a resume attempt into a fresh logical
// session. Replaying an unacknowledged suffix into a new backend can duplicate
// earlier side effects while making the new backend's totals look complete.
var errSessionNotFound = errors.New("session: requested resume session is no longer available")

// ErrNoSession is returned by Steer when no live session has the given id.
var ErrNoSession = errors.New("session: no such session")

// Server manages resumable sessions for one backend definition. Each
// session keeps its backend subprocess alive across client reconnects for
// up to TTL, buffering both directions so no MCP message is lost.
type Server struct {
	factory  BackendFactory
	ttl      time.Duration
	logf     func(string, ...any)
	store    SessionStore  // optional: enables cross-gateway session migration
	lease    LeaseStore    // set when store also supports CAS ownership leases
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
	// When the store supports compare-and-swap ownership leases, checkpoints go
	// through SaveIfOwned so a superseded gateway is fenced and two gateways
	// never both write persisted state for the same session. A client that
	// reconnects during a takeover may see one last inbound message dispatched
	// to the backend on the fenced gateway before its next checkpoint detects
	// the fence; MigrateBackend removes this residual (the backend is the
	// authoritative state source and governs its own duplicate-dispatch window).
	if ls, ok := store.(LeaseStore); ok {
		s.lease = ls
	}
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
	ep         *endpoint
	backend    Backend
	creatorKey string        // WireGuard key of the peer that opened the session
	reader     *bufio.Reader // backend output reader (survives handshake pre-read)
	reaper     *time.Timer   // fires when a detached session's TTL expires
	active     int           // number of live Handle goroutines for this session

	meta      Meta      // caller identity (for enumeration)
	createdAt time.Time // when this session was opened/rehydrated here (for age)

	leaseGen uint64 // fencing generation of the lease this gateway holds (0 = none)

	sendMu sync.Mutex // serializes peer-bound Sends so a Steer lands on a line boundary

	cmu         sync.Mutex // guards replay / captureDone
	replay      []byte     // captured client->backend bytes to replay on migration
	captureDone bool       // handshake captured (handshake mode)

	// ckptMu serializes whole checkpoints (snapshot + store write). The
	// ack-driven and replay-persist triggers run on different goroutines; over
	// a slow store (PostgreSQL) an older snapshot could otherwise commit after
	// a newer one, and a gateway rehydrating from that older state would
	// re-serve send sequence numbers the client has already seen — silently
	// dropping every response after the failover.
	ckptMu sync.Mutex
}

// sendLines forwards complete-line data to the peer, chunked to the frame cap,
// under sendMu so a concurrent Steer cannot interleave mid-line. Callers must
// pass a region that ends on a line boundary (or the final bytes at EOF).
func (ss *serverSession) sendLines(data []byte) error {
	ss.sendMu.Lock()
	defer ss.sendMu.Unlock()
	for len(data) > 0 {
		n := len(data)
		if n > maxPayload {
			n = maxPayload
		}
		if err := ss.ep.Send(data[:n]); err != nil {
			return err
		}
		data = data[n:]
	}
	return nil
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

// attach returns an existing session for a known id and creates a new one only
// when id is zero. An unknown resume id is terminal: silently creating a new
// backend could replay only a suffix after earlier side effects were installed.
func (s *Server) attach(id sessionID, meta Meta) (*serverSession, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !id.isZero() {
		if sess, ok := s.sessions[id]; ok {
			// Identity binding: a session may be reattached only by the
			// cryptographic identity that opened it. Otherwise any mesh peer
			// that learns a session id (they are logged and shared for
			// migration) could take over the backend and its buffered output.
			if sess.creatorKey != meta.PeerKey {
				return nil, false, errSessionIdentity
			}
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
				// The same identity binding holds across a failover: the
				// rehydrating gateway must reject a reattach from any identity
				// other than the one that originally opened the session.
				if ps.CreatorKey != meta.PeerKey {
					return nil, false, errSessionIdentity
				}
				sess, err := s.rehydrate(ps, meta)
				if err != nil {
					return nil, false, err
				}
				return sess, true, nil
			}
		}
		return nil, false, errSessionNotFound
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
		ep:         newEndpoint(newID),
		backend:    backend,
		creatorKey: meta.PeerKey,
		reader:     bufio.NewReaderSize(backend, maxPayload+64),
		active:     1,
		meta:       meta,
		createdAt:  time.Now(),
	}
	// Claim the ownership lease for this brand-new session so its checkpoints
	// write through SaveIfOwned. A store error here degrades to serving without
	// migration (leaseGen stays 0) rather than failing the client's request.
	if s.lease != nil {
		if l, ok, err := s.lease.AcquireLease(newID.String(), s.instance, 0, s.ttl, time.Now()); err == nil && ok {
			sess.leaseGen = l.Generation
		} else {
			s.logf("session %s: could not acquire lease (ok=%v err=%v); serving without migration", newID, ok, err)
		}
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
	// Take over the ownership lease before spawning a backend. attach() already
	// verified this reattach carries the session creator's identity, so this is an
	// authorized takeover: it bumps the fencing generation (fencing the previous
	// gateway out of SaveIfOwned) and, if several gateways race, only one wins.
	var leaseGen uint64
	if s.lease != nil {
		l, ok, err := s.lease.TakeoverLease(ps.ID, s.instance, ps.Generation, s.ttl, time.Now())
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, fmt.Errorf("session %s: lost the takeover race", ps.ID)
		}
		leaseGen = l.Generation
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
		creatorKey:  ps.CreatorKey,
		reader:      reader,
		active:      1,
		meta:        meta,
		createdAt:   time.Now(),
		replay:      ps.Replay,
		captureDone: true,
		leaseGen:    leaseGen,
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
	sess.ckptMu.Lock()
	defer sess.ckptMu.Unlock()
	sess.cmu.Lock()
	replay := append([]byte(nil), sess.replay...)
	sess.cmu.Unlock()
	ps := sess.ep.snapshot(replay, countRequests(replay))
	ps.Owner = s.instance
	ps.CreatorKey = sess.creatorKey

	// Lease-gated store: write only while we still hold the lease. If SaveIfOwned
	// reports we no longer own it, another gateway took the session over — we are
	// fenced and must stop serving. The lease guarantees two gateways never both
	// write persisted state for the same session; one last inbound message may
	// have already been dispatched to the backend before this fence is detected
	// (backend.Write precedes checkpoint — see pump). MigrateBackend avoids this
	// residual by making the backend the authoritative state source.
	if s.lease != nil && sess.leaseGen > 0 {
		ok, err := s.lease.SaveIfOwned(ps, s.instance, sess.leaseGen)
		if err != nil {
			s.logf("session %s: checkpoint write error: %v", sess.ep.id, err)
			return
		}
		if !ok {
			s.logf("session %s: fenced (lease taken over by another gateway); yielding", sess.ep.id)
			go s.remove(sess.ep.id)
		}
		return
	}
	// No lease support (or lease not held): best-effort save, no fencing.
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
	// backend stdout -> peer, line-framed. The backend emits newline-delimited
	// JSON-RPC; we only ever Send complete-line regions (holding sendMu), so an
	// out-of-band Server.Steer can inject a whole line between two of ours and
	// the peer's reassembled stream stays cleanly newline-delimited.
	go func() {
		buf := make([]byte, maxPayload)
		var pending []byte
		for {
			n, err := sess.reader.Read(buf)
			if n > 0 {
				pending = append(pending, buf[:n]...)
				if nl := bytes.LastIndexByte(pending, '\n'); nl >= 0 {
					if serr := sess.sendLines(pending[:nl+1]); serr != nil {
						return
					}
					pending = append([]byte(nil), pending[nl+1:]...)
				}
			}
			if err != nil {
				if len(pending) > 0 {
					_ = sess.sendLines(pending) // flush a final unterminated line
				}
				sess.ep.sendClose()
				s.remove(sess.ep.id)
				return
			}
		}
	}()
	// peer -> backend stdin. backend.Write (side effect) runs before checkpoint
	// (fence check), so a fenced gateway may dispatch one last inbound message
	// to its backend process before discovering it lost the lease. This is the
	// residual window noted in the checkpoint comment above.
	go func() {
		for {
			select {
			case p, ok := <-sess.ep.Inbound():
				if !ok {
					return
				}
				if s.store != nil && s.migMode != MigrateBackend {
					sess.cmu.Lock()
					capturing := s.migMode == MigrateFull || !sess.captureDone
					overflow := capturing && len(sess.replay)+len(p) > maxReplayBytes
					if capturing && !overflow {
						sess.replay = append(sess.replay, p...)
						if s.migMode == MigrateHandshake &&
							bytes.Contains(sess.replay, []byte("notifications/initialized")) {
							sess.captureDone = true
						}
					}
					sess.cmu.Unlock()
					if overflow {
						// A peer that streams input without finishing the
						// handshake would grow the replay buffer (and its
						// per-message on-disk checkpoint) without bound. Refuse
						// to migrate an oversized session rather than degrade.
						sess.ep.sendClose()
						s.remove(sess.ep.id)
						return
					}
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

// SessionInfo describes one live session for enumeration (Air's "Sessions"
// view). The session layer knows the caller and the age; a gateway can enrich
// it with a backend label it holds elsewhere.
type SessionInfo struct {
	ID      string        // hex session id
	Peer    string        // caller mesh FQDN
	PeerKey string        // caller's full transport-stamped WireGuard key
	Age     time.Duration // since the session opened/rehydrated on this gateway
}

// Sessions lists the live sessions on this gateway.
func (s *Server) Sessions() []SessionInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	out := make([]SessionInfo, 0, len(s.sessions))
	for id, sess := range s.sessions {
		out = append(out, SessionInfo{
			ID: id.String(), Peer: sess.meta.PeerFQDN, PeerKey: sess.meta.PeerKey,
			Age: now.Sub(sess.createdAt),
		})
	}
	return out
}

// Steer delivers a server->client MCP notification into a live session (Air ·
// Steer, P2): the agent driving the session receives {"jsonrpc":"2.0","method",
// "params"} as a well-formed, newline-delimited line, injected between complete
// backend lines so it never splices one. A notification (no id) is used, so no
// response is expected on the wire. It is a transport mechanism — the caller
// (control plane) authorizes and audits it; it returns ErrNoSession if the id
// is not live here.
func (s *Server) Steer(id string, method string, params any) error {
	sid, err := parseSessionID(id)
	if err != nil {
		return err
	}
	s.mu.Lock()
	sess, ok := s.sessions[sid]
	s.mu.Unlock()
	if !ok {
		return ErrNoSession
	}
	line, err := json.Marshal(struct {
		JSONRPC string `json:"jsonrpc"`
		Method  string `json:"method"`
		Params  any    `json:"params,omitempty"`
	}{"2.0", method, params})
	if err != nil {
		return err
	}
	return sess.sendLines(append(line, '\n'))
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
	clean := sanitizeErrorText([]byte(msg), maxPeerErrorBytes)
	_ = writeControlConn(conn, frame{typ: frameError, payload: []byte(clean)})
}
