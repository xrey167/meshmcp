package session

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"time"
)

// Live-session move (v2, first slice). This is a DELIBERATE, operator/creator-
// initiated relocation of ONE live session's ownership from a source gateway to a
// destination gateway, in three phases — prepare -> ready -> commit — with abort
// at every pre-commit step and crash-recovery to exactly one owner.
//
// It is ADDITIVE. It introduces no new MigrationMode and changes nothing in the
// existing reactive moves (client-reattach rehydrate, standby sweep adopt, clean
// Shutdown). The v1 Air Handoff (inert Context Capsule) is untouched. The only
// existing-file edits are the behavior-preserving extraction of
// spawnBackendForResume/registerResumed out of resumeFromPersisted (guarded by
// RunSessionMigration) and the inert endpoint.detach() helper.
//
// The four SACRED INVARIANTS and how this file keeps them:
//
//  1. Single-writer. Commit is ONE generation-fenced TakeoverLease CAS. The
//     destination serves only AFTER it owns; the source detaches its client
//     (freezes inbound) and takes its final checkpoint BEFORE COMMIT and is
//     hard-fenced by the generation bump. MigrateHandshake additionally drains to
//     a quiescent request/response boundary (or refuses); MigrateBackend tolerates
//     a residual because the backend is authoritative and dedups.
//
//  2. Resumable-by-exactly-one. The source holds its live lease at generation G
//     through every pre-commit step (freeze quiesces; it does NOT release). The
//     CAS is the single indivisible flip: a crash before it leaves the source
//     resumable at G; a crash after it leaves the destination resumable at G+1;
//     never both, never neither. See moveCrashMatrix in move_test.go.
//
//  3. Identity untouched. TakeoverLease stays contractually reserved for a
//     verified-creator reattach (rehydrate). The operator-driven move instead
//     gates its commit on a consumed single-use grant ("this destination may
//     receive session X once", air/move_grant.go) via the authorize callback —
//     never an arbitrary peer. The client that later attaches to the warm session
//     is still the creator (attach's creatorKey check is unchanged).
//
//  4. Additive. New file + control verb + warming map + inert detach()/hooks.
//
// Client redirection is NOT part of this: the move relocates ownership and
// pre-warms the destination; the creator lands on the destination by the same
// client-driven reattach + mesh discovery that today's crash-failover uses (an
// operator draining a gateway redirects discovery to the destination). Do not
// redirect the client to the destination before COMMIT succeeds.

// v1 supports moving only these two backend classes. MigrateFull (re-executes the
// whole input log) and stateful backends without a checkpoint/EventStore are
// refused at prepare — there is no safe reconstruction (replay would duplicate
// side effects; there is no state to restore). Deny-by-default.
func moveSupportedMode(m MigrationMode) bool {
	return m == MigrateHandshake || m == MigrateBackend
}

var (
	errMoveNoStore         = errors.New("session: live move requires a CAS lease store")
	errMoveModeUnsupported = errors.New("session: live move supports only MigrateHandshake and MigrateBackend backends")
	errMoveNoIdentity      = errors.New("session: live move requires a persisted creator identity")
	errMoveDegraded        = errors.New("session: cannot move a session that holds no fencing lease")
	errMoveAlreadyLive     = errors.New("session: already serving this session here; nothing to prepare")
	errMoveNotWarming      = errors.New("session: no prepared move for this session")
	errMoveUnauthorized    = errors.New("session: destination is not authorized to receive this session")
	errMoveNoState         = errors.New("session: committed the lease but could not load the moved session state")
	errMoveNotQuiescent    = errors.New("session: handshake-mode session is not at a quiescent boundary; move refused")
	errMoveProtocol        = errors.New("session: malformed move control frame")
)

// warmSession is a destination-side pre-warmed session awaiting a move commit: a
// spawned (and, for replay modes, handshake-replayed) backend that holds NO
// lease, serves NO client, and has NO s.sessions entry until CommitMove's CAS.
type warmSession struct {
	ps      PersistedSession // the prepare-time checkpoint (identity + replay + mode inputs)
	backend Backend
	reader  *bufio.Reader
	meta    Meta
	// gen is the source's generation observed at prepare — the expectedGen the
	// commit CAS presents to TakeoverLease. The endpoint is deliberately NOT built
	// here: the source keeps serving after prepare, so a prepare-time endpoint
	// would be stale. It is restored from the FINAL checkpoint at commit.
	gen uint64
}

// moveHooks are test seams: each fires at an exact point of a move and is nil in
// production (zero effect). A test uses them both to synchronize (no sleeps) and
// to inject a crash at that instant.
type moveHooks struct {
	onWarmReady func(id string) // dest: after PrepareMove parks the warm backend, before READY
	onBeforeCAS func(id string) // dest: after COMMIT, before authorize + TakeoverLease
	onAfterCAS  func(id string) // dest: after the CAS wins, before promote + checkpoint
	onPromoted  func(id string) // dest: after promote + checkpoint (now serving @G+1)
	onAborted   func(id string) // dest: after AbortMove discards the warm backend
	onQuiesced  func(id string) // source: after freeze + drain + final checkpoint @G, before COMMIT
	onThawed    func(id string) // source: after ThawForMove (move aborted pre-commit)
	onFenced    func(id string) // source: after YieldAfterMove (fenced), before returning
}

const moveProtocolVersion = 1

// maxMoveFrameBytes bounds one control frame so an identity-pinned but buggy or
// hostile peer cannot stream an unbounded line into the JSON decoder.
const maxMoveFrameBytes = 64 * 1024

type moveFrameType string

const (
	moveKindPrepare   moveFrameType = "prepare"
	moveKindReady     moveFrameType = "ready"
	moveKindRefuse    moveFrameType = "refuse"
	moveKindCommit    moveFrameType = "commit"
	moveKindCommitted moveFrameType = "committed"
	moveKindCASLost   moveFrameType = "cas_lost"
	moveKindAbort     moveFrameType = "abort"
)

// moveFrame is one newline-delimited JSON control frame on the source<->dest move
// channel (mirroring the offer/ack framing of air handoff, but carrying a
// session-move intent + generation, never an inert capsule).
type moveFrame struct {
	V          int           `json:"v"`
	Type       moveFrameType `json:"type"`
	SessionID  string        `json:"session_id"`
	Gen        uint64        `json:"gen,omitempty"`
	Mode       int           `json:"mode,omitempty"`
	CreatorKey string        `json:"creator_key,omitempty"`
	PeerFQDN   string        `json:"peer_fqdn,omitempty"`
	PeerAddr   string        `json:"peer_addr,omitempty"`
	OK         bool          `json:"ok,omitempty"`
	Reason     string        `json:"reason,omitempty"`
}

func writeMoveFrame(w *bufio.Writer, f moveFrame) error {
	f.V = moveProtocolVersion
	b, err := json.Marshal(f)
	if err != nil {
		return err
	}
	if len(b) > maxMoveFrameBytes {
		return errMoveProtocol
	}
	if _, err := w.Write(b); err != nil {
		return err
	}
	if err := w.WriteByte('\n'); err != nil {
		return err
	}
	return w.Flush()
}

func readMoveFrame(r *bufio.Reader) (moveFrame, error) {
	line, err := readBoundedLine(r, maxMoveFrameBytes)
	if err != nil {
		return moveFrame{}, err
	}
	var f moveFrame
	if err := json.Unmarshal(bytes.TrimSpace(line), &f); err != nil {
		return moveFrame{}, errMoveProtocol
	}
	if f.V != moveProtocolVersion {
		return moveFrame{}, errMoveProtocol
	}
	return f, nil
}

// readBoundedLine reads one '\n'-terminated line, failing rather than buffering
// past limit bytes.
func readBoundedLine(r *bufio.Reader, limit int) ([]byte, error) {
	var out []byte
	for {
		b, err := r.ReadByte()
		if err != nil {
			return nil, err
		}
		if b == '\n' {
			return out, nil
		}
		out = append(out, b)
		if len(out) > limit {
			return nil, errMoveProtocol
		}
	}
}

func moveRefuse(id, reason string) moveFrame {
	return moveFrame{Type: moveKindRefuse, SessionID: id, OK: false, Reason: reason}
}

// --- destination side: prepare, commit, abort ---

// PrepareMove pre-warms this gateway to receive session ps.ID from its current
// owner: it spawns (and, for the replay modes, handshake-replays) the backend and
// parks it in the warming map WITHOUT taking the ownership lease, WITHOUT a
// s.sessions entry, and WITHOUT a client pump. The source keeps owning and
// serving until CommitMove's single CAS. A warm entry is in-memory only, so a
// crash or AbortMove before commit strands nothing durable — the source remains
// the sole resumable owner at generation G. meta identifies the creator whose
// policy identity the backend is spawned under (from the checkpoint).
func (s *Server) PrepareMove(ps PersistedSession, meta Meta) error {
	if s.store == nil || s.lease == nil {
		return errMoveNoStore
	}
	if !moveSupportedMode(s.migMode) {
		return errMoveModeUnsupported
	}
	if ps.ID == "" || ps.CreatorKey == "" {
		return errMoveNoIdentity
	}
	if ps.Generation == 0 {
		// The source never held a fencing lease (degraded): its checkpoints bypass
		// SaveIfOwned, so it is unfenceable and a move could split-brain. Refuse.
		return errMoveDegraded
	}
	id, err := parseSessionID(ps.ID)
	if err != nil {
		return err
	}
	meta.SessionID = ps.ID
	if meta.PeerKey == "" {
		meta.PeerKey = ps.CreatorKey
	}
	if meta.PeerFQDN == "" {
		meta.PeerFQDN = ps.PeerFQDN
	}
	if meta.PeerAddr == "" {
		meta.PeerAddr = ps.PeerAddr
	}
	// Spawn OUTSIDE s.mu: the factory (and any handshake replay) may block, and
	// the server mutex must never be held across it.
	backend, reader, err := s.spawnBackendForResume(ps, meta)
	if err != nil {
		return err
	}
	s.mu.Lock()
	_, live := s.sessions[id]
	old, hadOld := s.warming[id]
	if !live {
		s.warming[id] = &warmSession{ps: ps, backend: backend, reader: reader, meta: meta, gen: ps.Generation}
	}
	s.mu.Unlock()

	if live {
		// The creator already reattached here (normal failover): nothing to warm.
		_ = backend.Close()
		return errMoveAlreadyLive
	}
	if hadOld {
		// A prior prepare for the same id is superseded; discard its backend.
		_ = old.backend.Close()
	}
	s.logf("session %s: pre-warmed for move (mode=%d, no lease taken)", ps.ID, s.migMode)
	if h := s.moveHooks.onWarmReady; h != nil {
		h(ps.ID)
	}
	return nil
}

// CommitMove performs the single fenced ownership swap that completes a move.
// authorize is the identity gate: it consumes the destination's single-use move
// grant (air/move_grant.go) and returns true only if this destination is the
// authorized target for the session — deny-by-default (nil authorize refuses).
// On authorization it issues ONE TakeoverLease CAS at the source's generation G;
// TakeoverLease (not AcquireLease) because the source's lease is deliberately
// still live — canTakeover skips the liveness refusal but keeps the generation
// CAS, so exactly one of any racers wins and the source is fenced by the bump.
// On CAS success it restores the endpoint from the source's FINAL checkpoint and
// promotes the pre-warmed backend to a serving session at G+1. It is idempotent
// AND concurrency-safe: it atomically CLAIMS the warm entry (removing it from the
// warming map under the lock), so a retried or duplicate commit either re-observes
// self-ownership and reports success or finds nothing to promote — a losing commit
// can never close the backend a winning commit is promoting.
func (s *Server) CommitMove(id string, authorize func() (bool, error)) (bool, error) {
	sid, err := parseSessionID(id)
	if err != nil {
		return false, err
	}
	// CLAIM the warm entry atomically: remove it from s.warming under the lock so
	// this call has EXCLUSIVE ownership of warm.backend. A concurrent or duplicate
	// CommitMove (an operator retry, or the next-slice gateway trigger double-
	// firing) then finds nothing warm and can neither promote nor close the same
	// backend. Without this claim a losing commit's discard could close the backend
	// a winning commit is promoting, whose immediate pump failure would
	// remove -> DeleteIfOwner the just-committed record and strand the session with
	// ZERO owners. Every exit below except the successful promote closes
	// warm.backend directly (it is no longer reachable via the map).
	s.mu.Lock()
	warm, warming := s.warming[sid]
	if warming {
		delete(s.warming, sid)
	}
	_, live := s.sessions[sid]
	s.mu.Unlock()
	if live {
		// Already serving here: a prior CommitMove promoted it (idempotent retry),
		// or the creator reattached and rehydrated it during the warm window — both
		// leave THIS gateway the owner. Report idempotent success and discard the
		// warm backend we just claimed (an un-pumped orphan holding no lease),
		// WITHOUT consuming the single-use grant (there is nothing left to
		// authorize — the session is already here).
		if warming {
			_ = warm.backend.Close()
		}
		return true, nil
	}
	if !warming {
		return false, errMoveNotWarming
	}
	if h := s.moveHooks.onBeforeCAS; h != nil {
		h(id)
	}
	// Identity gate: consume the single-use destination grant. Deny-by-default.
	if authorize == nil {
		_ = warm.backend.Close()
		return false, errMoveUnauthorized
	}
	authed, err := authorize()
	if err != nil {
		_ = warm.backend.Close()
		return false, err
	}
	if !authed {
		_ = warm.backend.Close()
		return false, errMoveUnauthorized
	}
	// The SINGLE compare-and-swap.
	lease, ok, err := s.lease.TakeoverLease(id, s.instance, warm.gen, s.ttl, time.Now())
	if err != nil {
		// Unknown-outcome store error: discard the warm backend rather than leak
		// it. If the CAS in fact committed, the moved state (owner=dest@G+1) is in
		// the store and a client reattach rehydrates it normally.
		_ = warm.backend.Close()
		return false, err
	}
	if !ok {
		// Lost the CAS: the generation moved under us. If it moved because WE
		// already own it (a retried commit whose earlier CAS already won, or a
		// concurrent reattach-rehydrate), report success; otherwise the swap
		// genuinely lost. Either way the warm backend we claimed is now an orphan
		// (the owning path serves its own backend) and is discarded.
		if cur, found, _ := s.store.Load(id); found && cur.Owner == s.instance {
			_ = warm.backend.Close()
			return true, nil
		}
		_ = warm.backend.Close()
		return false, nil
	}
	if h := s.moveHooks.onAfterCAS; h != nil {
		h(id)
	}
	// We now own the lease at G+1 and the source is fenced, so this read of its
	// final checkpoint is stable (we are the only writer). Restore the endpoint
	// from it (authoritative cursors + unacked send buffer) and promote the
	// pre-warmed backend onto that fresh endpoint.
	cur, found, err := s.store.Load(id)
	if err != nil || !found {
		_, _ = s.lease.ReleaseLease(id, s.instance, lease.Generation)
		_ = warm.backend.Close()
		return false, errMoveNoState
	}
	ep, err := restoreEndpoint(cur)
	if err != nil {
		_, _ = s.lease.ReleaseLease(id, s.instance, lease.Generation)
		_ = warm.backend.Close()
		return false, err
	}
	s.mu.Lock()
	sess := s.registerResumed(cur, ep, warm.backend, warm.reader, warm.meta, lease.Generation, 0)
	// No live client yet (the creator reattaches later via mesh discovery). Arm
	// the reaper now, exactly as the standby sweep's adopt does; attach stops it
	// on reattach.
	sess.reaper = time.AfterFunc(s.ttl, func() {
		s.logf("session %s: moved-in session expired after %s unclaimed", id, s.ttl)
		s.remove(sid)
	})
	s.mu.Unlock()
	s.logf("session %s: move committed; now owner at generation %d (warm backend promoted)", id, lease.Generation)
	if h := s.moveHooks.onPromoted; h != nil {
		h(id)
	}
	return true, nil
}

// discardWarm closes and drops a warm entry that was never committed (AbortMove).
// It re-reads the map under the lock, so it is a no-op if the entry was already
// claimed by a CommitMove; it takes no lease and writes nothing durable.
func (s *Server) discardWarm(sid sessionID) {
	s.mu.Lock()
	warm, ok := s.warming[sid]
	if ok {
		delete(s.warming, sid)
	}
	s.mu.Unlock()
	if ok {
		_ = warm.backend.Close()
	}
}

// AbortMove discards a pre-warmed session when a move is aborted (explicitly or
// by control-channel loss) before commit: it closes the warm backend and drops
// the warming entry. It takes no lease and writes nothing durable, so the source
// remains the sole owner. Idempotent — a second abort finds the entry gone.
func (s *Server) AbortMove(id string) {
	sid, err := parseSessionID(id)
	if err != nil {
		return
	}
	s.mu.Lock()
	_, ok := s.warming[sid]
	s.mu.Unlock()
	if ok {
		s.discardWarm(sid)
		s.logf("session %s: move aborted; warm backend discarded", id)
	}
	if h := s.moveHooks.onAborted; h != nil {
		h(id)
	}
}

// warmingCount reports how many sessions are pre-warmed for a move (tests).
func (s *Server) warmingCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.warming)
}

// --- source side: freeze, thaw, yield ---

// FreezeForMove quiesces the source side of a move after the destination is warm
// and READY: it detaches any bound client (so no further client->backend byte is
// dispatched), confirms the session is at a quiescent boundary, and takes the
// final checkpoint at the CURRENT generation G. The lease is NOT released — the
// source stays the sole resumable owner at G, so a crash here leaves exactly the
// source resumable. For MigrateHandshake it refuses (errMoveNotQuiescent) a
// session with input still pending to the backend, because a handshake-mode
// destination cannot reconstruct an un-replayed in-flight request; MigrateBackend
// tolerates it (the backend is authoritative and dedups).
func (s *Server) FreezeForMove(id string) error {
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
	if sess.leaseGen == 0 {
		return errMoveDegraded
	}
	// Detach the client: the session becomes an ordinary detached-but-live
	// (resumable-by-source) session. recvSeq is now frozen (no conn => no new
	// acked inbound).
	sess.ep.detach()
	if err := s.drainForMove(sess); err != nil {
		return err
	}
	// Final checkpoint @G (owner and generation unchanged). This durable payload
	// is authoritative and is written BEFORE the source signals COMMIT.
	s.checkpoint(sess)
	s.logf("session %s: frozen for move (final checkpoint at generation %d; lease retained)", id, sess.leaseGen)
	if h := s.moveHooks.onQuiesced; h != nil {
		h(id)
	}
	return nil
}

// drainForMove asserts the (now detached) session is at a quiescent boundary: no
// client->backend input still buffered. Responses the backend already produced
// live in the send buffer and travel in the final checkpoint, replayed to the
// destination on the client's reattach; only un-forwarded INPUT is a problem, and
// only for the replay modes.
func (s *Server) drainForMove(sess *serverSession) error {
	if len(sess.ep.Inbound()) == 0 {
		return nil
	}
	if s.migMode == MigrateBackend {
		// The backend is the authoritative state source and dedups a replayed
		// residual, so an un-forwarded frame is tolerable.
		return nil
	}
	return errMoveNotQuiescent
}

// ThawForMove reverses a FreezeForMove when a move aborts before commit. The
// session was only detached (never released), so it is already a normal
// detached-but-live session the client resumes on its next reattach; thaw is
// therefore a no-op on the lease and state and exists as the explicit, named
// counterpart to Freeze (and an abort-hook point).
func (s *Server) ThawForMove(id string) {
	s.logf("session %s: move thawed (source retains ownership and keeps serving)", id)
	if h := s.moveHooks.onThawed; h != nil {
		h(id)
	}
}

// YieldAfterMove releases the source's local session immediately after a
// confirmed commit, rather than waiting for the next fenced renew/checkpoint to
// detect the takeover. The destination now owns the lease at G+1; the source's
// remove -> DeleteIfOwner is a no-op (it no longer owns the row), so the moved
// state survives for the destination. Call ONLY after COMMITTED.
func (s *Server) YieldAfterMove(id string) {
	sid, err := parseSessionID(id)
	if err != nil {
		return
	}
	s.remove(sid)
	s.logf("session %s: yielded after move (destination owns; source fenced)", id)
	if h := s.moveHooks.onFenced; h != nil {
		h(id)
	}
}

// --- orchestration over a control connection ---

// MoveSessionTo is the SOURCE orchestrator: over an already-dialed, identity-
// pinned control connection to the destination gateway, it runs prepare -> ready
// -> freeze -> commit and yields on success. The source keeps serving through
// PREPARE and READY, freezes (detach + final checkpoint @G) only after READY, and
// yields only after COMMITTED. Any pre-COMMITTED failure or refusal thaws the
// source, which keeps serving. If the COMMIT outcome is unknown (control conn
// dropped after COMMIT), the source does NOT yield: its next fenced renew/
// checkpoint resolves it (fenced => yield; not => keep serving).
func (s *Server) MoveSessionTo(ctx context.Context, id string, conn net.Conn, destKey string) error {
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
	if s.store == nil || s.lease == nil {
		return errMoveNoStore
	}
	if !moveSupportedMode(s.migMode) {
		return errMoveModeUnsupported
	}
	if sess.leaseGen == 0 {
		return errMoveDegraded
	}
	gen := sess.leaseGen
	if dl, hasDL := ctx.Deadline(); hasDL {
		_ = conn.SetDeadline(dl)
		defer conn.SetDeadline(time.Time{})
	}
	w := bufio.NewWriter(conn)
	r := bufio.NewReaderSize(conn, maxMoveFrameBytes+64)
	s.logf("session %s: initiating live move to destination %s (generation %d)", id, destKey, gen)

	// Publish a fresh checkpoint @G so the destination can Load the current state.
	s.checkpoint(sess)
	prepare := moveFrame{
		Type: moveKindPrepare, SessionID: id, Gen: gen, Mode: int(s.migMode),
		CreatorKey: sess.creatorKey, PeerFQDN: sess.meta.PeerFQDN, PeerAddr: sess.meta.PeerAddr,
	}
	if err := writeMoveFrame(w, prepare); err != nil {
		return err
	}
	ready, err := readMoveFrame(r)
	if err != nil {
		return err
	}
	if ready.Type == moveKindRefuse || !ready.OK {
		return fmt.Errorf("destination refused move: %s", sanitizeReason(ready.Reason))
	}
	if ready.Type != moveKindReady {
		return errMoveProtocol
	}

	// Destination is warm. Freeze the source, then COMMIT.
	if err := s.FreezeForMove(id); err != nil {
		_ = writeMoveFrame(w, moveFrame{Type: moveKindAbort, SessionID: id})
		s.ThawForMove(id)
		return err
	}
	if err := writeMoveFrame(w, moveFrame{Type: moveKindCommit, SessionID: id, Gen: gen}); err != nil {
		s.ThawForMove(id)
		return err
	}
	committed, err := readMoveFrame(r)
	if err != nil {
		// Unknown outcome: the commit CAS may or may not have landed. Do NOT yield
		// blindly. The source keeps its lease; its next fenced renew/checkpoint
		// resolves ownership safely.
		return fmt.Errorf("move commit outcome unknown (source retains the session until fenced): %w", err)
	}
	if committed.Type == moveKindCASLost || !committed.OK {
		s.ThawForMove(id)
		return fmt.Errorf("destination could not commit move: %s", sanitizeReason(committed.Reason))
	}
	if committed.Type != moveKindCommitted {
		return errMoveProtocol
	}
	// The destination owns @G+1 and is resumable. Yield the local session.
	s.YieldAfterMove(id)
	return nil
}

// ServeMoveControl is the DESTINATION handler for one source->destination move
// control connection: it reads PREPARE/COMMIT/ABORT and drives
// PrepareMove/CommitMove/AbortMove on this gateway's Server. A control-connection
// drop before COMMITTED aborts the warm state (disconnect == abort), so an
// interrupted move never strands a warm backend or moves a lease. authorize is
// invoked at commit to consume this destination's single-use move grant
// (deny-by-default); pass nil to refuse all commits.
func (s *Server) ServeMoveControl(conn net.Conn, authorize func(id string) (bool, error)) error {
	if s.store == nil || s.lease == nil {
		return errMoveNoStore
	}
	r := bufio.NewReaderSize(conn, maxMoveFrameBytes+64)
	w := bufio.NewWriter(conn)
	preparedID := ""
	committed := false
	defer func() {
		// Disconnect == abort for any prepared-but-not-committed session.
		if preparedID != "" && !committed {
			s.AbortMove(preparedID)
		}
	}()
	for {
		f, err := readMoveFrame(r)
		if err != nil {
			return err
		}
		switch f.Type {
		case moveKindPrepare:
			ps, ok, lerr := s.store.Load(f.SessionID)
			if lerr != nil {
				_ = writeMoveFrame(w, moveRefuse(f.SessionID, "store error"))
				continue
			}
			if !ok {
				_ = writeMoveFrame(w, moveRefuse(f.SessionID, "unknown session"))
				continue
			}
			if f.CreatorKey != "" && ps.CreatorKey != f.CreatorKey {
				_ = writeMoveFrame(w, moveRefuse(f.SessionID, "creator identity mismatch"))
				continue
			}
			meta := Meta{PeerFQDN: ps.PeerFQDN, PeerAddr: ps.PeerAddr, PeerKey: ps.CreatorKey}
			if err := s.PrepareMove(ps, meta); err != nil {
				_ = writeMoveFrame(w, moveRefuse(f.SessionID, err.Error()))
				continue
			}
			preparedID = f.SessionID
			if err := writeMoveFrame(w, moveFrame{Type: moveKindReady, SessionID: f.SessionID, OK: true}); err != nil {
				return err
			}
		case moveKindCommit:
			var auth func() (bool, error)
			if authorize != nil {
				commitID := f.SessionID
				auth = func() (bool, error) { return authorize(commitID) }
			}
			ok, cerr := s.CommitMove(f.SessionID, auth)
			if cerr != nil || !ok {
				reason := "commit CAS lost"
				if cerr != nil {
					reason = cerr.Error()
				}
				_ = writeMoveFrame(w, moveFrame{Type: moveKindCASLost, SessionID: f.SessionID, Reason: reason})
				// A failed commit leaves nothing warm (CommitMove discarded it).
				preparedID = ""
				continue
			}
			committed = true
			_ = writeMoveFrame(w, moveFrame{Type: moveKindCommitted, SessionID: f.SessionID, OK: true})
			return nil
		case moveKindAbort:
			if preparedID != "" {
				s.AbortMove(preparedID)
				preparedID = ""
			}
			return nil
		default:
			return errMoveProtocol
		}
	}
}

// sanitizeReason bounds and strips control characters from a peer-supplied reason
// string before it is surfaced in an error.
func sanitizeReason(s string) string {
	const max = 256
	if len(s) > max {
		s = s[:max]
	}
	out := make([]rune, 0, len(s))
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			continue
		}
		out = append(out, r)
	}
	if len(out) == 0 {
		return "(no reason)"
	}
	return string(out)
}
