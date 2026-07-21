package session

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// PersistedFrame is one unacked server->client DATA frame.
type PersistedFrame struct {
	Seq     uint64 `json:"seq"`
	Payload []byte `json:"payload"`
}

// PersistedSession is the externalized state of a resumable session, enough
// for a *different* gateway to resume it after a failover: the transport
// cursors + unacked buffer, and the client->backend handshake to replay
// against a freshly spawned (stateless) backend.
type PersistedSession struct {
	ID    string `json:"id"`
	Owner string `json:"owner"` // gateway instance currently serving it (lease)
	// CreatorKey is the WireGuard public key of the peer that opened the
	// session. A gateway resuming this session (failover) must reject a
	// reattach from any other identity, so the session id alone can never be
	// used to take over the backend and its buffered output.
	CreatorKey string           `json:"creator_key,omitempty"`
	SendSeq    uint64           `json:"send_seq"`
	Acked      uint64           `json:"acked"`
	RecvSeq    uint64           `json:"recv_seq"`
	SendBuf    []PersistedFrame `json:"send_buf"`
	// Replay is the captured client->backend bytes to replay against a fresh
	// backend on migration; ReplayResponses is how many response lines that
	// replay produces (to discard, since the client already has them).
	Replay          []byte `json:"replay"`
	ReplayResponses int    `json:"replay_responses"`

	// Generation is a monotonic fencing token. Every successful lease
	// acquisition increments it, so a gateway whose lease was taken over holds a
	// stale generation and is fenced out of SaveIfOwned/Renew/Release — it cannot
	// write or delete after losing ownership.
	Generation uint64 `json:"generation,omitempty"`
	// LeaseExpiry is when the current owner's lease lapses (Unix nanos). After
	// it passes another gateway may acquire the lease; the fencing generation is
	// what actually prevents a superseded owner from writing.
	LeaseExpiry int64 `json:"lease_expiry,omitempty"`
}

// SessionStore persists session state so a session survives the gateway that
// created it. Implementations must be safe for concurrent use.
type SessionStore interface {
	Save(ps PersistedSession) error
	Load(id string) (PersistedSession, bool, error)
	// DeleteIfOwner removes the session only if owner still holds the lease,
	// so a reaper on a gateway that has been superseded does not delete a
	// session another gateway resumed.
	DeleteIfOwner(id, owner string) error
	// List returns every persisted session (in unspecified order) — the
	// enumeration behind Air's "who is on the mesh, in a session" view.
	List() ([]PersistedSession, error)
}

// MemStore is an in-memory SessionStore (tests, single-process).
type MemStore struct {
	mu sync.Mutex
	m  map[string]PersistedSession
}

func NewMemStore() *MemStore { return &MemStore{m: map[string]PersistedSession{}} }

func (s *MemStore) Save(ps PersistedSession) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[ps.ID] = ps
	return nil
}

func (s *MemStore) Load(id string) (PersistedSession, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ps, ok := s.m[id]
	return ps, ok, nil
}

func (s *MemStore) DeleteIfOwner(id, owner string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ps, ok := s.m[id]; ok && ps.Owner == owner {
		delete(s.m, id)
	}
	return nil
}

func (s *MemStore) List() ([]PersistedSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]PersistedSession, 0, len(s.m))
	for _, ps := range s.m {
		out = append(out, ps)
	}
	return out, nil
}

// canAcquire is the shared compare-and-swap decision for AcquireLease: it
// returns the new generation and whether the acquire is permitted. An acquire
// is allowed only when there is no live lease held by a *different* owner AND
// the caller's expectedGen matches the stored generation (so two racing
// takeovers of an expired lease cannot both succeed).
func canAcquire(cur PersistedSession, exists bool, owner string, expectedGen uint64, now time.Time) (uint64, bool) {
	if !exists {
		if expectedGen != 0 {
			return 0, false
		}
		return 1, true
	}
	live := now.UnixNano() < cur.LeaseExpiry
	if live && cur.Owner != owner {
		return 0, false // a live lease is held by another gateway
	}
	if cur.Generation != expectedGen {
		return 0, false // the generation moved under us (lost the CAS race)
	}
	return cur.Generation + 1, true
}

// canTakeover is AcquireLease's decision for an identity-bound session reattach
// (migration/failover): unlike canAcquire it does NOT refuse a still-live lease,
// because the trigger is the session's own creator reattaching to a new gateway.
// It still enforces the generation compare-and-swap, so among several gateways
// racing to take over the same session exactly one wins, and the generation bump
// fences the previous owner.
func canTakeover(cur PersistedSession, exists bool, expectedGen uint64) (uint64, bool) {
	if !exists {
		if expectedGen != 0 {
			return 0, false
		}
		return 1, true
	}
	if cur.Generation != expectedGen {
		return 0, false // the generation moved under us (lost the takeover race)
	}
	return cur.Generation + 1, true
}

func (s *MemStore) AcquireLease(id, owner string, expectedGen uint64, ttl time.Duration, now time.Time) (Lease, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, exists := s.m[id]
	newGen, ok := canAcquire(cur, exists, owner, expectedGen, now)
	if !ok {
		return Lease{}, false, nil
	}
	exp := now.Add(ttl)
	cur.ID, cur.Owner, cur.Generation, cur.LeaseExpiry = id, owner, newGen, exp.UnixNano()
	s.m[id] = cur
	return Lease{SessionID: id, Owner: owner, Generation: newGen, Expiry: exp}, true, nil
}

func (s *MemStore) TakeoverLease(id, owner string, expectedGen uint64, ttl time.Duration, now time.Time) (Lease, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, exists := s.m[id]
	newGen, ok := canTakeover(cur, exists, expectedGen)
	if !ok {
		return Lease{}, false, nil
	}
	exp := now.Add(ttl)
	cur.ID, cur.Owner, cur.Generation, cur.LeaseExpiry = id, owner, newGen, exp.UnixNano()
	s.m[id] = cur
	return Lease{SessionID: id, Owner: owner, Generation: newGen, Expiry: exp}, true, nil
}

func (s *MemStore) RenewLease(id, owner string, gen uint64, ttl time.Duration, now time.Time) (Lease, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, ok := s.m[id]
	if !ok || cur.Owner != owner || cur.Generation != gen {
		return Lease{}, false, nil
	}
	exp := now.Add(ttl)
	cur.LeaseExpiry = exp.UnixNano()
	s.m[id] = cur
	return Lease{SessionID: id, Owner: owner, Generation: gen, Expiry: exp}, true, nil
}

func (s *MemStore) ReleaseLease(id, owner string, gen uint64) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, ok := s.m[id]
	if !ok || cur.Owner != owner || cur.Generation != gen {
		return false, nil
	}
	cur.Owner, cur.LeaseExpiry = "", 0 // free the lease; keep generation + state
	s.m[id] = cur
	return true, nil
}

func (s *MemStore) SaveIfOwned(ps PersistedSession, owner string, gen uint64) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, ok := s.m[ps.ID]
	if !ok || cur.Owner != owner || cur.Generation != gen {
		return false, nil // fenced: a superseded owner cannot write
	}
	ps.Owner, ps.Generation, ps.LeaseExpiry = owner, gen, cur.LeaseExpiry
	s.m[ps.ID] = ps
	return true, nil
}

// Lease is an ownership grant for a session, carrying a monotonic fencing
// generation and an expiry. A holder presents (Owner, Generation) to renew,
// save, or release; a holder whose lease was taken over holds a stale
// generation and is fenced out.
type Lease struct {
	SessionID  string
	Owner      string
	Generation uint64
	Expiry     time.Time
}

// LeaseStore provides atomic compare-and-swap session ownership so two gateways
// cannot concurrently own the same session. AcquireLease grants ownership only
// when no live lease is held by another owner AND the caller's expectedGen
// matches the stored generation (optimistic concurrency); it increments the
// generation on success. Renew/Release/SaveIfOwned require the presented
// (owner, generation) to still match, so a superseded owner is fenced.
//
// NOTE ON DURABILITY: FileStore implements this over a shared filesystem with a
// cross-process lock. That is correct for a single host (or a lock-correct
// shared filesystem) and is intended for single-node development — it is NOT a
// substitute for a real distributed CAS store. Production cross-gateway HA needs
// a backend with genuine atomic compare-and-swap and fencing (PostgreSQL,
// etcd, or Redis with appropriate transaction semantics).
type LeaseStore interface {
	AcquireLease(id, owner string, expectedGen uint64, ttl time.Duration, now time.Time) (Lease, bool, error)
	// TakeoverLease forcibly acquires the lease for an authenticated session
	// reattach (migration/failover). Unlike AcquireLease it does not refuse a
	// still-live lease, because the trigger is the session's own creator (an
	// identity verified at the transport by the caller) reattaching to a new
	// gateway. It still enforces the generation compare-and-swap, so exactly one
	// of several racing takers wins and the generation bump fences the previous
	// owner. Callers MUST gate this on a verified creator-identity reattach; it is
	// not a general lease-steal.
	TakeoverLease(id, owner string, expectedGen uint64, ttl time.Duration, now time.Time) (Lease, bool, error)
	RenewLease(id, owner string, gen uint64, ttl time.Duration, now time.Time) (Lease, bool, error)
	ReleaseLease(id, owner string, gen uint64) (bool, error)
	// SaveIfOwned writes ps only if (owner, gen) still hold the lease; otherwise
	// it returns false and does not write (the caller was fenced).
	SaveIfOwned(ps PersistedSession, owner string, gen uint64) (bool, error)
}

// FileStore persists sessions as JSON files in a shared directory with a
// cross-process lock, providing atomic lease compare-and-swap for a single host
// / lock-correct shared filesystem (single-node development). It is NOT
// cross-gateway HA — see LeaseStore. Writes are atomic (temp + fsync + rename).
type FileStore struct {
	dir string
	mu  sync.Mutex
}

func NewFileStore(dir string) (*FileStore, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	return &FileStore{dir: dir}, nil
}

func (s *FileStore) path(id string) string { return filepath.Join(s.dir, id+".json") }

func (s *FileStore) lock() fileLock {
	return fileLock{
		path:      filepath.Join(s.dir, ".store.lock"),
		timeout:   5 * time.Second,
		staleness: 10 * time.Second,
	}
}

func (s *FileStore) Save(ps PersistedSession) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	lk := s.lock()
	if err := lk.acquire(); err != nil {
		return err
	}
	defer lk.release()

	b, err := json.Marshal(ps)
	if err != nil {
		return err
	}
	tmp := s.path(ps.ID) + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil { // durable: bytes on disk before rename
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, s.path(ps.ID)) // atomic replace
}

func (s *FileStore) Load(id string) (PersistedSession, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := os.ReadFile(s.path(id))
	if os.IsNotExist(err) {
		return PersistedSession{}, false, nil
	}
	if err != nil {
		return PersistedSession{}, false, err
	}
	var ps PersistedSession
	if err := json.Unmarshal(b, &ps); err != nil {
		return PersistedSession{}, false, err
	}
	return ps, true, nil
}

func (s *FileStore) DeleteIfOwner(id, owner string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	lk := s.lock()
	if err := lk.acquire(); err != nil {
		return err
	}
	defer lk.release()

	b, err := os.ReadFile(s.path(id))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var ps PersistedSession
	if err := json.Unmarshal(b, &ps); err != nil {
		return err
	}
	if ps.Owner != owner {
		return nil // superseded by another gateway; leave it
	}
	err = os.Remove(s.path(id))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

// readUnlocked reads and parses one session file. Caller holds s.mu (and, for a
// CAS, the cross-process lock).
func (s *FileStore) readUnlocked(id string) (PersistedSession, bool, error) {
	b, err := os.ReadFile(s.path(id))
	if os.IsNotExist(err) {
		return PersistedSession{}, false, nil
	}
	if err != nil {
		return PersistedSession{}, false, err
	}
	var ps PersistedSession
	if err := json.Unmarshal(b, &ps); err != nil {
		return PersistedSession{}, false, err
	}
	return ps, true, nil
}

// writeUnlocked writes ps atomically (temp + fsync + rename). Caller holds the
// locks.
func (s *FileStore) writeUnlocked(ps PersistedSession) error {
	b, err := json.Marshal(ps)
	if err != nil {
		return err
	}
	tmp := s.path(ps.ID) + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, s.path(ps.ID))
}

// withLock runs fn while holding both s.mu and the cross-process store lock, so
// a read-modify-write is atomic across processes (the CAS guarantee).
func (s *FileStore) withLock(fn func() error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	lk := s.lock()
	if err := lk.acquire(); err != nil {
		return err
	}
	defer lk.release()
	return fn()
}

func (s *FileStore) AcquireLease(id, owner string, expectedGen uint64, ttl time.Duration, now time.Time) (Lease, bool, error) {
	var lease Lease
	var ok bool
	err := s.withLock(func() error {
		cur, exists, err := s.readUnlocked(id)
		if err != nil {
			return err
		}
		newGen, allowed := canAcquire(cur, exists, owner, expectedGen, now)
		if !allowed {
			return nil
		}
		exp := now.Add(ttl)
		cur.ID, cur.Owner, cur.Generation, cur.LeaseExpiry = id, owner, newGen, exp.UnixNano()
		if err := s.writeUnlocked(cur); err != nil {
			return err
		}
		lease, ok = Lease{SessionID: id, Owner: owner, Generation: newGen, Expiry: exp}, true
		return nil
	})
	return lease, ok, err
}

func (s *FileStore) TakeoverLease(id, owner string, expectedGen uint64, ttl time.Duration, now time.Time) (Lease, bool, error) {
	var lease Lease
	var ok bool
	err := s.withLock(func() error {
		cur, exists, err := s.readUnlocked(id)
		if err != nil {
			return err
		}
		newGen, allowed := canTakeover(cur, exists, expectedGen)
		if !allowed {
			return nil
		}
		exp := now.Add(ttl)
		cur.ID, cur.Owner, cur.Generation, cur.LeaseExpiry = id, owner, newGen, exp.UnixNano()
		if err := s.writeUnlocked(cur); err != nil {
			return err
		}
		lease, ok = Lease{SessionID: id, Owner: owner, Generation: newGen, Expiry: exp}, true
		return nil
	})
	return lease, ok, err
}

func (s *FileStore) RenewLease(id, owner string, gen uint64, ttl time.Duration, now time.Time) (Lease, bool, error) {
	var lease Lease
	var ok bool
	err := s.withLock(func() error {
		cur, exists, err := s.readUnlocked(id)
		if err != nil || !exists || cur.Owner != owner || cur.Generation != gen {
			return err
		}
		exp := now.Add(ttl)
		cur.LeaseExpiry = exp.UnixNano()
		if err := s.writeUnlocked(cur); err != nil {
			return err
		}
		lease, ok = Lease{SessionID: id, Owner: owner, Generation: gen, Expiry: exp}, true
		return nil
	})
	return lease, ok, err
}

func (s *FileStore) ReleaseLease(id, owner string, gen uint64) (bool, error) {
	var ok bool
	err := s.withLock(func() error {
		cur, exists, err := s.readUnlocked(id)
		if err != nil || !exists || cur.Owner != owner || cur.Generation != gen {
			return err
		}
		cur.Owner, cur.LeaseExpiry = "", 0
		if err := s.writeUnlocked(cur); err != nil {
			return err
		}
		ok = true
		return nil
	})
	return ok, err
}

func (s *FileStore) SaveIfOwned(ps PersistedSession, owner string, gen uint64) (bool, error) {
	var ok bool
	err := s.withLock(func() error {
		cur, exists, err := s.readUnlocked(ps.ID)
		if err != nil || !exists || cur.Owner != owner || cur.Generation != gen {
			return err // fenced (or error): do not write
		}
		ps.Owner, ps.Generation, ps.LeaseExpiry = owner, gen, cur.LeaseExpiry
		if err := s.writeUnlocked(ps); err != nil {
			return err
		}
		ok = true
		return nil
	})
	return ok, err
}

// List scans the store directory and loads every persisted session. Files that
// have vanished (a concurrent DeleteIfOwner) or fail to parse are skipped, so a
// racing reaper never turns enumeration into an error.
func (s *FileStore) List() ([]PersistedSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, err
	}
	var out []PersistedSession
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".json") || strings.HasSuffix(name, ".tmp") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(s.dir, name))
		if err != nil {
			continue // vanished between ReadDir and here
		}
		var ps PersistedSession
		if json.Unmarshal(b, &ps) == nil && ps.ID != "" {
			out = append(out, ps)
		}
	}
	return out, nil
}

// snapshot exports the endpoint's resumable state.
func (e *endpoint) snapshot(replay []byte, replayResponses int) PersistedSession {
	e.mu.Lock()
	defer e.mu.Unlock()
	ps := PersistedSession{
		ID:              e.id.String(),
		SendSeq:         e.sendSeq,
		Acked:           e.acked,
		RecvSeq:         e.recvSeq,
		Replay:          replay,
		ReplayResponses: replayResponses,
	}
	for _, f := range e.sendBuf {
		ps.SendBuf = append(ps.SendBuf, PersistedFrame{Seq: f.seq, Payload: append([]byte(nil), f.payload...)})
	}
	return ps
}

// restoreEndpoint rebuilds an endpoint from persisted state (used when a
// gateway resumes a session it did not originate).
func restoreEndpoint(ps PersistedSession) (*endpoint, error) {
	id, err := parseSessionID(ps.ID)
	if err != nil {
		return nil, err
	}
	e := newEndpointCap(id, defaultMaxSendFrames)
	e.sendSeq = ps.SendSeq
	e.acked = ps.Acked
	e.recvSeq = ps.RecvSeq
	for _, pf := range ps.SendBuf {
		e.sendBuf = append(e.sendBuf, frame{typ: frameData, seq: pf.Seq, payload: pf.Payload})
		<-e.slots // one slot consumed per restored unacked frame
	}
	return e, nil
}

func parseSessionID(s string) (sessionID, error) {
	var id sessionID
	b, err := hex.DecodeString(s)
	if err != nil {
		return id, err
	}
	if len(b) != sessionIDLen {
		return id, fmt.Errorf("session: bad id length %d", len(b))
	}
	copy(id[:], b)
	return id, nil
}
