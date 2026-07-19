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

// FileStore persists sessions as JSON files in a shared directory, so two
// gateway processes on shared (optionally replicated) storage can hand a
// session off. Writes are atomic (temp + fsync + rename) and serialized
// across processes by a cross-process lock, so the ownership lease holds even
// under concurrent multi-gateway access.
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
