// Package kg is the importable core of the mesh knowledge graph: a
// hash-chained, provenance-native triple store. It was extracted verbatim from
// the cmd/kg binary so that in-process callers — notably the single-writer
// facade in air/knowstore (S1) — can own and drive one Store directly instead
// of forking a subprocess per session and racing on the same kg.jsonl.
//
// Every assertion and deletion is stamped with the asserting mesh identity
// (Peer, the caller's WireGuard public key) and linked into a tamper-evident
// chain, so the graph is non-repudiable: you can prove who asserted what, and
// that no fact was silently altered (Verify). It mirrors the gateway's audit
// ledger (policy/chain.go), applied to knowledge itself.
//
// The Store's own mutex serializes its mutations, but that is a within-process
// guard only. The concurrency bug the knowledge system fixes is N separate
// subprocesses appending to one file; the structural fix is to keep exactly one
// Store, owned by one writer (air/knowstore) — not to rely on this mutex across
// processes.
package kg

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"sync"
)

// Record is one entry in the knowledge graph's append-only, hash-chained log.
// Every assertion and deletion is stamped with the asserting mesh identity
// (Peer, the caller's WireGuard public key) and linked into a tamper-evident
// chain — so the graph is non-repudiable: you can prove who asserted what, and
// that no fact was silently altered (Verify).
type Record struct {
	Seq  int    `json:"seq"`
	Op   string `json:"op"` // "assert" | "delete"
	ID   string `json:"id"`
	S    string `json:"s,omitempty"`
	P    string `json:"p,omitempty"`
	O    string `json:"o,omitempty"`
	Peer string `json:"peer,omitempty"` // asserting WireGuard identity
	Time string `json:"time,omitempty"`

	PrevHash string `json:"prev_hash"`
	Hash     string `json:"hash,omitempty"`
}

// Store is a hash-chained triple log persisted as newline-delimited JSON.
type Store struct {
	mu   sync.Mutex
	path string
	recs []Record
	seq  int
	prev string
	now  func() string
}

// Open loads (or starts) a Store at path. now supplies each record's timestamp;
// if nil, records carry an empty time.
func Open(path string, now func() string) (*Store, error) {
	if now == nil {
		now = func() string { return "" }
	}
	s := &Store{path: path, now: now}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return s, nil // fresh store
		}
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 16<<20)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var r Record
		if err := json.Unmarshal(line, &r); err != nil {
			return nil, fmt.Errorf("corrupt store at record %d: %w", s.seq+1, err)
		}
		s.recs = append(s.recs, r)
		s.seq = r.Seq
		s.prev = r.Hash
	}
	return s, sc.Err()
}

// ChainHash computes a record's hash over its JSON with Hash cleared.
func ChainHash(r Record) string {
	r.Hash = ""
	b, _ := json.Marshal(r)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func newID() string {
	var b [12]byte
	_, _ = rand.Read(b[:])
	return "t_" + hex.EncodeToString(b[:])
}

// appendRecord links a record into the chain and persists it. It is unexported:
// the only entry points that extend the chain are Assert and Delete, so the
// hash chain can never be advanced out from under those invariants.
func (s *Store) appendRecord(r Record) (Record, error) {
	s.seq++
	r.Seq = s.seq
	r.Time = s.now()
	r.PrevHash = s.prev
	r.Hash = ChainHash(r)

	if s.path != "" {
		f, err := os.OpenFile(s.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			s.seq-- // roll back the counter on a write failure
			return Record{}, err
		}
		b, _ := json.Marshal(r)
		if _, err := f.Write(append(b, '\n')); err != nil {
			f.Close()
			s.seq--
			return Record{}, err
		}
		if err := f.Close(); err != nil {
			s.seq--
			return Record{}, err
		}
	}
	s.prev = r.Hash
	s.recs = append(s.recs, r)
	return r, nil
}

// Assert records a new triple stamped with peer, returning it.
func (s *Store) Assert(sub, pred, obj, peer string) (Record, error) {
	if sub == "" || pred == "" || obj == "" {
		return Record{}, fmt.Errorf("subject, predicate, and object are all required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.appendRecord(Record{Op: "assert", ID: newID(), S: sub, P: pred, O: obj, Peer: peer})
}

// Delete tombstones the triple with the given id.
func (s *Store) Delete(id, peer string) (Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.appendRecord(Record{Op: "delete", ID: id, Peer: peer})
}

// Active returns the triples in effect as of asOf (0 or negative = current
// head): asserted, and not tombstoned, at a sequence <= asOf.
func (s *Store) Active(asOf int) []Record {
	s.mu.Lock()
	defer s.mu.Unlock()
	if asOf <= 0 {
		asOf = s.seq
	}
	deleted := map[string]bool{}
	asserts := map[string]Record{}
	var order []string
	for _, r := range s.recs {
		if r.Seq > asOf {
			break
		}
		switch r.Op {
		case "delete":
			deleted[r.ID] = true
		case "assert":
			if _, seen := asserts[r.ID]; !seen {
				order = append(order, r.ID)
			}
			asserts[r.ID] = r
		}
	}
	out := make([]Record, 0, len(order))
	for _, id := range order {
		if !deleted[id] {
			out = append(out, asserts[id])
		}
	}
	return out
}

// Query returns active triples (as of asOf) matching the non-empty fields of
// the pattern; an empty field is a wildcard.
func (s *Store) Query(sub, pred, obj string, asOf int) []Record {
	var out []Record
	for _, r := range s.Active(asOf) {
		if (sub == "" || r.S == sub) && (pred == "" || r.P == pred) && (obj == "" || r.O == obj) {
			out = append(out, r)
		}
	}
	return out
}

// Neighbors returns active triples in which node is the subject or the object.
func (s *Store) Neighbors(node string, asOf int) []Record {
	var out []Record
	for _, r := range s.Active(asOf) {
		if r.S == node || r.O == node {
			out = append(out, r)
		}
	}
	return out
}

// Verify walks the whole log and checks sequence contiguity and hash linkage —
// proving the knowledge graph has not been edited, reordered, or truncated.
func (s *Store) Verify() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	prev := ""
	for i, r := range s.recs {
		if r.Seq != i+1 {
			return fmt.Errorf("sequence break at record %d (seq %d)", i+1, r.Seq)
		}
		if r.PrevHash != prev {
			return fmt.Errorf("chain break at seq %d: prev_hash mismatch", r.Seq)
		}
		if ChainHash(r) != r.Hash {
			return fmt.Errorf("tampered record at seq %d: hash mismatch", r.Seq)
		}
		prev = r.Hash
	}
	return nil
}

// Head returns the current sequence number (the "now" cursor for time-travel).
func (s *Store) Head() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.seq
}

// Merge reconciles records from any number of replicas into the converged set
// of active triples — an OR-set with tombstones (S8): a triple id is active iff
// some replica asserted it and none deleted it. Merging is commutative and
// idempotent (the result is sorted by id, independent of input order), so peers
// that edit the graph offline and sync in any order converge to the same
// knowledge. Each replica then appends the reconciled triples it lacked to its
// own hash-chained log, so the reconciliation stays audited.
func Merge(logs ...[]Record) []Record {
	deleted := map[string]bool{}
	asserts := map[string]Record{}
	for _, log := range logs {
		for _, r := range log {
			switch r.Op {
			case "delete":
				deleted[r.ID] = true
			case "assert":
				asserts[r.ID] = r
			}
		}
	}
	out := make([]Record, 0, len(asserts))
	for id, r := range asserts {
		if !deleted[id] {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
