package main

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

// record is one entry in the knowledge graph's append-only, hash-chained log.
// Every assertion and deletion is stamped with the asserting mesh identity
// (Peer, the caller's WireGuard public key) and linked into a tamper-evident
// chain — so the graph is non-repudiable: you can prove who asserted what, and
// that no fact was silently altered (Op "verify"). This mirrors the gateway's
// audit ledger (policy/chain.go), applied to knowledge itself.
type record struct {
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

// store is a hash-chained triple log persisted as newline-delimited JSON.
type store struct {
	mu   sync.Mutex
	path string
	recs []record
	seq  int
	prev string
	now  func() string
}

func openStore(path string, now func() string) (*store, error) {
	if now == nil {
		now = func() string { return "" }
	}
	s := &store{path: path, now: now}
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
		var r record
		if err := json.Unmarshal(line, &r); err != nil {
			return nil, fmt.Errorf("corrupt store at record %d: %w", s.seq+1, err)
		}
		s.recs = append(s.recs, r)
		s.seq = r.Seq
		s.prev = r.Hash
	}
	return s, sc.Err()
}

// chainHash computes a record's hash over its JSON with Hash cleared.
func chainHash(r record) string {
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

// append links a record into the chain and persists it.
func (s *store) append(r record) (record, error) {
	s.seq++
	r.Seq = s.seq
	r.Time = s.now()
	r.PrevHash = s.prev
	r.Hash = chainHash(r)

	if s.path != "" {
		f, err := os.OpenFile(s.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			s.seq-- // roll back the counter on a write failure
			return record{}, err
		}
		b, _ := json.Marshal(r)
		if _, err := f.Write(append(b, '\n')); err != nil {
			f.Close()
			s.seq--
			return record{}, err
		}
		if err := f.Close(); err != nil {
			s.seq--
			return record{}, err
		}
	}
	s.prev = r.Hash
	s.recs = append(s.recs, r)
	return r, nil
}

// assert records a new triple stamped with peer, returning it.
func (s *store) assert(sub, pred, obj, peer string) (record, error) {
	if sub == "" || pred == "" || obj == "" {
		return record{}, fmt.Errorf("subject, predicate, and object are all required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.append(record{Op: "assert", ID: newID(), S: sub, P: pred, O: obj, Peer: peer})
}

// del tombstones the triple with the given id.
func (s *store) del(id, peer string) (record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.append(record{Op: "delete", ID: id, Peer: peer})
}

// active returns the triples in effect as of asOf (0 or negative = current
// head): asserted, and not tombstoned, at a sequence <= asOf.
func (s *store) active(asOf int) []record {
	s.mu.Lock()
	defer s.mu.Unlock()
	if asOf <= 0 {
		asOf = s.seq
	}
	deleted := map[string]bool{}
	asserts := map[string]record{}
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
	out := make([]record, 0, len(order))
	for _, id := range order {
		if !deleted[id] {
			out = append(out, asserts[id])
		}
	}
	return out
}

// query returns active triples (as of asOf) matching the non-empty fields of
// the pattern; an empty field is a wildcard.
func (s *store) query(sub, pred, obj string, asOf int) []record {
	var out []record
	for _, r := range s.active(asOf) {
		if (sub == "" || r.S == sub) && (pred == "" || r.P == pred) && (obj == "" || r.O == obj) {
			out = append(out, r)
		}
	}
	return out
}

// neighbors returns active triples in which node is the subject or the object.
func (s *store) neighbors(node string, asOf int) []record {
	var out []record
	for _, r := range s.active(asOf) {
		if r.S == node || r.O == node {
			out = append(out, r)
		}
	}
	return out
}

// verify walks the whole log and checks sequence contiguity and hash linkage —
// proving the knowledge graph has not been edited, reordered, or truncated.
func (s *store) verify() error {
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
		if chainHash(r) != r.Hash {
			return fmt.Errorf("tampered record at seq %d: hash mismatch", r.Seq)
		}
		prev = r.Hash
	}
	return nil
}

// head returns the current sequence number (the "now" cursor for time-travel).
func (s *store) head() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.seq
}

// mergeRecords reconciles records from any number of replicas into the
// converged set of active triples — an OR-set with tombstones (S8): a triple
// id is active iff some replica asserted it and none deleted it. Merging is
// commutative and idempotent (the result is sorted by id, independent of input
// order), so peers that edit the graph offline and sync in any order converge
// to the same knowledge. Each replica then appends the reconciled triples it
// lacked to its own hash-chained log, so the reconciliation stays audited.
func mergeRecords(logs ...[]record) []record {
	deleted := map[string]bool{}
	asserts := map[string]record{}
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
	out := make([]record, 0, len(asserts))
	for id, r := range asserts {
		if !deleted[id] {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
