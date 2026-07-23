package air

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Grant-on-request is the iOS-style "Allow once / Always / Deny" for the mesh:
// the final step after pairing. Pairing (PairedStore) makes a peer RECOGNIZED;
// this store is what turns a recognized peer's DENIED tool request into a
// pending OPPORTUNITY an operator resolves with one tap — and an "Always"/"once"
// approval WRITES the grant here, so the peer's retry succeeds without anyone
// hand-editing a --grant flag or YAML.
//
// The boundary, deliberately mirroring pairing's: this store never widens the
// endpoint reachability ACL, nor the operator control-steer allow. It confers a
// narrow, per-identity, per-verb, per-scope capability and nothing else. A grant
// for one scope never confers another; a grant for one verb never confers a
// different verb's access (entries are namespaced by verb). Deny-by-default is
// preserved: no matching grant → not granted.
//
// Every mutation is persisted with the same temp+fsync+rename write PairedStore
// uses (mirroring federation/dcr.go's writeAtomic), with in-memory rollback on a
// persist failure, so an approval or revocation survives a crash and a concurrent
// reader never observes a torn half-update.

const (
	// maxGrantText bounds the identity / verb / scope strings so a request body
	// can never carry an unbounded string into the store. It reuses presence's
	// identity ceiling for consistency with the paired store's bounds.
	maxGrantText = maxPresenceIdentityText
	// DefaultGrantPendingMax bounds how many distinct pending grant opportunities
	// may queue at once. Opportunities are recorded from DENIED tool calls; even
	// though only a RECOGNIZED peer can record one, a recognized peer probing many
	// distinct scopes could otherwise grow the set without bound.
	DefaultGrantPendingMax = 256
)

// Grant is one written capability: identity may exercise Scope under Verb. Once
// marks a single-use ("allow once") grant that is consumed the first time it
// authorizes a call and then gone; a persistent ("always") grant has Once=false.
type Grant struct {
	Identity  string `json:"identity"`   // the peer's WireGuard public key (unforgeable)
	Verb      string `json:"verb"`       // the air verb the scope belongs to (e.g. "kg")
	Scope     string `json:"scope"`      // a verb-appropriate scope (e.g. a corpus glob)
	Once      bool   `json:"once"`       // single-use ("allow once") vs persistent ("always")
	GrantedBy string `json:"granted_by"` // the operator identity that approved it
	GrantedAt string `json:"granted_at"` // RFC3339 approval time
}

// GrantOpportunity is a pending "this recognized peer was denied Scope and would
// like it" request, recorded from a denied call. It confers NOTHING until an
// operator approves it; it only surfaces the ask so the operator can resolve it.
type GrantOpportunity struct {
	Identity  string `json:"identity"`
	Verb      string `json:"verb"`
	Scope     string `json:"scope"`
	FirstSeen string `json:"first_seen"`
	LastSeen  string `json:"last_seen"`
	Count     int    `json:"count"` // how many times this exact ask has been denied
}

// grantSchemaVersion is the current on-disk format version of the grant store.
const grantSchemaVersion = 1

// grantState is the on-disk shape: both sets, written together atomically.
type grantState struct {
	// SchemaVersion self-describes the file format; a store from a newer build is
	// refused on load (fail closed) rather than silently forgetting grants.
	SchemaVersion int                `json:"schema_version"`
	Grants        []Grant            `json:"grants"`
	Pending       []GrantOpportunity `json:"pending"`
}

// GrantStore is an atomic, concurrency-safe store of written grants and pending
// grant opportunities, keyed by the unforgeable (identity, verb, scope) triple.
type GrantStore struct {
	mu      sync.Mutex
	path    string
	grants  map[string]Grant
	pending map[string]GrantOpportunity
}

// grantKey is the exact composite key for a grant / opportunity. Control-free,
// bounded fields (validated on the way in) make the NUL separator unambiguous.
func grantKey(identity, verb, scope string) string {
	return identity + "\x00" + verb + "\x00" + scope
}

// OpenGrantStore loads the store at path, or returns an empty store when the file
// does not yet exist. A present-but-unparseable file is a hard error rather than
// a silent reset, so a corrupt store never quietly forgets every grant
// (fail-closed, mirroring the paired store's load posture).
func OpenGrantStore(path string) (*GrantStore, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("grant: store path is empty")
	}
	s := &GrantStore{
		path:    path,
		grants:  map[string]Grant{},
		pending: map[string]GrantOpportunity{},
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return s, nil
		}
		return nil, fmt.Errorf("grant: read store %s: %w", path, err)
	}
	var st grantState
	if err := json.Unmarshal(b, &st); err != nil {
		return nil, fmt.Errorf("grant: parse store %s: %w", path, err)
	}
	if err := checkSchemaVersion("grant", st.SchemaVersion, grantSchemaVersion); err != nil {
		return nil, err
	}
	for _, g := range st.Grants {
		if g.Identity != "" && g.Verb != "" && g.Scope != "" {
			s.grants[grantKey(g.Identity, g.Verb, g.Scope)] = g
		}
	}
	for _, p := range st.Pending {
		if p.Identity == "" || p.Verb == "" || p.Scope == "" {
			continue
		}
		k := grantKey(p.Identity, p.Verb, p.Scope)
		// A scope that is both granted and (stale) pending is already resolved:
		// drop the redundant opportunity so the two sets stay disjoint.
		if _, granted := s.grants[k]; granted {
			continue
		}
		s.pending[k] = p
	}
	return s, nil
}

// Add writes (or replaces) a grant and drops any matching pending opportunity —
// approving the ask resolves it. It validates the triple so a malformed or
// hostile grant never lands in the store.
func (s *GrantStore) Add(identity, verb, scope string, once bool, grantedBy string, now time.Time) (Grant, error) {
	if err := validateGrantTriple(identity, verb, scope); err != nil {
		return Grant{}, err
	}
	grantedBy = strings.TrimSpace(grantedBy)
	if len(grantedBy) > maxGrantText || hasControl(grantedBy) {
		return Grant{}, fmt.Errorf("grant: invalid granted-by identity")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	k := grantKey(identity, verb, scope)
	g := Grant{
		Identity:  identity,
		Verb:      verb,
		Scope:     scope,
		Once:      once,
		GrantedBy: grantedBy,
		GrantedAt: now.UTC().Format(time.RFC3339),
	}
	prevGrant, hadGrant := s.grants[k]
	prevPend, hadPend := s.pending[k]
	s.grants[k] = g
	delete(s.pending, k)
	if err := s.persistLocked(); err != nil {
		// Roll back both sides on a persist failure.
		if hadGrant {
			s.grants[k] = prevGrant
		} else {
			delete(s.grants, k)
		}
		if hadPend {
			s.pending[k] = prevPend
		}
		return Grant{}, err
	}
	return g, nil
}

// Remove revokes a grant. removed is false when no such grant existed. After a
// successful Remove a Check for the same triple returns false.
func (s *GrantStore) Remove(identity, verb, scope string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := grantKey(identity, verb, scope)
	g, ok := s.grants[k]
	if !ok {
		return false, nil
	}
	delete(s.grants, k)
	if err := s.persistLocked(); err != nil {
		s.grants[k] = g
		return false, err
	}
	return true, nil
}

// DropOpportunity discards a pending opportunity without granting anything — the
// "Deny" tap. removed is false when no such opportunity existed.
func (s *GrantStore) DropOpportunity(identity, verb, scope string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := grantKey(identity, verb, scope)
	p, ok := s.pending[k]
	if !ok {
		return false, nil
	}
	delete(s.pending, k)
	if err := s.persistLocked(); err != nil {
		s.pending[k] = p
		return false, err
	}
	return true, nil
}

// Record notes that identity was denied scope under verb — a pending opportunity
// an operator can later resolve. It is deduped (a repeat ask bumps Count/LastSeen
// rather than adding a row) and bounded (DefaultGrantPendingMax). added is true
// only when a NEW opportunity was created, so a caller can quiet a repeat ask.
// Recording confers NOTHING; the caller must gate it on peer recognition.
func (s *GrantStore) Record(identity, verb, scope string, now time.Time) (GrantOpportunity, bool, error) {
	if err := validateGrantTriple(identity, verb, scope); err != nil {
		return GrantOpportunity{}, false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	k := grantKey(identity, verb, scope)
	if _, granted := s.grants[k]; granted {
		// Already granted — nothing to ask for (deny-by-default is not in play).
		return GrantOpportunity{}, false, nil
	}
	ts := now.UTC().Format(time.RFC3339)
	if existing, ok := s.pending[k]; ok {
		updated := existing
		updated.LastSeen = ts
		updated.Count++
		s.pending[k] = updated
		if err := s.persistLocked(); err != nil {
			s.pending[k] = existing
			return GrantOpportunity{}, false, err
		}
		return updated, false, nil
	}
	if len(s.pending) >= DefaultGrantPendingMax {
		return GrantOpportunity{}, false, fmt.Errorf("grant: too many pending opportunities (max %d)", DefaultGrantPendingMax)
	}
	op := GrantOpportunity{
		Identity: identity, Verb: verb, Scope: scope,
		FirstSeen: ts, LastSeen: ts, Count: 1,
	}
	s.pending[k] = op
	if err := s.persistLocked(); err != nil {
		delete(s.pending, k)
		return GrantOpportunity{}, false, err
	}
	return op, true, nil
}

// Check reports whether an exact (identity, verb, scope) grant exists, without
// consuming it. It is a non-mutating probe; use ConsumeOnceMatching to spend a
// single-use grant.
func (s *GrantStore) Check(identity, verb, scope string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.grants[grantKey(identity, verb, scope)]
	return ok
}

// ScopesFor returns the scopes granted to identity under verb, split into
// persistent ("always") and once ("allow once") sets. The caller folds these
// into its per-call capability so its verb's own authorization gate can apply
// them; the split lets the caller consume a single-use grant only when that grant
// is what authorized the call.
func (s *GrantStore) ScopesFor(identity, verb string) (persistent, once []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, g := range s.grants {
		if g.Identity != identity || g.Verb != verb {
			continue
		}
		if g.Once {
			once = append(once, g.Scope)
		} else {
			persistent = append(persistent, g.Scope)
		}
	}
	sort.Strings(persistent)
	sort.Strings(once)
	return persistent, once
}

// ConsumeOnceMatching removes exactly ONE single-use grant for (identity, verb)
// whose scope the authorizes predicate accepts — the grant that authorized the
// current call — and returns it. consumed is false when no single-use grant
// matched (e.g. the call was authorized by a persistent or static grant, or by a
// scope for a different verb). This is the single-use guarantee: the second call
// finds the grant gone and is denied again. The predicate lets the caller decide
// authorization with its own verb-appropriate scope semantics, so the store never
// has to know what a scope means.
func (s *GrantStore) ConsumeOnceMatching(identity, verb string, authorizes func(scope string) bool, now time.Time) (Grant, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Deterministic scan order so the consumed grant is stable across runs.
	keys := make([]string, 0, len(s.grants))
	for k, g := range s.grants {
		if g.Identity == identity && g.Verb == verb && g.Once {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	for _, k := range keys {
		g := s.grants[k]
		if !authorizes(g.Scope) {
			continue
		}
		delete(s.grants, k)
		if err := s.persistLocked(); err != nil {
			s.grants[k] = g
			return Grant{}, false, err
		}
		return g, true, nil
	}
	return Grant{}, false, nil
}

// Grants returns a deterministic snapshot of the written grants (by identity,
// then verb, then scope), copied so a caller cannot mutate internal state.
func (s *GrantStore) Grants() []Grant {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Grant, 0, len(s.grants))
	for _, g := range s.grants {
		out = append(out, g)
	}
	sort.Slice(out, func(i, j int) bool { return grantLess(out[i], out[j]) })
	return out
}

// Pending returns a deterministic snapshot of the pending opportunities (oldest
// first), copied so a caller cannot mutate internal state.
func (s *GrantStore) Pending() []GrantOpportunity {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]GrantOpportunity, 0, len(s.pending))
	for _, p := range s.pending {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].FirstSeen != out[j].FirstSeen {
			return out[i].FirstSeen < out[j].FirstSeen
		}
		return grantKey(out[i].Identity, out[i].Verb, out[i].Scope) <
			grantKey(out[j].Identity, out[j].Verb, out[j].Scope)
	})
	return out
}

func grantLess(a, b Grant) bool {
	if a.Identity != b.Identity {
		return a.Identity < b.Identity
	}
	if a.Verb != b.Verb {
		return a.Verb < b.Verb
	}
	return a.Scope < b.Scope
}

// persistLocked writes the whole store atomically. The caller must hold s.mu. It
// mirrors PairedStore.persistLocked (federation/dcr.go's writeAtomic): write a
// sibling temp file, fsync it, then rename it into place, so a reader (or a crash)
// never observes a partially written store at the canonical path.
func (s *GrantStore) persistLocked() error {
	st := grantState{SchemaVersion: grantSchemaVersion, Grants: s.sortedGrantsLocked(), Pending: s.sortedPendingLocked()}
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return fmt.Errorf("grant: marshal store: %w", err)
	}
	if dir := filepath.Dir(s.path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("grant: create store dir: %w", err)
		}
	}
	tmp := s.path + ".tmp-" + randGrantSuffix()
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("grant: open tmp file: %w", err)
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("grant: write tmp file: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("grant: sync tmp file: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("grant: close tmp file: %w", err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("grant: rename into place: %w", err)
	}
	return nil
}

func (s *GrantStore) sortedGrantsLocked() []Grant {
	out := make([]Grant, 0, len(s.grants))
	for _, g := range s.grants {
		out = append(out, g)
	}
	sort.Slice(out, func(i, j int) bool { return grantLess(out[i], out[j]) })
	return out
}

func (s *GrantStore) sortedPendingLocked() []GrantOpportunity {
	out := make([]GrantOpportunity, 0, len(s.pending))
	for _, p := range s.pending {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].FirstSeen != out[j].FirstSeen {
			return out[i].FirstSeen < out[j].FirstSeen
		}
		return grantKey(out[i].Identity, out[i].Verb, out[i].Scope) <
			grantKey(out[j].Identity, out[j].Verb, out[j].Scope)
	})
	return out
}

// validateGrantTriple rejects an unusable or hostile (identity, verb, scope): each
// field must be present, length-capped, and control-character free so it is safe
// to store, key on, and later render in a terminal.
func validateGrantTriple(identity, verb, scope string) error {
	if identity == "" || len(identity) > maxGrantText || hasControl(identity) {
		return fmt.Errorf("grant requires a valid identity public key")
	}
	if verb == "" || len(verb) > maxGrantText || hasControl(verb) {
		return fmt.Errorf("grant requires a valid verb")
	}
	if scope == "" || len(scope) > maxGrantText || hasControl(scope) {
		return fmt.Errorf("grant requires a valid scope")
	}
	return nil
}

func randGrantSuffix() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
