package air

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Pairing is the AirDrop "Accept?" moment for the mesh. A peer that is not yet
// on any allow list may REQUEST access; the request grants NOTHING — it only
// queues the peer's transport-verified identity for an operator to approve. An
// operator approval moves the request into the paired store: a durable set of
// RECOGNIZED peer identities, meant to be consulted ALONGSIDE the static config
// allow, so peers can become recognized WITHOUT hand-editing YAML.
//
// The boundary is non-negotiable: being recognized is NOT authorization. A
// paired peer is a known identity, nothing more — this store never adds a peer
// to the privileged control-steer allow, nor to any backend or tool ACL. Actual
// tool access stays explicit (grant-on-request, a separate step). This store
// confers recognition; it never confers capability.

const (
	// maxPairLabelBytes bounds the free-form, peer-supplied label so a request
	// body can never carry an unbounded string into the store or the operator's
	// terminal.
	maxPairLabelBytes = 128
	// DefaultPendingMax bounds how many distinct pending requests may queue at
	// once. The request endpoint is reachable by peers that are NOT yet allowed,
	// so without a ceiling a population of distinct identities could exhaust
	// memory/disk. Approved peers are operator-gated and not bounded here.
	DefaultPendingMax = 256
)

// ErrNoPendingRequest is returned by Approve when no pending request exists for
// the given identity (and it is not already paired) — the operator cannot
// approve something nobody asked for.
var ErrNoPendingRequest = errors.New("pairing: no pending request for that identity")

// PairStatus is a peer's own view of where it stands: approved (recognized),
// pending (queued, awaiting an operator), or none (not requested / declined).
type PairStatus string

const (
	StatusApproved PairStatus = "approved"
	StatusPending  PairStatus = "pending"
	StatusDenied   PairStatus = "denied"
	StatusNone     PairStatus = "none"
)

// DeniedRequest records an operator's decline so the requester can be TOLD —
// "your request was declined: <reason>" beats a silent disappearance from the
// queue (guided recovery, not a dead end). A denial is advisory memory, never
// a ban: a fresh Request clears it and queues the ask again.
type DeniedRequest struct {
	PublicKey string `json:"public_key"`
	Reason    string `json:"reason,omitempty"`
	DeniedAt  string `json:"denied_at"`
}

// maxDeniedRemembered bounds how many denials are kept (oldest evicted), so
// remembering declines can never grow the store without bound.
const maxDeniedRemembered = 256

// PendingRequest is a queued, not-yet-approved pair request. It records the
// peer's TRANSPORT-VERIFIED identity (never a body-supplied one) and confers
// nothing until an operator approves it.
type PendingRequest struct {
	PublicKey   string `json:"public_key"`
	FQDN        string `json:"fqdn,omitempty"`
	Label       string `json:"label,omitempty"`
	RequestedAt string `json:"requested_at"`
}

// PairedPeer is an operator-approved, RECOGNIZED peer identity. Recognition is
// not authorization (see the file's boundary note): it names a known peer, it
// does not grant that peer any tool or control capability.
type PairedPeer struct {
	PublicKey  string `json:"public_key"`
	FQDN       string `json:"fqdn,omitempty"`
	Label      string `json:"label,omitempty"`
	ApprovedAt string `json:"approved_at"`
	Approver   string `json:"approver"`
}

// pairedSchemaVersion is the current on-disk format version of the paired store.
const pairedSchemaVersion = 1

// pairedState is the on-disk shape of the whole store: the two sets, written
// together atomically so a reader never observes a torn half-update.
type pairedState struct {
	// SchemaVersion self-describes the file format; a store from a newer build is
	// refused on load (fail closed) rather than silently forgetting peers.
	SchemaVersion int              `json:"schema_version"`
	Pending       []PendingRequest `json:"pending"`
	Paired        []PairedPeer     `json:"paired"`
	// Denied is additive (older builds simply ignore it), so the schema version
	// stays 1 and existing stores keep loading both directions.
	Denied []DeniedRequest `json:"denied,omitempty"`
}

// PairedStore is an atomic, concurrency-safe store of pending pair requests and
// approved (recognized) peers. Every mutation is persisted with a temp+fsync+
// rename write (mirroring federation/dcr.go's writeAtomic), so an approval or
// revocation survives a crash and a concurrent reader never sees a partial file.
// It is keyed by the unforgeable WireGuard public key — the same cryptographic
// identity acl.allows matches on.
type PairedStore struct {
	mu      sync.Mutex
	path    string
	pending map[string]PendingRequest // keyed by public key
	paired  map[string]PairedPeer     // keyed by public key
	denied  map[string]DeniedRequest  // keyed by public key (advisory memory, not a ban)
}

// OpenPairedStore loads the store at path, or returns an empty store when the
// file does not yet exist. A present-but-unparseable file is a hard error
// rather than a silent reset, so a corrupt store never quietly forgets every
// approved peer (fail-closed, mirroring the DCR store's load posture).
func OpenPairedStore(path string) (*PairedStore, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("pairing: store path is empty")
	}
	s := &PairedStore{
		path:    path,
		pending: map[string]PendingRequest{},
		paired:  map[string]PairedPeer{},
		denied:  map[string]DeniedRequest{},
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return s, nil
		}
		return nil, fmt.Errorf("pairing: read store %s: %w", path, err)
	}
	var st pairedState
	if err := json.Unmarshal(b, &st); err != nil {
		return nil, fmt.Errorf("pairing: parse store %s: %w", path, err)
	}
	if err := checkSchemaVersion("pairing", st.SchemaVersion, pairedSchemaVersion); err != nil {
		return nil, err
	}
	for _, p := range st.Pending {
		if p.PublicKey != "" {
			s.pending[p.PublicKey] = p
		}
	}
	for _, p := range st.Paired {
		if p.PublicKey != "" {
			// A peer that is both paired and (stale) pending is recognized:
			// drop the redundant pending entry so the two sets stay disjoint.
			delete(s.pending, p.PublicKey)
			s.paired[p.PublicKey] = p
		}
	}
	for _, d := range st.Denied {
		if d.PublicKey == "" {
			continue
		}
		// Approved or re-pending supersedes a stale denial.
		if _, ok := s.paired[d.PublicKey]; ok {
			continue
		}
		if _, ok := s.pending[d.PublicKey]; ok {
			continue
		}
		s.denied[d.PublicKey] = d
	}
	return s, nil
}

// Request queues a pair request for a transport-verified identity. It GRANTS
// NOTHING: it records the peer so an operator can approve it later. added is
// true only when a NEW pending entry was created; a re-request from an already
// pending or already paired identity is idempotent (added=false), so a peer
// polling its own status cannot flood the store with duplicates.
func (s *PairedStore) Request(id VerifiedIdentity, label string, now time.Time) (PendingRequest, bool, error) {
	if err := validatePairIdentity(id); err != nil {
		return PendingRequest{}, false, err
	}
	label, err := cleanPairLabel(label)
	if err != nil {
		return PendingRequest{}, false, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.paired[id.PublicKey]; ok {
		return PendingRequest{}, false, nil // already recognized — nothing to queue
	}
	if existing, ok := s.pending[id.PublicKey]; ok {
		return existing, false, nil // dedup: idempotent re-request
	}
	if len(s.pending) >= DefaultPendingMax {
		return PendingRequest{}, false, fmt.Errorf("pairing: too many pending requests (max %d)", DefaultPendingMax)
	}

	req := PendingRequest{
		PublicKey:   id.PublicKey,
		FQDN:        id.FQDN,
		Label:       label,
		RequestedAt: now.UTC().Format(time.RFC3339),
	}
	// A fresh request supersedes a remembered denial — a decline is advisory
	// memory for the requester, never a ban; the operator decides again.
	prevDenied, hadDenied := s.denied[id.PublicKey]
	delete(s.denied, id.PublicKey)
	s.pending[id.PublicKey] = req
	if err := s.persistLocked(); err != nil {
		delete(s.pending, id.PublicKey) // roll back the in-memory change on a persist failure
		if hadDenied {
			s.denied[id.PublicKey] = prevDenied
		}
		return PendingRequest{}, false, err
	}
	return req, true, nil
}

// Approve moves a pending request into the paired (recognized) set. approver is
// the operator identity performing the approval, recorded for the audit trail.
// It is idempotent: approving an already-paired identity returns the existing
// record. This method establishes RECOGNITION only — it never grants a tool or
// control capability.
func (s *PairedStore) Approve(pubKey, approver string, now time.Time) (PairedPeer, error) {
	if pubKey == "" {
		return PairedPeer{}, fmt.Errorf("pairing: approve requires a public key")
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if existing, ok := s.paired[pubKey]; ok {
		return existing, nil // idempotent: already recognized
	}
	req, ok := s.pending[pubKey]
	if !ok {
		return PairedPeer{}, ErrNoPendingRequest
	}
	peer := PairedPeer{
		PublicKey:  req.PublicKey,
		FQDN:       req.FQDN,
		Label:      req.Label,
		ApprovedAt: now.UTC().Format(time.RFC3339),
		Approver:   approver,
	}
	s.paired[pubKey] = peer
	delete(s.pending, pubKey)
	if err := s.persistLocked(); err != nil {
		delete(s.paired, pubKey) // roll back both sides on a persist failure
		s.pending[pubKey] = req
		return PairedPeer{}, err
	}
	return peer, nil
}

// Deny drops a pending request without recognizing it, remembering the
// operator's reason so the requester can be told WHY (guided recovery — the
// requester polls status and sees "denied: <reason>" instead of silently
// vanishing from the queue). The reason is bounded and control-character free
// like a pair label; empty is fine. removed is false when no pending request
// existed for the identity (no denial is recorded then — there was nothing to
// decline).
func (s *PairedStore) Deny(pubKey, reason string, now time.Time) (bool, error) {
	reason, err := cleanPairLabel(reason)
	if err != nil {
		return false, fmt.Errorf("pairing: deny reason: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	req, ok := s.pending[pubKey]
	if !ok {
		return false, nil
	}
	delete(s.pending, pubKey)
	den := DeniedRequest{PublicKey: pubKey, Reason: reason, DeniedAt: now.UTC().Format(time.RFC3339)}
	s.denied[pubKey] = den
	s.evictDeniedLocked()
	if err := s.persistLocked(); err != nil {
		s.pending[pubKey] = req
		delete(s.denied, pubKey)
		return false, err
	}
	return true, nil
}

// evictDeniedLocked drops the oldest remembered denials over the cap. The
// caller holds s.mu.
func (s *PairedStore) evictDeniedLocked() {
	for len(s.denied) > maxDeniedRemembered {
		oldestKey, oldestAt := "", ""
		for k, d := range s.denied {
			if oldestKey == "" || d.DeniedAt < oldestAt || (d.DeniedAt == oldestAt && k < oldestKey) {
				oldestKey, oldestAt = k, d.DeniedAt
			}
		}
		delete(s.denied, oldestKey)
	}
}

// Revoke removes an approved peer, so it is no longer recognized. removed is
// false when the identity was not paired. Revocation must work: after it, a
// Recognized check for the identity returns false.
func (s *PairedStore) Revoke(pubKey string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	peer, ok := s.paired[pubKey]
	if !ok {
		return false, nil
	}
	delete(s.paired, pubKey)
	if err := s.persistLocked(); err != nil {
		s.paired[pubKey] = peer
		return false, err
	}
	return true, nil
}

// Recognized reports whether a transport-verified identity is an approved,
// paired peer. It matches on the unforgeable public key (the FQDN is advisory
// and never sufficient on its own), and fails closed on an empty key. This is
// NOT an authorization check — recognition is not capability; callers that gate
// a privileged surface must still consult that surface's own ACL.
func (s *PairedStore) Recognized(pubKey, fqdn string) bool {
	if pubKey == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.paired[pubKey]
	return ok
}

// Status returns the caller's own view of where it stands. It reveals only the
// queried identity's state — never anything about other peers.
func (s *PairedStore) Status(pubKey string) PairStatus {
	st, _ := s.StatusDetail(pubKey)
	return st
}

// StatusDetail is Status plus the operator's decline reason when the identity's
// last request was denied — so `air join` can tell the human WHY and what to do
// next instead of a bare "declined". The reason is only ever revealed to the
// identity it concerns (the caller queries its own transport-verified key).
func (s *PairedStore) StatusDetail(pubKey string) (PairStatus, string) {
	if pubKey == "" {
		return StatusNone, ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.paired[pubKey]; ok {
		return StatusApproved, ""
	}
	if _, ok := s.pending[pubKey]; ok {
		return StatusPending, ""
	}
	if d, ok := s.denied[pubKey]; ok {
		return StatusDenied, d.Reason
	}
	return StatusNone, ""
}

// Pending returns a deterministic snapshot of the queued requests (oldest
// first), copied so a caller cannot mutate the store's internal state.
func (s *PairedStore) Pending() []PendingRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return sortedPending(s.pending)
}

// Paired returns a deterministic snapshot of the recognized peers (oldest
// approval first), copied so a caller cannot mutate the store's internal state.
func (s *PairedStore) Paired() []PairedPeer {
	s.mu.Lock()
	defer s.mu.Unlock()
	return sortedPaired(s.paired)
}

// persistLocked writes the whole store atomically. The caller must hold s.mu.
// It mirrors federation/dcr.go's writeAtomic: write a sibling temp file, fsync
// it, then rename it into place, so a reader (or a crash) never observes a
// partially written store at the canonical path.
func (s *PairedStore) persistLocked() error {
	st := pairedState{SchemaVersion: pairedSchemaVersion, Pending: sortedPending(s.pending), Paired: sortedPaired(s.paired), Denied: sortedDenied(s.denied)}
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return fmt.Errorf("pairing: marshal store: %w", err)
	}
	if dir := filepath.Dir(s.path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("pairing: create store dir: %w", err)
		}
	}
	tmp := s.path + ".tmp-" + randPairSuffix()
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("pairing: open tmp file: %w", err)
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("pairing: write tmp file: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("pairing: sync tmp file: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("pairing: close tmp file: %w", err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("pairing: rename into place: %w", err)
	}
	return nil
}

func sortedPending(m map[string]PendingRequest) []PendingRequest {
	out := make([]PendingRequest, 0, len(m))
	for _, p := range m {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].RequestedAt != out[j].RequestedAt {
			return out[i].RequestedAt < out[j].RequestedAt
		}
		return out[i].PublicKey < out[j].PublicKey
	})
	return out
}

func sortedDenied(m map[string]DeniedRequest) []DeniedRequest {
	out := make([]DeniedRequest, 0, len(m))
	for _, d := range m {
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].DeniedAt != out[j].DeniedAt {
			return out[i].DeniedAt < out[j].DeniedAt
		}
		return out[i].PublicKey < out[j].PublicKey
	})
	return out
}

func sortedPaired(m map[string]PairedPeer) []PairedPeer {
	out := make([]PairedPeer, 0, len(m))
	for _, p := range m {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ApprovedAt != out[j].ApprovedAt {
			return out[i].ApprovedAt < out[j].ApprovedAt
		}
		return out[i].PublicKey < out[j].PublicKey
	})
	return out
}

// validatePairIdentity rejects an unusable or hostile transport identity,
// reusing presence's identity bounds (non-empty, length-capped, control-char
// free public key; an FQDN that is at most advisory).
func validatePairIdentity(id VerifiedIdentity) error {
	if id.PublicKey == "" || len(id.PublicKey) > maxPresenceIdentityText || hasControl(id.PublicKey) {
		return fmt.Errorf("pairing requires a valid transport-verified public key")
	}
	if len(id.FQDN) > maxPresenceIdentityText || hasControl(id.FQDN) {
		return fmt.Errorf("pairing has an invalid transport-verified FQDN")
	}
	return nil
}

// cleanPairLabel trims and bounds the peer-supplied label, rejecting control
// characters so it is safe to store and later render in a terminal.
func cleanPairLabel(label string) (string, error) {
	label = strings.TrimSpace(label)
	if len(label) > maxPairLabelBytes {
		return "", fmt.Errorf("pairing label too long (max %d bytes)", maxPairLabelBytes)
	}
	if hasControl(label) {
		return "", fmt.Errorf("pairing label has control characters")
	}
	return label, nil
}

func randPairSuffix() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
