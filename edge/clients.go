package edge

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// Client lifecycle states. A client can complete authorization and obtain
// tokens only in the approved state; every other state is a hard stop.
const (
	ClientPending  = "pending"
	ClientApproved = "approved"
	ClientDenied   = "denied"
	ClientRevoked  = "revoked"
)

// bcryptCost is the pinned work factor for the RFC 7592 registration access
// token hash — the same cost federation/dcr.go pins. It is a var, not a const,
// solely so tests can lower it (bcrypt at cost 12 across many registrations
// under -race is prohibitively slow); production never changes it.
var bcryptCost = 12

// ClientRecord is one registered OAuth client, persisted as clients/client-<id>.json.
// The registration access token is stored only as bcrypt(sha256(token)); the raw
// token is returned once at registration and never persisted.
type ClientRecord struct {
	ClientID                string    `json:"client_id"`
	ClientName              string    `json:"client_name"`
	RedirectURIs            []string  `json:"redirect_uris"`
	TokenEndpointAuthMethod string    `json:"token_endpoint_auth_method"`
	RegTokenHash            []byte    `json:"registration_access_token_hash"`
	RegistrationMode        string    `json:"registration_mode"` // open-approval | token
	Status                  string    `json:"status"`
	CreatedAt               time.Time `json:"created_at"`
	ApprovedBy              string    `json:"approved_by,omitempty"`
	ApprovedAt              time.Time `json:"approved_at,omitempty"`
}

// ClientStore is the file-backed registry of OAuth clients. It mirrors the DCR
// store discipline: 0700 dir, one 0600 JSON file per client, tmp+rename writes,
// per-client_id locking for read-modify-write safety.
type ClientStore struct {
	dir   string
	keyed keyedLocks
	now   func() time.Time
}

// NewClientStore opens (creating if needed) the client store under dir.
func NewClientStore(dir string, now func() time.Time) (*ClientStore, error) {
	if now == nil {
		now = time.Now
	}
	if err := secureDir(dir); err != nil {
		return nil, err
	}
	return &ClientStore{dir: dir, now: now}, nil
}

func (s *ClientStore) file(clientID string) string {
	return filepath.Join(s.dir, "client-"+clientID+".json")
}

// Create persists a new client. In open-approval mode it lands ClientPending;
// in token mode it lands ClientApproved (the operator vouched by minting the
// initial access token). It returns the record and the one-time raw
// registration access token.
func (s *ClientStore) Create(name string, redirectURIs []string, mode string) (ClientRecord, string, error) {
	clientID := "edge-" + randHex(16)
	unlock := s.keyed.lock(clientID)
	defer unlock()

	regToken := randToken()
	hash, err := hashRegToken(regToken)
	if err != nil {
		return ClientRecord{}, "", err
	}
	status := ClientPending
	if mode == RegistrationToken {
		status = ClientApproved
	}
	rec := ClientRecord{
		ClientID:                clientID,
		ClientName:              name,
		RedirectURIs:            redirectURIs,
		TokenEndpointAuthMethod: "none",
		RegTokenHash:            hash,
		RegistrationMode:        mode,
		Status:                  status,
		CreatedAt:               s.now().UTC(),
	}
	if status == ClientApproved {
		rec.ApprovedBy = "initial-access-token"
		rec.ApprovedAt = rec.CreatedAt
	}
	if err := writeAtomicJSON(s.file(clientID), rec); err != nil {
		return ClientRecord{}, "", err
	}
	return rec, regToken, nil
}

// Get returns the record for clientID, or os.ErrNotExist.
func (s *ClientStore) Get(clientID string) (ClientRecord, error) {
	var rec ClientRecord
	if err := readJSON(s.file(clientID), &rec); err != nil {
		return ClientRecord{}, err
	}
	return rec, nil
}

// VerifyRegToken reports whether raw is the client's registration access token
// (constant-time via bcrypt).
func (s *ClientStore) VerifyRegToken(rec ClientRecord, raw string) bool {
	return compareRegToken(rec.RegTokenHash, raw)
}

// transition sets a new status under the client lock, refusing illegal moves.
func (s *ClientStore) transition(clientID, to, by string) (ClientRecord, error) {
	unlock := s.keyed.lock(clientID)
	defer unlock()
	var rec ClientRecord
	if err := readJSON(s.file(clientID), &rec); err != nil {
		return ClientRecord{}, err
	}
	if rec.Status == ClientRevoked {
		return rec, fmt.Errorf("edge: client %s is revoked and cannot be %s", clientID, to)
	}
	rec.Status = to
	if to == ClientApproved {
		rec.ApprovedBy = by
		rec.ApprovedAt = s.now().UTC()
	}
	if err := writeAtomicJSON(s.file(clientID), rec); err != nil {
		return ClientRecord{}, err
	}
	return rec, nil
}

// Approve moves a client to approved, recording the approver.
func (s *ClientStore) Approve(clientID, by string) (ClientRecord, error) {
	return s.transition(clientID, ClientApproved, by)
}

// Deny moves a client to denied.
func (s *ClientStore) Deny(clientID, by string) (ClientRecord, error) {
	return s.transition(clientID, ClientDenied, by)
}

// Revoke moves a client to revoked (terminal). Token/session teardown is the
// caller's responsibility (see the revocation cascade).
func (s *ClientStore) Revoke(clientID, by string) (ClientRecord, error) {
	unlock := s.keyed.lock(clientID)
	defer unlock()
	var rec ClientRecord
	if err := readJSON(s.file(clientID), &rec); err != nil {
		return ClientRecord{}, err
	}
	rec.Status = ClientRevoked
	rec.ApprovedBy = by
	if err := writeAtomicJSON(s.file(clientID), rec); err != nil {
		return ClientRecord{}, err
	}
	return rec, nil
}

// List returns all client records sorted by creation time (newest first).
func (s *ClientStore) List() ([]ClientRecord, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []ClientRecord
	for _, e := range entries {
		if e.IsDir() || !strings.HasPrefix(e.Name(), "client-") || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		var rec ClientRecord
		if err := readJSON(filepath.Join(s.dir, e.Name()), &rec); err != nil {
			continue // skip unreadable/partial records rather than failing the whole list
		}
		out = append(out, rec)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

// CountPending returns how many clients are awaiting approval — the quantity the
// open-approval max_pending cap bounds.
func (s *ClientStore) CountPending() (int, error) {
	recs, err := s.List()
	if err != nil {
		return 0, err
	}
	n := 0
	for _, r := range recs {
		if r.Status == ClientPending {
			n++
		}
	}
	return n, nil
}

// hashRegToken hashes a registration access token as bcrypt(sha256(token)); the
// SHA-256 pre-hash is mandatory because bcrypt silently truncates inputs beyond
// 72 bytes.
func hashRegToken(raw string) ([]byte, error) {
	sum := sha256Bytes(raw)
	return bcrypt.GenerateFromPassword(sum, bcryptCost)
}

func compareRegToken(hash []byte, raw string) bool {
	if len(hash) == 0 {
		return false
	}
	return bcrypt.CompareHashAndPassword(hash, sha256Bytes(raw)) == nil
}
