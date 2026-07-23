package edge

import (
	"os"
	"path/filepath"
	"time"
)

// codeTTL bounds an authorization code's life (OAuth 2.1 recommends ≤ ~1 min;
// codes are single-use regardless).
const codeTTL = 120 * time.Second

// codeRecord is a single-use authorization code, persisted by the hash of the
// code. It binds the PKCE challenge, redirect_uri, client, and requested
// resource so the token exchange can re-check all of them.
type codeRecord struct {
	ClientID      string    `json:"client_id"`
	RedirectURI   string    `json:"redirect_uri"`
	CodeChallenge string    `json:"code_challenge"`
	Scope         string    `json:"scope"`
	Resource      string    `json:"resource"`
	ExpiresAt     time.Time `json:"expires_at"`
}

// codeStore persists authorization codes. Consumption is claim-by-rename so
// exactly one token exchange can redeem a code even across processes.
type codeStore struct {
	dir string
}

func newCodeStore(dir string) (*codeStore, error) {
	if err := secureDir(dir); err != nil {
		return nil, err
	}
	return &codeStore{dir: dir}, nil
}

func (s *codeStore) file(code string) string {
	return filepath.Join(s.dir, "code-"+sha256Hex(code)+".json")
}

// issue mints a code for an approved authorization request.
func (s *codeStore) issue(authz authzRecord, now time.Time) (string, error) {
	code := randToken()
	rec := codeRecord{
		ClientID:      authz.ClientID,
		RedirectURI:   authz.RedirectURI,
		CodeChallenge: authz.CodeChallenge,
		Scope:         authz.Scope,
		Resource:      authz.Resource,
		ExpiresAt:     now.Add(codeTTL),
	}
	if err := writeAtomicJSON(s.file(code), rec); err != nil {
		return "", err
	}
	return code, nil
}

// consume atomically claims a code, returning its record. A second attempt to
// consume the same code observes os.ErrNotExist.
func (s *codeStore) consume(code string) (codeRecord, error) {
	var rec codeRecord
	if err := claimByRename(s.file(code), &rec); err != nil {
		return codeRecord{}, err
	}
	return rec, nil
}

// accessRecord is an issued access token, persisted by the hash of the token.
// It carries the signed capability so the MCP path re-verifies a real Ed25519
// grant on every call rather than trusting the on-disk record.
type accessRecord struct {
	ClientID   string    `json:"client_id"`
	FamilyID   string    `json:"family_id"`
	Capability string    `json:"capability"` // signed policy.CapabilityClaims token
	CapID      string    `json:"cap_id"`
	Resource   string    `json:"resource"`
	ExpiresAt  time.Time `json:"expires_at"`
}

// refreshRecord is a refresh token in a rotation family. Presence of RotatedTo
// means it was already used; presenting a rotated token again is reuse and
// triggers family revocation (outside the replay-grace window).
type refreshRecord struct {
	ClientID   string    `json:"client_id"`
	FamilyID   string    `json:"family_id"`
	Generation int       `json:"generation"`
	RotatedTo  string    `json:"rotated_to,omitempty"` // sha256 of the successor
	RotatedAt  time.Time `json:"rotated_at,omitempty"`
	ExpiresAt  time.Time `json:"expires_at"`
}

// tokenStore persists access and refresh tokens.
type tokenStore struct {
	dir    string
	rotate keyedLocks // serializes rotation of a single refresh token
}

func newTokenStore(dir string) (*tokenStore, error) {
	if err := secureDir(dir); err != nil {
		return nil, err
	}
	return &tokenStore{dir: dir}, nil
}

func (s *tokenStore) accessFile(tok string) string {
	return filepath.Join(s.dir, "access-"+sha256Hex(tok)+".json")
}
func (s *tokenStore) refreshFile(tok string) string {
	return filepath.Join(s.dir, "refresh-"+sha256Hex(tok)+".json")
}

// putAccess writes an access-token record and returns the raw token.
func (s *tokenStore) putAccess(rec accessRecord) (string, error) {
	tok := randToken()
	if err := writeAtomicJSON(s.accessFile(tok), rec); err != nil {
		return "", err
	}
	return tok, nil
}

// getAccess reads an access-token record by its raw token (os.ErrNotExist if
// unknown).
func (s *tokenStore) getAccess(tok string) (accessRecord, error) {
	var rec accessRecord
	if err := readJSON(s.accessFile(tok), &rec); err != nil {
		return accessRecord{}, err
	}
	return rec, nil
}

// putRefresh writes a refresh-token record and returns the raw token.
func (s *tokenStore) putRefresh(rec refreshRecord) (string, error) {
	tok := randToken()
	if err := writeAtomicJSON(s.refreshFile(tok), rec); err != nil {
		return "", err
	}
	return tok, nil
}

func (s *tokenStore) getRefresh(tok string) (refreshRecord, error) {
	var rec refreshRecord
	if err := readJSON(s.refreshFile(tok), &rec); err != nil {
		return refreshRecord{}, err
	}
	return rec, nil
}

// markRotated records that a refresh token was consumed, pointing at its
// successor. A later presentation of the same token is detectable reuse.
func (s *tokenStore) markRotated(tok, successorHash string, rec refreshRecord, at time.Time) error {
	rec.RotatedTo = successorHash
	rec.RotatedAt = at
	return writeAtomicJSON(s.refreshFile(tok), rec)
}

// revokeFamily deletes every access and refresh token belonging to familyID —
// the theft-detection response to a rotated-refresh-token reuse, and the token
// half of a client revocation.
func (s *tokenStore) revokeFamily(familyID string) error {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	for _, e := range entries {
		path := filepath.Join(s.dir, e.Name())
		if fam := familyOf(path, e.Name()); fam == familyID {
			_ = os.Remove(path)
		}
	}
	return nil
}

// familyOf reads a token record's family id (best-effort; unreadable files are
// skipped by returning "").
func familyOf(path, name string) string {
	switch {
	case hasPrefixSuffix(name, "access-", ".json"):
		var rec accessRecord
		if readJSON(path, &rec) == nil {
			return rec.FamilyID
		}
	case hasPrefixSuffix(name, "refresh-", ".json"):
		var rec refreshRecord
		if readJSON(path, &rec) == nil {
			return rec.FamilyID
		}
	}
	return ""
}

func hasPrefixSuffix(s, prefix, suffix string) bool {
	return len(s) >= len(prefix)+len(suffix) && s[:len(prefix)] == prefix && s[len(s)-len(suffix):] == suffix
}
