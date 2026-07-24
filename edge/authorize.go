package edge

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/xrey167/meshmcp/protocol/authorization"
)

// Authorization-request lifecycle. A request is created pending, an operator
// approves it, and the first status poll after approval mints the code and
// completes it (so exactly one code is issued per authorization).
const (
	authzPending   = "pending"
	authzApproved  = "approved"
	authzDenied    = "denied"
	authzCompleted = "completed"
)

// authzRecord is one in-flight authorization request, persisted as
// authz/authz-<request_id>.json. Only a hash of the client's state is stored —
// the raw state is echoed back in the redirect but never needs to be at rest.
type authzRecord struct {
	RequestID     string    `json:"request_id"`
	ClientID      string    `json:"client_id"`
	ClientName    string    `json:"client_name"`
	RedirectURI   string    `json:"redirect_uri"`
	CodeChallenge string    `json:"code_challenge"` // S256 only
	Scope         string    `json:"scope"`
	Resource      string    `json:"resource"`
	State         string    `json:"state"`
	Status        string    `json:"status"`
	CreatedAt     time.Time `json:"created_at"`
	ExpiresAt     time.Time `json:"expires_at"`
}

// AuthzStore is the file-backed store of pending authorization requests. It is
// exported so the operator CLI (meshmcp edge authz ...) can decide requests by
// operating on the same state directory the daemon reads.
type AuthzStore struct {
	dir   string
	keyed keyedLocks
	now   func() time.Time
}

func NewAuthzStore(dir string, now func() time.Time) (*AuthzStore, error) {
	if now == nil {
		now = time.Now
	}
	if err := secureDir(dir); err != nil {
		return nil, err
	}
	return &AuthzStore{dir: dir, now: now}, nil
}

func (s *AuthzStore) file(id string) string { return filepath.Join(s.dir, "authz-"+id+".json") }

func (s *AuthzStore) put(rec authzRecord) error { return writeAtomicJSON(s.file(rec.RequestID), rec) }

func (s *AuthzStore) get(id string) (authzRecord, error) {
	var rec authzRecord
	if err := readJSON(s.file(id), &rec); err != nil {
		return authzRecord{}, err
	}
	return rec, nil
}

// setStatus transitions an authorization request under its lock.
func (s *AuthzStore) setStatus(id, to, by string) (authzRecord, error) {
	unlock := s.keyed.lock(id)
	defer unlock()
	rec, err := s.get(id)
	if err != nil {
		return authzRecord{}, err
	}
	rec.Status = to
	if err := s.put(rec); err != nil {
		return authzRecord{}, err
	}
	return rec, nil
}

// Approve marks a pending authorization request approved (operator action).
func (s *AuthzStore) Approve(id, by string) error {
	_, err := s.setStatus(id, authzApproved, by)
	return err
}

// Deny marks a pending authorization request denied (operator action).
func (s *AuthzStore) Deny(id, by string) error {
	_, err := s.setStatus(id, authzDenied, by)
	return err
}

// PendingView is a CLI-facing projection of a pending authorization request.
type PendingView struct {
	RequestID  string
	ClientID   string
	ClientName string
	Status     string
	CreatedAt  time.Time
}

// ListPending returns authorization requests awaiting a decision, newest first.
func (s *AuthzStore) ListPending() ([]PendingView, error) {
	recs, err := s.list()
	if err != nil {
		return nil, err
	}
	var out []PendingView
	for _, r := range recs {
		if r.Status == authzPending {
			out = append(out, PendingView{r.RequestID, r.ClientID, r.ClientName, r.Status, r.CreatedAt})
		}
	}
	return out, nil
}

func (s *AuthzStore) list() ([]authzRecord, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []authzRecord
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), "authz-") || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		var rec authzRecord
		if err := readJSON(filepath.Join(s.dir, e.Name()), &rec); err != nil {
			continue
		}
		out = append(out, rec)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

// handleAuthorize is the OAuth 2.1 authorization endpoint (GET). It validates
// the request, persists a pending authorization, and returns a self-contained
// consent page that polls for the operator's decision. No credential is
// collected in the browser — approval happens out of band via the operator CLI.
func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	if !s.preauthLimit.allow(s.rateLimitKey(r)) {
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}
	q := r.URL.Query()
	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")

	rec, err := s.clients.Get(clientID)
	if err != nil || rec.Status == ClientRevoked || rec.Status == ClientDenied {
		// Unknown/rejected client: render an error page, never redirect (we can't
		// trust an unvalidated redirect target).
		s.renderAuthzError(w, "unknown or unauthorized client")
		return
	}
	if !exactURIMatch(rec.RedirectURIs, redirectURI) {
		s.renderAuthzError(w, "redirect_uri does not exactly match a registered redirect URI")
		return
	}
	// From here the redirect_uri is trusted, so protocol errors go back to the
	// client as an OAuth error redirect (RFC 6749 §4.1.2.1).
	if q.Get("response_type") != authorization.ResponseTypeCode {
		s.redirectError(w, r, redirectURI, q.Get("state"), "unsupported_response_type")
		return
	}
	if q.Get("code_challenge_method") != authorization.PKCECodeChallengeS256 || q.Get("code_challenge") == "" {
		s.redirectError(w, r, redirectURI, q.Get("state"), "invalid_request") // PKCE S256 is mandatory
		return
	}
	if rec.Status != ClientApproved {
		// A pending (not-yet-approved) client cannot authorize.
		s.renderAuthzError(w, "this client is registered but awaiting operator approval; try again once it is approved")
		return
	}

	reqID := randHex(16)
	now := s.now().UTC()
	authz := authzRecord{
		RequestID:     reqID,
		ClientID:      clientID,
		ClientName:    rec.ClientName,
		RedirectURI:   redirectURI,
		CodeChallenge: q.Get("code_challenge"),
		Scope:         q.Get("scope"),
		Resource:      q.Get("resource"),
		State:         q.Get("state"),
		Status:        authzPending,
		CreatedAt:     now,
		ExpiresAt:     now.Add(s.cfg.OAuth.AuthzPendingTTL.Std()),
	}
	if err := s.authz.put(authz); err != nil {
		s.renderAuthzError(w, "could not record the authorization request")
		return
	}
	s.renderConsentPage(w, authz)
}

// handleAuthorizeStatus is the side-effect-free-ish poll the consent page uses.
// It reports pending/denied/expired, and on first observation of an approved
// request mints the single authorization code and returns the redirect target.
func (s *Server) handleAuthorizeStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	id := r.URL.Query().Get("request_id")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"status": "error"})
		return
	}
	unlock := s.authz.keyed.lock(id)
	defer unlock()
	rec, err := s.authz.get(id)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"status": "not_found"})
		return
	}
	if s.now().After(rec.ExpiresAt) && rec.Status == authzPending {
		writeJSON(w, http.StatusOK, map[string]string{"status": "expired"})
		return
	}
	switch rec.Status {
	case authzPending:
		writeJSON(w, http.StatusOK, map[string]string{"status": "pending"})
	case authzDenied:
		writeJSON(w, http.StatusOK, map[string]string{"status": "denied"})
	case authzApproved:
		// Mint the one code for this authorization and complete it.
		code, err := s.codes.issue(rec, s.now())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"status": "error"})
			return
		}
		rec.Status = authzCompleted
		_ = s.authz.put(rec)
		writeJSON(w, http.StatusOK, map[string]string{"status": "approved", "redirect": redirectWithCode(rec.RedirectURI, code, rec.State)})
	case authzCompleted:
		// Already completed; the client should have consumed the code. Tell the
		// page the flow is done so it stops polling.
		writeJSON(w, http.StatusOK, map[string]string{"status": "completed"})
	default:
		writeJSON(w, http.StatusOK, map[string]string{"status": "pending"})
	}
}

// exactURIMatch reports whether uri exactly equals one of the registered URIs.
// No normalization is performed — exact string match is the OAuth security rule.
func exactURIMatch(registered []string, uri string) bool {
	if uri == "" {
		return false
	}
	for _, r := range registered {
		if r == uri {
			return true
		}
	}
	return false
}

func redirectWithCode(redirectURI, code, state string) string {
	u, err := url.Parse(redirectURI)
	if err != nil {
		return redirectURI
	}
	q := u.Query()
	q.Set("code", code)
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// redirectError sends an OAuth error back to a validated redirect_uri.
func (s *Server) redirectError(w http.ResponseWriter, r *http.Request, redirectURI, state, code string) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		s.renderAuthzError(w, code)
		return
	}
	q := u.Query()
	q.Set("error", code)
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

// pkceVerify reports whether verifier matches challenge under S256:
// base64url(SHA256(verifier)) == challenge.
func pkceVerify(verifier, challenge string) bool {
	if verifier == "" || challenge == "" {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:]) == challenge
}
