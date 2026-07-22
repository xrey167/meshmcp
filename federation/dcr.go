// Package federation, this file: RFC 7591 Dynamic Client Registration and
// RFC 7592 client management for Feature C1 of docs/spec/OAUTH-STANDARDS.md.
//
// This is a standalone, independently-testable http.Handler surface — it is
// NOT wired into federate.go's buildBoundaryServer or any live listener in
// this slice (that is Feature C3, deliberately deferred; see the design
// doc's "exposure-model question"). Every endpoint here is exercised only via
// httptest.NewServer / direct ServeHTTP calls in dcr_test.go.
package federation

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/xrey167/meshmcp/policy"
)

// bcryptCost is the pinned work factor for registration_access_token hashes.
// Pinned per docs/spec/OAUTH-STANDARDS.md Feature C1 ("pin a cost factor
// explicitly, recommended 12") — TestDCR_BcryptCostFactorPinned guards
// against this being silently retuned without updating that document.
const bcryptCost = 12

// dcrMaxBodyBytes bounds every C1 request body (mirrors the S26
// http.MaxBytesReader control already applied to /v1/approve and /v1/deny).
const dcrMaxBodyBytes = 16 << 10

// registrationSourceInternal / registrationSourceDCR are the only two
// recognized values of a stored client record's registration_source. Any
// other value — including empty/missing, or a value that fails to parse at
// all — must be treated as unreadable and refused, never defaulted to "dcr"
// (this is the P0-3/F22-class fail-open bug this store is required not to
// repeat; see docs/spec/OAUTH-STANDARDS.md Feature C1).
const (
	registrationSourceInternal = "internal"
	registrationSourceDCR      = "dcr"
)

// scopeClientRegister is the only scope the registration endpoint accepts.
const scopeClientRegister = "client:register"

// defaultMaxClientsPerToken bounds live registered client_ids attributable to
// a single initial access token when InitialAccessToken.MaxClients is unset,
// so registration can never unboundedly exhaust disk/inodes.
const defaultMaxClientsPerToken = 50

// defaultManageMax / defaultManageWindow bound the bcrypt-bearing management
// path (GET/PUT/DELETE) per source address — bcrypt is deliberately
// CPU-expensive, and this path is reachable by a party with no established
// identity at all, so an unbounded attempt rate is a CPU-exhaustion DoS.
const (
	defaultManageMax    = 30
	defaultManageWindow = time.Minute
)

// InitialAccessToken is a bootstrap bearer credential that gates
// POST /oauth2/register. This is a deliberate, documented exception to
// meshmcp's "never a plain bearer token" rule (see design doc "Bearer-token
// exceptions"): a first-time registrant has no DPoP key yet, and RFC
// 7591/7592 define this credential as bearer per spec. It is never usable
// for tool access — only for the registration/management surface.
type InitialAccessToken struct {
	Token  string   // raw configured secret, compared in constant time
	Scopes []string // must include scopeClientRegister to register a client
	// MaxClients caps how many live (non-deleted) client_ids may exist under
	// this token at once. <= 0 falls back to defaultMaxClientsPerToken.
	MaxClients int
}

// clientRecord is the on-disk shape of one registered/provisioned client,
// mirroring policy/approval_token.go's FileApprovalStore conventions: one
// 0600 JSON file per client_id in a 0700 dir, written via tmp+rename.
type clientRecord struct {
	ClientID   string `json:"client_id"`
	ClientName string `json:"client_name,omitempty"`
	// RegistrationTokenHash is bcrypt(sha256(registration_access_token)),
	// cost bcryptCost. The SHA-256 pre-hash is mandatory, not optional:
	// bcrypt silently truncates input past 72 bytes, so hashing the raw
	// token directly would let two distinct long tokens sharing a 72-byte
	// prefix collide (see TestDCR_LongTokenPreHashedBeforeBcrypt).
	RegistrationTokenHash string `json:"registration_access_token_hash"`
	RegistrationSource    string `json:"registration_source"`
	// IssuerTokenHash is sha256(initial_access_token) hex, recorded so the
	// per-token registration quota can be counted by scanning the store
	// without ever persisting the raw initial access token. Empty for
	// admin-provisioned ("internal") records, which were not created via an
	// initial access token at all.
	IssuerTokenHash string `json:"issuer_token_hash,omitempty"`
	CreatedAt       int64  `json:"created_at"`
}

// errRecordNotFound / errRecordUnreadable are sentinels distinguishing "this
// client_id was never registered" (404 is fine) from every other failure mode
// (read error, unparseable JSON, unknown registration_source), which must all
// be treated as "refuse the mutating request" — never as "not internal,
// therefore allowed" (the fail-closed requirement this slice exists to
// enforce).
var (
	errRecordNotFound   = errors.New("dcr: client record not found")
	errRecordUnreadable = errors.New("dcr: client record unreadable")
)

// keyedLocks serializes critical sections by an arbitrary string key. It is
// the concurrency control for the two load-then-write sequences in this store
// that a shared filesystem cannot make atomic on its own: the per-client_id
// manage path (a concurrent DELETE and PUT must not both pass token
// verification and then race on disk, silently resurrecting a deleted client
// with its old token still valid) and the per-issuer registration path (K
// concurrent registrations under one initial access token must not all read
// the pre-write quota count and all pass the cap before any persists). The key
// space is bounded — live client_ids are quota-capped and issuer hashes are
// bounded by the configured token set — so the map is never pruned.
type keyedLocks struct {
	mu    sync.Mutex
	locks map[string]*sync.Mutex
}

// lock acquires the mutex for key, creating it on first use, and returns its
// unlock func (defer it). Distinct keys never block each other.
func (k *keyedLocks) lock(key string) func() {
	k.mu.Lock()
	if k.locks == nil {
		k.locks = map[string]*sync.Mutex{}
	}
	m := k.locks[key]
	if m == nil {
		m = &sync.Mutex{}
		k.locks[key] = m
	}
	k.mu.Unlock()
	m.Lock()
	return m.Unlock
}

// rateLimiter is a simple fixed-window request cap keyed by an arbitrary
// string (here, the caller's source IP), sized for the bcrypt-bearing
// management path where a token bucket's extra precision isn't worth the
// complexity — the goal is bounding attempt volume, not smoothing bursts.
type rateLimiter struct {
	mu     sync.Mutex
	max    int
	window time.Duration
	hits   map[string][]time.Time
}

func newRateLimiter(max int, window time.Duration) *rateLimiter {
	if max <= 0 {
		max = defaultManageMax
	}
	if window <= 0 {
		window = defaultManageWindow
	}
	return &rateLimiter{max: max, window: window, hits: map[string][]time.Time{}}
}

func (rl *rateLimiter) allow(key string, now time.Time) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	cutoff := now.Add(-rl.window)
	prev := rl.hits[key]
	kept := prev[:0]
	for _, t := range prev {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	if len(kept) >= rl.max {
		rl.hits[key] = kept
		return false
	}
	rl.hits[key] = append(kept, now)
	return true
}

// DCRStore is the RFC 7591/7592 client registration + management store. It
// implements the full request lifecycle as plain http.HandlerFuncs, returned
// by Handler — no listener is created or bound here (see the package doc
// comment and the design doc's exposure-model question).
type DCRStore struct {
	Dir    string
	Tokens []InitialAccessToken
	// Audit receives one record per registration/management/deletion state
	// transition. A nil Audit, or any error from Append, denies the
	// operation outright (F22 fail-closed semantics) — this store has no
	// best-effort audit mode, unlike policy.AuditLog's opt-in FailClosed.
	// Wiring a real sink here (rather than the no-op test double used in
	// dcr_test.go) is an open issue carried to Feature C3.
	Audit policy.AuditSink

	manageLimiter *rateLimiter
	now           func() time.Time // injectable clock for tests; nil = time.Now

	// keyed serializes the load-then-write critical sections that the
	// filesystem cannot make atomic: per-client_id on the manage path and
	// per-issuer on the registration path. See keyedLocks.
	keyed keyedLocks
}

// NewDCRStore builds a store rooted at dir with the given initial access
// tokens and audit sink.
func NewDCRStore(dir string, tokens []InitialAccessToken, audit policy.AuditSink) *DCRStore {
	return &DCRStore{
		Dir:           dir,
		Tokens:        tokens,
		Audit:         audit,
		manageLimiter: newRateLimiter(defaultManageMax, defaultManageWindow),
	}
}

// SetManageRateLimit overrides the management-path rate limit (test hook;
// production callers can leave the default).
func (s *DCRStore) SetManageRateLimit(max int, window time.Duration) {
	s.manageLimiter = newRateLimiter(max, window)
}

func (s *DCRStore) clock() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now()
}

// Handler returns the RFC 7591/7592 mux: POST /oauth2/register and
// GET/PUT/DELETE /oauth2/register/{client_id}. Callers exercise it via
// httptest.NewServer or ServeHTTP directly; production wiring (choice of
// listener, TLS) is explicitly out of scope for this slice.
func (s *DCRStore) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth2/register", s.handleRegister)
	mux.HandleFunc("/oauth2/register/", s.handleManage)
	return mux
}

// NewDCRServer builds an *http.Server for the C1 endpoints with the same
// Slowloris controls already applied to the mesh-facing loopback surfaces
// (S26/S27, httpserve.go) — required here even more, since this handler is
// reachable by a party holding no established mesh identity at all.
func NewDCRServer(addr string, h http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
}

func (s *DCRStore) file(clientID string) string {
	return filepath.Join(s.Dir, "client-"+clientID+".json")
}

// hashRegistrationToken SHA-256 pre-hashes raw before bcrypt so a token
// longer than 72 bytes cannot be silently truncated by bcrypt into losing
// entropy (RFC 7592 token; see docs/spec/OAUTH-STANDARDS.md Feature C1).
func hashRegistrationToken(raw string) ([]byte, error) {
	sum := sha256.Sum256([]byte(raw))
	return bcrypt.GenerateFromPassword(sum[:], bcryptCost)
}

// verifyRegistrationToken reports whether raw is the token that produced
// hash, via bcrypt's own constant-time compare (never a manual ==).
func verifyRegistrationToken(hash []byte, raw string) bool {
	sum := sha256.Sum256([]byte(raw))
	return bcrypt.CompareHashAndPassword(hash, sum[:]) == nil
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func newClientID() string { return "dcr-" + randHex(16) }

func newRegistrationToken() string { return randHex(32) }

// load reads and validates a client record, refusing to distinguish "unknown
// registration_source" from any other read/parse failure: every one of these
// is refused identically by the caller (see errRecordUnreadable's doc
// comment) so a corrupt or partially-written record is never treated as
// deletable by omission.
func (s *DCRStore) load(clientID string) (clientRecord, error) {
	var rec clientRecord
	b, err := os.ReadFile(s.file(clientID))
	if err != nil {
		if os.IsNotExist(err) {
			return rec, errRecordNotFound
		}
		return rec, fmt.Errorf("%w: %v", errRecordUnreadable, err)
	}
	if err := json.Unmarshal(b, &rec); err != nil {
		return rec, fmt.Errorf("%w: unparseable json: %v", errRecordUnreadable, err)
	}
	if rec.RegistrationSource != registrationSourceInternal && rec.RegistrationSource != registrationSourceDCR {
		return rec, fmt.Errorf("%w: missing/unrecognized registration_source", errRecordUnreadable)
	}
	return rec, nil
}

// writeAtomic persists rec via tmp-file + os.Rename, so a reader can never
// observe a partially-written record at the canonical path (mirrors
// policy/approval_token.go's FileApprovalStore.Grant).
func (s *DCRStore) writeAtomic(clientID string, rec clientRecord) error {
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return fmt.Errorf("dcr: create store dir: %w", err)
	}
	// MkdirAll preserves the mode of an existing directory. The DCR store may
	// contain registration access-token hashes, so repair a pre-created path
	// (for example an operator-provisioned mount) to the same private boundary
	// promised for a newly created store.
	if err := os.Chmod(s.Dir, 0o700); err != nil {
		return fmt.Errorf("dcr: secure store dir: %w", err)
	}
	b, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return fmt.Errorf("dcr: marshal record: %w", err)
	}
	dst := s.file(clientID)
	tmp := dst + ".tmp-" + randHex(8)
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("dcr: open tmp file: %w", err)
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("dcr: write tmp file: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("dcr: sync tmp file: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("dcr: close tmp file: %w", err)
	}
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("dcr: rename into place: %w", err)
	}
	return nil
}

// removeAtomic deletes a client record via rename-then-remove, so the
// canonical path is never left half-removed for a concurrent reader.
func (s *DCRStore) removeAtomic(clientID string) error {
	dst := s.file(clientID)
	tmp := dst + ".deleted-" + randHex(8)
	if err := os.Rename(dst, tmp); err != nil {
		return fmt.Errorf("dcr: rename for delete: %w", err)
	}
	return os.Remove(tmp)
}

// liveCountForIssuer counts live client records attributed to a given
// initial-access-token hash, by scanning the store directory. O(files in
// dir) is acceptable here: the whole point of the quota is to keep that
// count small.
func (s *DCRStore) liveCountForIssuer(issuerHashHex string) (int, error) {
	entries, err := os.ReadDir(s.Dir)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	n := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasPrefix(name, "client-") || !strings.HasSuffix(name, ".json") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(s.Dir, name))
		if err != nil {
			continue // a concurrently-deleted file is not "live"
		}
		var rec clientRecord
		if json.Unmarshal(b, &rec) != nil {
			continue
		}
		if rec.IssuerTokenHash == issuerHashHex {
			n++
		}
	}
	return n, nil
}

func (s *DCRStore) findToken(presented string) *InitialAccessToken {
	for i := range s.Tokens {
		if subtle.ConstantTimeCompare([]byte(s.Tokens[i].Token), []byte(presented)) == 1 {
			return &s.Tokens[i]
		}
	}
	return nil
}

func hasScope(scopes []string, want string) bool {
	for _, sc := range scopes {
		if sc == want {
			return true
		}
	}
	return false
}

func bearerToken(r *http.Request) (string, bool) {
	const prefix = "Bearer "
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, prefix) {
		return "", false
	}
	return strings.TrimPrefix(h, prefix), true
}

func clientIPKey(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func writeDCRJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// audit appends one C1 state-transition record and fails closed: a nil sink
// or an Append error both deny the caller's operation (F22 semantics) —
// there is no best-effort mode here, unlike policy.AuditLog's opt-in
// FailClosed. A real production sink (rather than the no-op/failing test
// doubles used in dcr_test.go) is an open issue for Feature C3.
func (s *DCRStore) audit(rec policy.AuditRecord) error {
	if s.Audit == nil {
		return fmt.Errorf("dcr: no audit sink configured (fail-closed)")
	}
	return s.Audit.Append(rec)
}

func auditRegisterRecord(clientID string) policy.AuditRecord {
	return policy.AuditRecord{Backend: "dcr-facade", Peer: clientID, Method: "oauth2/register", Decision: "allow"}
}

func auditManageRecord(clientID, op string) policy.AuditRecord {
	return policy.AuditRecord{Backend: "dcr-facade", Peer: clientID, Method: "oauth2/register/" + op, Decision: "allow"}
}

// registerRequestBody is the subset of RFC 7591 client metadata this façade
// accepts; unrecognized fields are ignored (this is a bootstrap for a
// federation partner, not a general-purpose AS).
type registerRequestBody struct {
	ClientName string `json:"client_name"`
}

func (s *DCRStore) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	// Token/scope check happens before anything else touches the store or
	// the request body — an invalid registrant is rejected before the store
	// is consulted at all (TestDCR_RegisterRequiresValidInitialAccessToken).
	presented, ok := bearerToken(r)
	if !ok {
		http.Error(w, "missing bearer initial access token", http.StatusUnauthorized)
		return
	}
	iat := s.findToken(presented)
	if iat == nil || !hasScope(iat.Scopes, scopeClientRegister) {
		http.Error(w, "invalid initial access token or missing client:register scope", http.StatusUnauthorized)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, dcrMaxBodyBytes)
	var meta registerRequestBody
	if r.ContentLength != 0 {
		if err := json.NewDecoder(r.Body).Decode(&meta); err != nil {
			http.Error(w, "malformed or oversized registration metadata", http.StatusBadRequest)
			return
		}
	}

	issuerSum := sha256.Sum256([]byte(presented))
	issuerHashHex := hex.EncodeToString(issuerSum[:])
	maxClients := iat.MaxClients
	if maxClients <= 0 {
		maxClients = defaultMaxClientsPerToken
	}
	// Serialize the count-then-write per issuer token so concurrent
	// registrations under the same initial access token cannot each observe
	// the pre-write count and all pass the quota check (the TOCTOU the bcrypt
	// step below widens to hundreds of ms). Distinct issuer tokens never
	// contend. Held across bcrypt + audit + write, which is correct: the whole
	// sequence must be atomic w.r.t. the live count it just read.
	unlock := s.keyed.lock("issuer:" + issuerHashHex)
	defer unlock()
	n, err := s.liveCountForIssuer(issuerHashHex)
	if err != nil {
		http.Error(w, "registration store unavailable", http.StatusInternalServerError)
		return
	}
	if n >= maxClients {
		http.Error(w, "registration quota exceeded for this initial access token", http.StatusTooManyRequests)
		return
	}

	clientID := newClientID()
	regToken := newRegistrationToken()
	hash, err := hashRegistrationToken(regToken)
	if err != nil {
		http.Error(w, "failed to hash registration token", http.StatusInternalServerError)
		return
	}
	now := s.clock()
	rec := clientRecord{
		ClientID:              clientID,
		ClientName:            meta.ClientName,
		RegistrationTokenHash: string(hash),
		RegistrationSource:    registrationSourceDCR,
		IssuerTokenHash:       issuerHashHex,
		CreatedAt:             now.Unix(),
	}

	// Audit BEFORE the store mutation: if the audit write fails, the
	// registration must never happen (F22 fail-closed semantics) — a client
	// must never end up registered without a corresponding landed audit
	// record (TestDCR_AuditWriteFailureDeniesRegistration).
	if err := s.audit(auditRegisterRecord(clientID)); err != nil {
		http.Error(w, "registration denied: audit sink unavailable", http.StatusServiceUnavailable)
		return
	}
	if err := s.writeAtomic(clientID, rec); err != nil {
		http.Error(w, "failed to persist client record", http.StatusInternalServerError)
		return
	}

	writeDCRJSON(w, http.StatusCreated, map[string]any{
		"client_id":                 clientID,
		"client_id_issued_at":       now.Unix(),
		"client_name":               meta.ClientName,
		"registration_access_token": regToken,
		"registration_client_uri":   "/oauth2/register/" + clientID,
	})
}

func (s *DCRStore) handleManage(w http.ResponseWriter, r *http.Request) {
	clientID := strings.TrimPrefix(r.URL.Path, "/oauth2/register/")
	if clientID == "" || strings.Contains(clientID, "/") {
		http.NotFound(w, r)
		return
	}
	// Rate-limit the bcrypt-bearing path per source address before doing any
	// bcrypt work — bcrypt cost 12 is deliberately CPU-expensive, and this
	// path is reachable by a party with no established identity at all.
	if !s.manageLimiter.allow(clientIPKey(r), s.clock()) {
		http.Error(w, "too many management attempts, slow down", http.StatusTooManyRequests)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, dcrMaxBodyBytes)

	presented, ok := bearerToken(r)
	if !ok {
		http.Error(w, "missing bearer registration_access_token", http.StatusUnauthorized)
		return
	}

	// Serialize the load → verify → write/remove sequence per client_id, so a
	// concurrent DELETE and PUT against the same client cannot both pass token
	// verification against the still-present record and then race on disk —
	// which could let PUT's writeAtomic land after DELETE's removeAtomic and
	// silently resurrect a deleted client carrying its old, already-revoked
	// registration_access_token. Distinct client_ids never contend.
	unlock := s.keyed.lock("client:" + clientID)
	defer unlock()

	rec, err := s.load(clientID)
	if err != nil {
		// Fail-closed: a read error, unparseable record, or missing/
		// unrecognized registration_source must never be treated as "not
		// internal, therefore allowed" — refuse every mutating request
		// outright. This also covers GET: without a valid record there is no
		// stored hash to authenticate the presented token against, so
		// authentication itself cannot succeed either.
		if errors.Is(err, errRecordNotFound) {
			http.Error(w, "no such client", http.StatusNotFound)
			return
		}
		http.Error(w, "client record unreadable or invalid: refusing management operation", http.StatusInternalServerError)
		return
	}

	if !verifyRegistrationToken([]byte(rec.RegistrationTokenHash), presented) {
		http.Error(w, "registration_access_token does not match", http.StatusUnauthorized)
		return
	}

	switch r.Method {
	case http.MethodGet:
		writeDCRJSON(w, http.StatusOK, map[string]any{
			"client_id":               rec.ClientID,
			"client_name":             rec.ClientName,
			"registration_client_uri": "/oauth2/register/" + rec.ClientID,
			"registration_source":     rec.RegistrationSource,
		})
	case http.MethodPut:
		var meta registerRequestBody
		if json.NewDecoder(r.Body).Decode(&meta) != nil {
			http.Error(w, "malformed or oversized metadata", http.StatusBadRequest)
			return
		}
		updated := rec
		updated.ClientName = meta.ClientName
		if err := s.audit(auditManageRecord(clientID, "update")); err != nil {
			http.Error(w, "update denied: audit sink unavailable", http.StatusServiceUnavailable)
			return
		}
		if err := s.writeAtomic(clientID, updated); err != nil {
			http.Error(w, "failed to persist update", http.StatusInternalServerError)
			return
		}
		writeDCRJSON(w, http.StatusOK, map[string]any{"client_id": rec.ClientID, "client_name": updated.ClientName})
	case http.MethodDelete:
		if rec.RegistrationSource == registrationSourceInternal {
			// Admin-provisioned clients have no valid deletion path at all,
			// regardless of what registration_access_token is presented —
			// this check runs even when the presented token matches the
			// stored hash exactly (TestDCR_DeleteRefusesInternalClient), so a
			// future "simplification" that removes it fails loudly rather
			// than silently widening what DCR can delete.
			http.Error(w, "internal client cannot be deleted via DCR", http.StatusForbidden)
			return
		}
		if err := s.audit(auditManageRecord(clientID, "delete")); err != nil {
			http.Error(w, "delete denied: audit sink unavailable", http.StatusServiceUnavailable)
			return
		}
		if err := s.removeAtomic(clientID); err != nil {
			http.Error(w, "failed to delete client record", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
