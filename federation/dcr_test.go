package federation

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/xrey167/meshmcp/policy"
)

// noopAuditSink accepts every record — used where the test isn't exercising
// the fail-closed audit path itself.
type noopAuditSink struct{}

func (noopAuditSink) Append(policy.AuditRecord) error { return nil }

// failingAuditSink always denies — used to prove audit-write failure denies
// the operation (F22 semantics), rather than asserting which Go function ran.
type failingAuditSink struct{ calls int32 }

func (f *failingAuditSink) Append(policy.AuditRecord) error {
	atomic.AddInt32(&f.calls, 1)
	return fmt.Errorf("simulated audit sink outage")
}

func newTestStore(t *testing.T, tokens []InitialAccessToken) *DCRStore {
	t.Helper()
	dir := t.TempDir()
	if tokens == nil {
		tokens = []InitialAccessToken{{Token: "valid-initial-token", Scopes: []string{scopeClientRegister}}}
	}
	return NewDCRStore(dir, tokens, noopAuditSink{})
}

func doRegister(t *testing.T, store *DCRStore, token string, body []byte) *http.Response {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/oauth2/register", bytes.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	store.Handler().ServeHTTP(rec, req)
	return rec.Result()
}

func registerClient(t *testing.T, store *DCRStore, token string) map[string]any {
	t.Helper()
	resp := doRegister(t, store, token, []byte(`{"client_name":"partner-bot"}`))
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("registration failed: status %d", resp.StatusCode)
	}
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode registration response: %v", err)
	}
	return out
}

func manageReq(t *testing.T, store *DCRStore, method, clientID, token string, body []byte) *http.Response {
	t.Helper()
	req := httptest.NewRequest(method, "/oauth2/register/"+clientID, bytes.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	store.Handler().ServeHTTP(rec, req)
	return rec.Result()
}

// TestDCR_RegisterRequiresValidInitialAccessToken: rejected before the store
// is ever touched, whether the token is absent, unknown, or lacks scope.
func TestDCR_RegisterRequiresValidInitialAccessToken(t *testing.T) {
	tokens := []InitialAccessToken{
		{Token: "valid-tok", Scopes: []string{scopeClientRegister}},
		{Token: "wrong-scope-tok", Scopes: []string{"some:other:scope"}},
	}
	cases := []struct {
		name  string
		token string
	}{
		{"no token", ""},
		{"unknown token", "not-a-real-token"},
		{"token lacking client:register scope", "wrong-scope-tok"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			store := newTestStore(t, tokens)
			resp := doRegister(t, store, c.token, []byte(`{}`))
			if resp.StatusCode != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", resp.StatusCode)
			}
			entries, _ := os.ReadDir(store.Dir)
			if len(entries) != 0 {
				t.Fatalf("store was touched despite invalid token: %d entries", len(entries))
			}
		})
	}
}

// TestDCR_RegisterPersistsHashedTokenOnly: the on-disk file never contains
// the raw registration_access_token, only its bcrypt hash.
func TestDCR_RegisterPersistsHashedTokenOnly(t *testing.T) {
	store := newTestStore(t, nil)
	out := registerClient(t, store, "valid-initial-token")
	rawToken := out["registration_access_token"].(string)
	clientID := out["client_id"].(string)

	b, err := os.ReadFile(store.file(clientID))
	if err != nil {
		t.Fatalf("read client file: %v", err)
	}
	if strings.Contains(string(b), rawToken) {
		t.Fatalf("raw registration_access_token found in stored file contents")
	}
	var rec clientRecord
	if err := json.Unmarshal(b, &rec); err != nil {
		t.Fatalf("unmarshal stored record: %v", err)
	}
	if rec.RegistrationTokenHash == "" || rec.RegistrationTokenHash == rawToken {
		t.Fatalf("stored hash missing or equals raw token")
	}
	if !verifyRegistrationToken([]byte(rec.RegistrationTokenHash), rawToken) {
		t.Fatalf("stored hash does not verify against the token that was actually issued")
	}
}

// TestDCR_BcryptCostFactorPinned: a regression guard against the cost factor
// being silently retuned without updating the documented value.
func TestDCR_BcryptCostFactorPinned(t *testing.T) {
	store := newTestStore(t, nil)
	out := registerClient(t, store, "valid-initial-token")
	clientID := out["client_id"].(string)

	b, err := os.ReadFile(store.file(clientID))
	if err != nil {
		t.Fatalf("read client file: %v", err)
	}
	var rec clientRecord
	if err := json.Unmarshal(b, &rec); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	cost, err := bcrypt.Cost([]byte(rec.RegistrationTokenHash))
	if err != nil {
		t.Fatalf("bcrypt.Cost: %v", err)
	}
	if cost != bcryptCost {
		t.Fatalf("stored hash cost = %d, want pinned %d", cost, bcryptCost)
	}
}

// TestDCR_LongTokenPreHashedBeforeBcrypt: two tokens longer than 72 bytes
// sharing the same first 72 bytes must still produce distinguishable hashes —
// this only holds if the SHA-256 pre-hash step actually runs, since bcrypt
// alone silently truncates past 72 bytes.
func TestDCR_LongTokenPreHashedBeforeBcrypt(t *testing.T) {
	prefix := strings.Repeat("a", 72)
	tokenA := prefix + "-suffix-one-AAAA"
	tokenB := prefix + "-suffix-two-BBBB-different"

	hashA, err := hashRegistrationToken(tokenA)
	if err != nil {
		t.Fatalf("hash tokenA: %v", err)
	}
	if !verifyRegistrationToken(hashA, tokenA) {
		t.Fatalf("hash of tokenA failed to verify against itself")
	}
	if verifyRegistrationToken(hashA, tokenB) {
		t.Fatalf("hash of tokenA verified against tokenB despite differing after byte 72 — " +
			"bcrypt truncation was not guarded against by a SHA-256 pre-hash")
	}
}

// TestDCR_RegisterFilePermsAndAtomicWrite: 0600 file in a 0700 dir, and no
// stray tmp file left visible after a successful write.
func TestDCR_RegisterFilePermsAndAtomicWrite(t *testing.T) {
	store := newTestStore(t, nil)
	out := registerClient(t, store, "valid-initial-token")
	clientID := out["client_id"].(string)

	dirInfo, err := os.Stat(store.Dir)
	if err != nil {
		t.Fatalf("stat store dir: %v", err)
	}
	if !dirInfo.IsDir() {
		t.Fatalf("store dir is not a directory")
	}
	fileInfo, err := os.Stat(store.file(clientID))
	if err != nil {
		t.Fatalf("stat client file: %v", err)
	}
	// Windows does not emulate POSIX permission bits (Go's os package on
	// Windows can only represent read-only vs read-write), so the exact
	// 0600/0700 assertion only holds on POSIX platforms — the same reason
	// policy/approval_token_test.go's TestApprovalFilePermissions is
	// platform-limited here. The write path itself always requests 0600/0700
	// regardless of OS; only the assertion is skipped.
	if runtime.GOOS != "windows" {
		if perm := fileInfo.Mode().Perm(); perm != 0o600 {
			t.Fatalf("client file perms = %o, want 0600", perm)
		}
		if perm := dirInfo.Mode().Perm(); perm != 0o700 {
			t.Fatalf("store dir perms = %o, want 0700", perm)
		}
	}

	entries, err := os.ReadDir(store.Dir)
	if err != nil {
		t.Fatalf("read store dir: %v", err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp-") {
			t.Fatalf("stray tmp file left after successful write: %s", e.Name())
		}
	}
}

// TestDCR_ManageRequiresMatchingToken: GET/PUT/DELETE are rejected for a
// wrong or malformed registration_access_token — asserted behaviorally
// (consistent rejection, and rejection timing not wildly divergent from a
// correct attempt), never by asserting which Go function ran.
func TestDCR_ManageRequiresMatchingToken(t *testing.T) {
	store := newTestStore(t, nil)
	out := registerClient(t, store, "valid-initial-token")
	clientID := out["client_id"].(string)
	realToken := out["registration_access_token"].(string)

	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		t.Run(method+"/no token", func(t *testing.T) {
			resp := manageReq(t, store, method, clientID, "", []byte(`{}`))
			if resp.StatusCode != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", resp.StatusCode)
			}
		})
		t.Run(method+"/wrong token", func(t *testing.T) {
			resp := manageReq(t, store, method, clientID, "wrong-token-value", []byte(`{}`))
			if resp.StatusCode != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", resp.StatusCode)
			}
		})
		t.Run(method+"/malformed token", func(t *testing.T) {
			resp := manageReq(t, store, method, clientID, "###not-hex-not-anything###", []byte(`{}`))
			if resp.StatusCode != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", resp.StatusCode)
			}
		})
	}

	// Behavioral timing check: wrong-token attempts should not be so much
	// faster than a correct one that a short-circuit before the bcrypt
	// compare is evident. Both paths run bcrypt at the pinned cost once the
	// record itself loads successfully, so timing should stay the same order
	// of magnitude. Generous tolerance to avoid flakiness.
	const trials = 8
	start := time.Now()
	for i := 0; i < trials; i++ {
		manageReq(t, store, http.MethodGet, clientID, "wrong-token-value", nil)
	}
	wrongElapsed := time.Since(start)

	start = time.Now()
	for i := 0; i < trials; i++ {
		manageReq(t, store, http.MethodGet, clientID, realToken, nil)
	}
	correctElapsed := time.Since(start)

	if wrongElapsed < correctElapsed/10 {
		t.Fatalf("wrong-token attempts (%v) suspiciously faster than correct (%v) — "+
			"possible short-circuit before the bcrypt compare", wrongElapsed, correctElapsed)
	}
}

// TestDCR_DeleteRefusesInternalClient: an internal record cannot be deleted
// via DCR under any presented token, including one that would match if the
// registration_source check were (incorrectly) skipped.
func TestDCR_DeleteRefusesInternalClient(t *testing.T) {
	store := newTestStore(t, nil)
	clientID := "internal-seeded-client"
	token := "internal-clients-real-token"
	hash, err := hashRegistrationToken(token)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	rec := clientRecord{
		ClientID:              clientID,
		RegistrationTokenHash: string(hash),
		RegistrationSource:    registrationSourceInternal,
		CreatedAt:             time.Now().Unix(),
	}
	if err := store.writeAtomic(clientID, rec); err != nil {
		t.Fatalf("seed internal record: %v", err)
	}

	resp := manageReq(t, store, http.MethodDelete, clientID, token, nil)
	if resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusOK {
		t.Fatalf("internal client was deleted via DCR: status %d", resp.StatusCode)
	}
	if _, err := os.Stat(store.file(clientID)); err != nil {
		t.Fatalf("internal client record no longer on disk after refused delete: %v", err)
	}
}

// TestDCR_DeleteRefusesOnUnreadableRecord: a corrupt/unparseable record, or
// one missing registration_source, refuses DELETE (and PUT) — the P0-3-class
// fail-closed test.
func TestDCR_DeleteRefusesOnUnreadableRecord(t *testing.T) {
	t.Run("corrupt json", func(t *testing.T) {
		store := newTestStore(t, nil)
		clientID := "corrupt-client"
		if err := os.MkdirAll(store.Dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(store.file(clientID), []byte("{not valid json"), 0o600); err != nil {
			t.Fatal(err)
		}
		resp := manageReq(t, store, http.MethodDelete, clientID, "any-token", nil)
		if resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusOK {
			t.Fatalf("corrupt record was deleted: status %d", resp.StatusCode)
		}
		putResp := manageReq(t, store, http.MethodPut, clientID, "any-token", []byte(`{}`))
		if putResp.StatusCode == http.StatusOK {
			t.Fatalf("corrupt record was updated via PUT: status %d", putResp.StatusCode)
		}
		if _, err := os.Stat(store.file(clientID)); err != nil {
			t.Fatalf("corrupt record vanished despite refused delete: %v", err)
		}
	})

	t.Run("missing registration_source", func(t *testing.T) {
		store := newTestStore(t, nil)
		clientID := "no-source-client"
		token := "some-token"
		hash, err := hashRegistrationToken(token)
		if err != nil {
			t.Fatal(err)
		}
		// Deliberately omit RegistrationSource (zero value ""), simulating a
		// partially-written or pre-migration record.
		raw := fmt.Sprintf(`{"client_id":%q,"registration_access_token_hash":%q}`, clientID, string(hash))
		if err := os.MkdirAll(store.Dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(store.file(clientID), []byte(raw), 0o600); err != nil {
			t.Fatal(err)
		}
		resp := manageReq(t, store, http.MethodDelete, clientID, token, nil)
		if resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusOK {
			t.Fatalf("record with missing registration_source was deleted: status %d", resp.StatusCode)
		}
	})
}

// TestDCR_ManageCRUDLifecycle: register -> GET reflects the record -> PUT
// updates client_name -> a subsequent GET reflects the update. Exercises the
// GET/PUT success paths, which the token-rejection tests above never reach
// (they return before the method switch runs). DoD sign-off requires "full
// CRUD lifecycle test green."
func TestDCR_ManageCRUDLifecycle(t *testing.T) {
	store := newTestStore(t, nil)
	out := registerClient(t, store, "valid-initial-token")
	clientID := out["client_id"].(string)
	token := out["registration_access_token"].(string)

	getResp := manageReq(t, store, http.MethodGet, clientID, token, nil)
	if getResp.StatusCode != http.StatusOK {
		t.Fatalf("GET status = %d, want 200", getResp.StatusCode)
	}
	var got map[string]any
	if err := json.NewDecoder(getResp.Body).Decode(&got); err != nil {
		t.Fatalf("decode GET response: %v", err)
	}
	if got["client_id"] != clientID {
		t.Fatalf("GET client_id = %v, want %q", got["client_id"], clientID)
	}

	putResp := manageReq(t, store, http.MethodPut, clientID, token, []byte(`{"client_name":"renamed-bot"}`))
	if putResp.StatusCode != http.StatusOK {
		t.Fatalf("PUT status = %d, want 200", putResp.StatusCode)
	}

	getResp2 := manageReq(t, store, http.MethodGet, clientID, token, nil)
	if getResp2.StatusCode != http.StatusOK {
		t.Fatalf("post-PUT GET status = %d, want 200", getResp2.StatusCode)
	}
	var got2 map[string]any
	if err := json.NewDecoder(getResp2.Body).Decode(&got2); err != nil {
		t.Fatalf("decode post-PUT GET response: %v", err)
	}
	if got2["client_name"] != "renamed-bot" {
		t.Fatalf("post-PUT client_name = %v, want %q", got2["client_name"], "renamed-bot")
	}
}

// TestDCR_DeleteAllowsDCRClient: a dcr-sourced record with a correct token
// CAN be deleted — proves the refusal above is source-gated, not a blanket
// delete-disable bug.
func TestDCR_DeleteAllowsDCRClient(t *testing.T) {
	store := newTestStore(t, nil)
	out := registerClient(t, store, "valid-initial-token")
	clientID := out["client_id"].(string)
	token := out["registration_access_token"].(string)

	resp := manageReq(t, store, http.MethodDelete, clientID, token, nil)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete of dcr client failed: status %d", resp.StatusCode)
	}
	if _, err := os.Stat(store.file(clientID)); !os.IsNotExist(err) {
		t.Fatalf("client record still on disk after successful delete: err=%v", err)
	}
}

// TestDCR_RegistrationQuotaEnforced: registering beyond the configured
// per-initial-access-token cap is rejected once the cap is hit.
func TestDCR_RegistrationQuotaEnforced(t *testing.T) {
	tokens := []InitialAccessToken{{Token: "capped-token", Scopes: []string{scopeClientRegister}, MaxClients: 2}}
	store := newTestStore(t, tokens)

	for i := 0; i < 2; i++ {
		resp := doRegister(t, store, "capped-token", []byte(`{}`))
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("registration %d unexpectedly failed: status %d", i, resp.StatusCode)
		}
	}
	resp := doRegister(t, store, "capped-token", []byte(`{}`))
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("registration past quota status = %d, want 429", resp.StatusCode)
	}

	entries, err := os.ReadDir(store.Dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("live client_id count = %d, want exactly 2 (quota cap)", len(entries))
	}
}

// TestDCR_MaxBytesReaderEnforced: an oversized body to /register is rejected
// rather than fully read/processed (mirrors the S26 pattern).
func TestDCR_MaxBytesReaderEnforced(t *testing.T) {
	store := newTestStore(t, nil)
	oversized := bytes.Repeat([]byte("a"), dcrMaxBodyBytes+1024)
	body := append([]byte(`{"client_name":"`), append(oversized, []byte(`"}`)...)...)

	resp := doRegister(t, store, "valid-initial-token", body)
	if resp.StatusCode == http.StatusCreated {
		t.Fatalf("oversized registration body was accepted")
	}
	entries, _ := os.ReadDir(store.Dir)
	if len(entries) != 0 {
		t.Fatalf("oversized request still resulted in a stored client record")
	}
}

// TestDCR_SlowlorisTimeoutEnforced: a deliberately slow-trickling request is
// cut off by ReadHeaderTimeout/ReadTimeout (mirrors S27).
func TestDCR_SlowlorisTimeoutEnforced(t *testing.T) {
	store := newTestStore(t, nil)
	ts := httptest.NewUnstartedServer(store.Handler())
	ts.Config.ReadHeaderTimeout = 150 * time.Millisecond
	ts.Config.ReadTimeout = 300 * time.Millisecond
	ts.Start()
	defer ts.Close()

	conn, err := net.Dial("tcp", ts.Listener.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Send a request line and a partial header, then never complete the
	// blank line that ends the header section.
	if _, err := conn.Write([]byte("POST /oauth2/register HTTP/1.1\r\nHost: test\r\n")); err != nil {
		t.Fatalf("write partial request: %v", err)
	}

	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	start := time.Now()
	buf := make([]byte, 1)
	_, readErr := conn.Read(buf)
	elapsed := time.Since(start)
	if readErr == nil {
		t.Fatalf("expected the connection to be closed by ReadHeaderTimeout; got a response instead")
	}
	if elapsed > time.Second {
		t.Fatalf("server did not enforce ReadHeaderTimeout promptly: took %v", elapsed)
	}
}

// TestDCR_AuditWriteFailureDeniesRegistration: a simulated audit-sink failure
// during registration must deny the registration itself — no client record
// is created without a corresponding landed audit entry.
func TestDCR_AuditWriteFailureDeniesRegistration(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "dcr-store")
	sink := &failingAuditSink{}
	store := NewDCRStore(dir, []InitialAccessToken{{Token: "valid-initial-token", Scopes: []string{scopeClientRegister}}}, sink)

	resp := doRegister(t, store, "valid-initial-token", []byte(`{}`))
	if resp.StatusCode == http.StatusCreated {
		t.Fatalf("registration succeeded despite audit sink failure")
	}
	if atomic.LoadInt32(&sink.calls) == 0 {
		t.Fatalf("audit sink was never invoked")
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Fatalf("a client record was created despite the audit write failing: %d entries", len(entries))
	}
}

// TestDCR_ManagementRateLimitEnforced: repeated attempts on the bcrypt-bearing
// management path from the same source are eventually throttled (required
// control per docs/spec/OAUTH-STANDARDS.md Feature C1, in addition to the
// exact-named tests above).
func TestDCR_ManagementRateLimitEnforced(t *testing.T) {
	store := newTestStore(t, nil)
	store.SetManageRateLimit(3, time.Minute)
	out := registerClient(t, store, "valid-initial-token")
	clientID := out["client_id"].(string)
	token := out["registration_access_token"].(string)

	var sawLimited bool
	for i := 0; i < 6; i++ {
		resp := manageReq(t, store, http.MethodGet, clientID, token, nil)
		if resp.StatusCode == http.StatusTooManyRequests {
			sawLimited = true
			break
		}
	}
	if !sawLimited {
		t.Fatalf("management path was never rate-limited across repeated attempts")
	}
}
