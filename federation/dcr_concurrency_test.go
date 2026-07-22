package federation

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// countClientFiles counts live client-*.json records in a store directory,
// ignoring the transient tmp/deleted files the atomic writers leave briefly.
func countClientFiles(t *testing.T, dir string) int {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return 0
		}
		t.Fatalf("read store dir: %v", err)
	}
	n := 0
	for _, e := range entries {
		name := e.Name()
		if !e.IsDir() && strings.HasPrefix(name, "client-") && strings.HasSuffix(name, ".json") {
			n++
		}
	}
	return n
}

// TestDCR_ConcurrentRegisterRespectsQuota drives the per-issuer registration
// quota under concurrency: with MaxClients=2 and 8 simultaneous registrations
// under one initial access token, exactly 2 client records may survive. Before
// the per-issuer lock this landed all 8 (every goroutine read the pre-write
// count and passed the cap during the ~100ms bcrypt window).
func TestDCR_ConcurrentRegisterRespectsQuota(t *testing.T) {
	tokens := []InitialAccessToken{{Token: "capped", Scopes: []string{scopeClientRegister}, MaxClients: 2}}
	store := newTestStore(t, tokens)

	const n = 8
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodPost, "/oauth2/register", bytes.NewReader([]byte(`{}`)))
			req.Header.Set("Authorization", "Bearer capped")
			store.Handler().ServeHTTP(httptest.NewRecorder(), req)
		}()
	}
	wg.Wait()

	if live := countClientFiles(t, store.Dir); live != 2 {
		t.Fatalf("live client records = %d, want exactly 2 (quota must hold under concurrency)", live)
	}
}

// TestDCR_ConcurrentDeletePutNoResurrect drives the per-client_id manage lock:
// a DELETE racing a PUT against the same client must never leave the client
// resurrected once the DELETE has reported success. Before the lock, a PUT
// whose writeAtomic landed after the DELETE's removeAtomic silently recreated
// the record — still carrying its old, already-revoked registration token.
func TestDCR_ConcurrentDeletePutNoResurrect(t *testing.T) {
	for iter := 0; iter < 25; iter++ {
		store := newTestStore(t, nil)
		c := registerClient(t, store, "valid-initial-token")
		clientID, _ := c["client_id"].(string)
		regTok, _ := c["registration_access_token"].(string)
		if clientID == "" || regTok == "" {
			t.Fatalf("iter %d: registration response missing id/token: %v", iter, c)
		}

		var delStatus int32
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			resp := manageReq(t, store, http.MethodDelete, clientID, regTok, nil)
			atomic.StoreInt32(&delStatus, int32(resp.StatusCode))
		}()
		go func() {
			defer wg.Done()
			_ = manageReq(t, store, http.MethodPut, clientID, regTok, []byte(`{"client_name":"renamed"}`))
		}()
		wg.Wait()

		if atomic.LoadInt32(&delStatus) == http.StatusNoContent {
			resp := manageReq(t, store, http.MethodGet, clientID, regTok, nil)
			if resp.StatusCode == http.StatusOK {
				t.Fatalf("iter %d: DELETE returned 204 but a racing PUT resurrected the client (GET=200)", iter)
			}
		}
	}
}
