package edge

import (
	"os"
	"sync"
	"testing"
	"time"
)

func newTestClientStore(t *testing.T) *ClientStore {
	t.Helper()
	s, err := NewClientStore(t.TempDir(), func() time.Time { return time.Unix(1_700_000_000, 0).UTC() })
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestClientStoreLifecycle(t *testing.T) {
	s := newTestClientStore(t)
	rec, tok, err := s.Create("App", []string{"https://app/cb"}, RegistrationOpenApproval)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Status != ClientPending {
		t.Fatalf("status = %q, want pending", rec.Status)
	}
	if !s.VerifyRegToken(rec, tok) {
		t.Fatal("registration token should verify")
	}
	if s.VerifyRegToken(rec, "wrong") {
		t.Fatal("wrong token must not verify")
	}

	if _, err := s.Approve(rec.ClientID, "op"); err != nil {
		t.Fatal(err)
	}
	got, _ := s.Get(rec.ClientID)
	if got.Status != ClientApproved || got.ApprovedBy != "op" {
		t.Fatalf("approve did not persist: %+v", got)
	}

	// A revoked client cannot be re-approved.
	if _, err := s.Revoke(rec.ClientID, "op"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Approve(rec.ClientID, "op"); err == nil {
		t.Fatal("re-approving a revoked client must fail")
	}
}

func TestClientStoreTokenModeApprovedDirectly(t *testing.T) {
	s := newTestClientStore(t)
	rec, _, err := s.Create("App", []string{"https://app/cb"}, RegistrationToken)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Status != ClientApproved {
		t.Fatalf("token-mode create status = %q, want approved", rec.Status)
	}
}

func TestClientStoreGetMissing(t *testing.T) {
	s := newTestClientStore(t)
	_, err := s.Get("edge-nope")
	if !os.IsNotExist(err) {
		t.Fatalf("missing client should be os.ErrNotExist, got %v", err)
	}
}

// TestClientStoreConcurrentTransitions runs concurrent approve/deny/revoke on
// one client; the store must remain consistent (no torn record) and end in a
// well-defined terminal state, never panicking or corrupting the file.
func TestClientStoreConcurrentTransitions(t *testing.T) {
	s := newTestClientStore(t)
	rec, _, _ := s.Create("App", []string{"https://app/cb"}, RegistrationOpenApproval)

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			switch i % 3 {
			case 0:
				_, _ = s.Approve(rec.ClientID, "op")
			case 1:
				_, _ = s.Deny(rec.ClientID, "op")
			case 2:
				_, _ = s.Revoke(rec.ClientID, "op")
			}
		}(i)
	}
	wg.Wait()

	got, err := s.Get(rec.ClientID)
	if err != nil {
		t.Fatalf("record unreadable after concurrent transitions: %v", err)
	}
	switch got.Status {
	case ClientApproved, ClientDenied, ClientRevoked:
	default:
		t.Fatalf("unexpected terminal status %q", got.Status)
	}
}
