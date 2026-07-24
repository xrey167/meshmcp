package harness

import (
	"encoding/base64"
	"fmt"
	"sync"
	"testing"
)

// mockEnroller records enrolled/deregistered nodes and can be made to fail.
type mockEnroller struct {
	mu           sync.Mutex
	enrolled     []string
	deregistered []string
	failEnroll   bool
	seq          int
}

func (m *mockEnroller) Enroll(node string) (string, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failEnroll {
		return "", "", fmt.Errorf("enroll refused")
	}
	m.seq++
	m.enrolled = append(m.enrolled, node)
	return fmt.Sprintf("setup-key-%d", m.seq), "https://mgmt.example", nil
}

func (m *mockEnroller) Deregister(node string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deregistered = append(m.deregistered, node)
	return nil
}

func TestEnrollMinterMintRetire(t *testing.T) {
	enr := &mockEnroller{}
	m := NewEnrollMinter(enr)

	id, err := m.Mint("run1", RoleExecutor, 0)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	// The identity key must be a valid 32-byte WireGuard (X25519) public key.
	raw, err := base64.StdEncoding.DecodeString(id.Key)
	if err != nil || len(raw) != 32 {
		t.Fatalf("identity key is not a 32-byte WG pubkey: len=%d err=%v", len(raw), err)
	}
	if id.FQDN != "executor--run1--0" || id.Role != RoleExecutor {
		t.Fatalf("unexpected identity: %+v", id)
	}
	if !m.Active(id.Key) {
		t.Fatal("minted worker should be active")
	}
	// Launch creds must be present and hold a private key + the enrollment key.
	creds, ok := m.Creds(id.Key)
	if !ok || creds.PrivKey == "" || creds.SetupKey == "" || creds.MgmtURL == "" {
		t.Fatalf("launch creds missing: %+v (ok=%v)", creds, ok)
	}
	if len(enr.enrolled) != 1 || enr.enrolled[0] != "executor--run1--0" {
		t.Fatalf("enroll not called for the node: %v", enr.enrolled)
	}

	// Retire deregisters and clears state.
	if err := m.Retire(id); err != nil {
		t.Fatalf("retire: %v", err)
	}
	if m.Active(id.Key) {
		t.Fatal("retired worker must not be active")
	}
	if _, ok := m.Creds(id.Key); ok {
		t.Fatal("creds must be dropped on retire")
	}
	if len(enr.deregistered) != 1 || enr.deregistered[0] != "executor--run1--0" {
		t.Fatalf("deregister not called: %v", enr.deregistered)
	}
	// Double retire is a no-op success.
	if err := m.Retire(id); err != nil {
		t.Fatalf("double retire should be a no-op: %v", err)
	}
}

func TestEnrollMinterFailClosed(t *testing.T) {
	m := NewEnrollMinter(&mockEnroller{failEnroll: true})
	id, err := m.Mint("run1", RoleExecutor, 0)
	if err == nil {
		t.Fatal("mint must fail closed when enrollment fails")
	}
	if id.Key != "" {
		t.Fatal("no identity should be returned on a failed enroll")
	}
}

func TestEnrollMinterUniqueKeys(t *testing.T) {
	m := NewEnrollMinter(&mockEnroller{})
	a, _ := m.Mint("run1", RoleExecutor, 0)
	b, _ := m.Mint("run1", RoleExecutor, 1)
	if a.Key == b.Key {
		t.Fatal("each worker must get a unique key")
	}
}

// TestEnrollMinterSatisfiesMinter asserts EnrollMinter is a drop-in Minter.
func TestEnrollMinterSatisfiesMinter(t *testing.T) {
	var _ Minter = NewEnrollMinter(&mockEnroller{})
}
