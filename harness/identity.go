package harness

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"sync"
)

// Identity is a mesh actor: a transport-bound WireGuard-style public key plus a
// stable FQDN used for policy peer-matching. Every actor in a run — the
// orchestrator, each ephemeral role worker, the human principal, a provider
// bridge — is one of these. An identity is never a self-asserted name: the Key
// is what authorizes, and role.go compiles per-role policy that matches the
// FQDN convention below.
//
// FQDN convention: "<role>--<run>--<n>" for workers (see Minter.Mint), and a
// caller-supplied stable FQDN for the principal/orchestrator. The "<role>--*"
// glob in a compiled policy rule matches every worker of that role because
// path.Match's '*' spans the dot-free separator '--'.
type Identity struct {
	Key  string // base64 public key — the transport-bound identity
	FQDN string // policy peer-matching name
	Role Role   // the capability role this identity was minted for
}

// Caller is a convenience for the principal/orchestrator identity that drives a
// run from the CLI or an MCP call, before any workers exist.
func Caller(key, fqdn string) Identity {
	return Identity{Key: key, FQDN: fqdn, Role: RoleOrchestrator}
}

// Minter mints and retires ephemeral worker identities. In production this is
// backed by control/ (mint a scoped, short-lived mesh peer key, enroll it, and
// retire it on completion). MemMinter is the in-process implementation used by
// tests and single-host runs: it generates a real Ed25519 keypair per worker so
// keys are unique and attributable, but does not enroll them on a live mesh.
type Minter interface {
	// Mint creates a fresh identity for role within run. n is the worker's
	// ordinal within the run, used only to build a readable FQDN.
	Mint(run string, role Role, n int) (Identity, error)
	// Retire marks an identity's key as no longer valid. After Retire the key
	// must never authorize another action; its audit segment is sealed by the
	// caller (Orchestrator.settle).
	Retire(id Identity) error
	// Active reports whether key currently belongs to a live, un-retired worker.
	Active(key string) bool
}

// MemMinter is an in-process Minter. Safe for concurrent use.
type MemMinter struct {
	mu      sync.Mutex
	active  map[string]Identity
	retired map[string]bool
}

// NewMemMinter builds an empty in-process minter.
func NewMemMinter() *MemMinter {
	return &MemMinter{active: map[string]Identity{}, retired: map[string]bool{}}
}

// Mint generates a fresh Ed25519 keypair and derives a role-scoped FQDN.
func (m *MemMinter) Mint(run string, role Role, n int) (Identity, error) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Identity{}, fmt.Errorf("mint worker key: %w", err)
	}
	id := Identity{
		Key:  base64.StdEncoding.EncodeToString(pub),
		FQDN: fmt.Sprintf("%s--%s--%d", role, run, n),
		Role: role,
	}
	m.mu.Lock()
	m.active[id.Key] = id
	m.mu.Unlock()
	return id, nil
}

// Retire removes id from the active set. Retiring an unknown or already-retired
// key is a no-op success (idempotent), so a double settle is safe.
func (m *MemMinter) Retire(id Identity) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.active, id.Key)
	m.retired[id.Key] = true
	return nil
}

// Active reports whether key is a live, un-retired worker.
func (m *MemMinter) Active(key string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.active[key]
	return ok
}
