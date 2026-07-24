package harness

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"sync"
)

// Enroller issues and revokes ephemeral mesh enrollment credentials. It is the
// harness's minimal view of the control plane's node enrollment: Enroll mints a
// one-off, short-lived join credential for a node; Deregister removes it. In
// production it is satisfied by an adapter over control.NetBirdIssuer (which
// mints an ephemeral one-off setup key and deletes the peer); a mock satisfies
// it in tests. Keeping the interface here means the harness does not import the
// control plane directly.
type Enroller interface {
	// Enroll mints a join credential for node, returning the setup key and the
	// management URL the node uses to join.
	Enroll(node string) (setupKey, mgmtURL string, err error)
	// Deregister removes node from the mesh (retiring its identity).
	Deregister(node string) error
}

// WorkerCreds are the credentials a spawned worker process needs to join the
// mesh AS its minted identity: the WireGuard private key whose public half is
// the Identity.Key, plus the ephemeral setup key and management URL. They are
// held only until the worker is launched and are never audited or logged.
type WorkerCreds struct {
	PrivKey  string // base64 WireGuard (X25519) private key
	SetupKey string // one-off ephemeral enrollment key
	MgmtURL  string // management URL to join
}

// EnrollMinter is a production Minter: it generates a real WireGuard (X25519)
// keypair per worker — so the worker's public key (its transport-bound identity)
// is known at mint time — and obtains a scoped, ephemeral enrollment credential
// from the control plane. The worker later joins the mesh with that private key
// and setup key, so it appears on the mesh as exactly the minted public key.
// On completion the identity is retired via Deregister. Safe for concurrent use.
type EnrollMinter struct {
	enr Enroller

	mu     sync.Mutex
	active map[string]Identity    // pubkey -> identity
	creds  map[string]WorkerCreds // pubkey -> launch creds
	node   map[string]string      // pubkey -> node (FQDN) for Deregister
}

// NewEnrollMinter builds a minter over an Enroller.
func NewEnrollMinter(enr Enroller) *EnrollMinter {
	return &EnrollMinter{
		enr:    enr,
		active: map[string]Identity{},
		creds:  map[string]WorkerCreds{},
		node:   map[string]string{},
	}
}

// Mint generates a WireGuard keypair, enrolls the node, and returns the
// identity. The generated public key IS the identity — attributable and
// independently policy-scoped. If enrollment fails the key is discarded and no
// identity is minted (fail-closed: a worker is never created without a
// governed, revocable credential).
func (m *EnrollMinter) Mint(run string, role Role, n int) (Identity, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return Identity{}, fmt.Errorf("mint worker key: %w", err)
	}
	pub := base64.StdEncoding.EncodeToString(priv.PublicKey().Bytes())
	fqdn := fmt.Sprintf("%s--%s--%d", role, run, n)

	setupKey, mgmtURL, err := m.enr.Enroll(fqdn)
	if err != nil {
		return Identity{}, fmt.Errorf("enroll worker %s: %w", fqdn, err)
	}

	id := Identity{Key: pub, FQDN: fqdn, Role: role}
	m.mu.Lock()
	m.active[pub] = id
	m.creds[pub] = WorkerCreds{
		PrivKey:  base64.StdEncoding.EncodeToString(priv.Bytes()),
		SetupKey: setupKey,
		MgmtURL:  mgmtURL,
	}
	m.node[pub] = fqdn
	m.mu.Unlock()
	return id, nil
}

// Retire removes the identity from the active set, drops its launch creds, and
// deregisters it from the mesh. Retiring an unknown/already-retired key is a
// no-op success (idempotent). The Deregister error is surfaced so a leaked peer
// can be logged rather than silently accumulating.
func (m *EnrollMinter) Retire(id Identity) error {
	m.mu.Lock()
	node := m.node[id.Key]
	delete(m.active, id.Key)
	delete(m.creds, id.Key)
	delete(m.node, id.Key)
	m.mu.Unlock()
	if node == "" {
		return nil
	}
	return m.enr.Deregister(node)
}

// Active reports whether key is a live, un-retired worker.
func (m *EnrollMinter) Active(key string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.active[key]
	return ok
}

// Creds returns the launch credentials for a minted worker (consumed by a worker
// spawner). They are only available between Mint and Retire.
func (m *EnrollMinter) Creds(key string) (WorkerCreds, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.creds[key]
	return c, ok
}
