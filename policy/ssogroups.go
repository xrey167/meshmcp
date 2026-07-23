package policy

// SSO-mapped group attribution (F31 v1).
//
// SSOGroups records, per WireGuard TRANSPORT key, the groups a verified OIDC
// token attributed to that key — an ADDITIVE attribution bound to an
// already-authenticated mesh identity, never a replacement for it. It implements
// GroupResolver so existing `group:<name>` policy rules match an SSO-attributed
// caller exactly as they match a config-defined StaticGroups member.
//
// Invariants that keep the WireGuard identity the root of trust:
//   - A binding keys STRICTLY on the transport peerKey passed to Bind (resolved
//     by the caller from the connection, never from the token). One key's
//     binding is never visible under another key's InGroup — attribution is
//     per-transport-key, never shared.
//   - A binding is bounded to an expiry; InGroup returns false once now >= exp
//     (lazy eviction), so a token that was valid stops attributing anything after
//     it expires.
//   - A token that fails verification never reaches Bind, so a forged/expired/
//     wrong-audience/unpinned token attributes nothing → InGroup false → today's
//     deny behavior.

import (
	"sync"
	"time"
)

// maxSSOBindings caps distinct transport keys held in memory. Cardinality is
// already bounded by mesh membership (a peer can only ever bind its OWN
// transport key), but a hard cap is defense in depth against unbounded growth.
const maxSSOBindings = 4096

// ssoBinding is one transport key's verified attribution. groups is an immutable
// set built once at Bind time (never mutated in place).
type ssoBinding struct {
	groups  map[string]bool
	subject string
	email   string
	exp     time.Time
}

// SSOGroups is the in-memory attributed-identity store. The zero value is not
// usable; construct with NewSSOGroups.
type SSOGroups struct {
	mu    sync.Mutex
	now   func() time.Time
	binds map[string]ssoBinding // transport peerKey -> binding
}

// NewSSOGroups builds an empty store. now defaults to time.Now (injectable for
// tests + TTL eviction).
func NewSSOGroups(now func() time.Time) *SSOGroups {
	if now == nil {
		now = time.Now
	}
	return &SSOGroups{now: now, binds: map[string]ssoBinding{}}
}

// Bind records claims for peerKey with the given expiry, REPLACING any prior
// binding for that key (immutable replace — a fresh group set is built, the
// caller's claims are never mutated). A blank peerKey is ignored: attribution
// must always attach to a resolved transport identity, never to nothing.
func (s *SSOGroups) Bind(peerKey string, claims OIDCClaims, exp time.Time) {
	if peerKey == "" {
		return
	}
	g := make(map[string]bool, len(claims.Groups))
	for _, name := range claims.Groups {
		if name != "" {
			g[name] = true
		}
	}
	b := ssoBinding{groups: g, subject: claims.Subject, email: claims.Email, exp: exp}

	s.mu.Lock()
	defer s.mu.Unlock()
	// If this is a new key and we're at capacity, sweep expired bindings first;
	// only refuse the new binding if that frees nothing (fail closed — no
	// attribution rather than unbounded memory).
	if _, exists := s.binds[peerKey]; !exists && len(s.binds) >= maxSSOBindings {
		s.sweepLocked()
		if len(s.binds) >= maxSSOBindings {
			return
		}
	}
	s.binds[peerKey] = b
}

// InGroup reports whether peerKey has a NON-EXPIRED binding containing group. It
// ignores peerFQDN entirely: SSO attribution is strictly per transport key. A
// blank key or group, an absent binding, or an expired binding all return false;
// an expired binding is evicted on read.
func (s *SSOGroups) InGroup(peerKey, _ /*peerFQDN*/, group string) bool {
	if peerKey == "" || group == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.binds[peerKey]
	if !ok {
		return false
	}
	if !s.now().Before(b.exp) { // now >= exp: expired
		delete(s.binds, peerKey)
		return false
	}
	return b.groups[group]
}

// Sweep evicts every expired binding. Optional housekeeping; InGroup already
// evicts lazily on read, so this is only useful to reclaim memory for keys that
// are never read again.
func (s *SSOGroups) Sweep() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked()
}

func (s *SSOGroups) sweepLocked() {
	now := s.now()
	for k, b := range s.binds {
		if !now.Before(b.exp) {
			delete(s.binds, k)
		}
	}
}

// CombinedGroups ORs several GroupResolvers behind the Engine's single resolver
// slot: a caller is in a group iff ANY constituent resolver says so. This is how
// StaticGroups (config-defined) and SSOGroups (token-attributed) compose without
// changing the Engine, which holds exactly one GroupResolver.
type CombinedGroups []GroupResolver

func (c CombinedGroups) InGroup(peerKey, peerFQDN, group string) bool {
	for _, r := range c {
		if r != nil && r.InGroup(peerKey, peerFQDN, group) {
			return true
		}
	}
	return false
}
