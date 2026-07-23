package main

import (
	"net"
	"net/netip"
	"path"
	"strings"
	"sync/atomic"

	"github.com/netbirdio/netbird/client/embed"
)

// acl decides which mesh peers may use a backend.
// Patterns are FQDN globs ("laptop-*.netbird.cloud") or "pubkey:<key>".
// An empty pattern list allows every mesh peer (the mesh itself is
// already the outer boundary).
//
// The pattern list lives behind a shared atomic pointer, so every COPY of an
// acl (the value is captured into accept loops and handler closures at
// startup) observes a later swap — that is what makes peer ACLs hot-reloadable
// on SIGHUP without re-plumbing a single capture site. An admission check
// loads the pointer once and evaluates a consistent snapshot.
type acl struct {
	p *atomic.Pointer[[]string]
}

func newACL(patterns []string) acl {
	a := acl{p: new(atomic.Pointer[[]string])}
	a.swap(patterns)
	return a
}

// current returns the active pattern snapshot (nil for the zero acl).
func (a acl) current() []string {
	if a.p == nil {
		return nil
	}
	if l := a.p.Load(); l != nil {
		return *l
	}
	return nil
}

// swap atomically replaces the pattern list (config hot-reload). It copies the
// input so a caller mutating its slice later cannot bypass the atomic swap.
// A zero acl (no shared pointer) ignores the swap.
func (a acl) swap(patterns []string) {
	if a.p == nil {
		return
	}
	cp := append([]string(nil), patterns...)
	a.p.Store(&cp)
}

// empty reports whether the ACL has no patterns. For most backends an empty ACL
// means "any mesh peer" (the mesh is the outer boundary), but privileged
// surfaces (e.g. the Air control endpoint) treat an empty ACL as default-deny.
func (a acl) empty() bool { return len(a.current()) == 0 }

func (a acl) allows(pubKey, fqdn string) bool {
	// Fail closed on an unidentifiable peer: if the transport could not resolve
	// any cryptographic identity (both key and FQDN empty), deny — an
	// unattributable caller must never be admitted, even to an open backend.
	if pubKey == "" && fqdn == "" {
		return false
	}
	patterns := a.current()
	if len(patterns) == 0 {
		return true
	}
	for _, p := range patterns {
		if key, ok := strings.CutPrefix(p, "pubkey:"); ok {
			if key == pubKey {
				return true
			}
			continue
		}
		if ok, _ := path.Match(p, fqdn); ok {
			return true
		}
	}
	return false
}

// peerIdentity resolves a connection's remote address to the peer's
// WireGuard public key and mesh FQDN — the cryptographic caller identity.
func peerIdentity(client *embed.Client, addr net.Addr) (pubKey, fqdn string) {
	return peerIdentityStr(client, addr.String())
}

func peerIdentityStr(client *embed.Client, remote string) (pubKey, fqdn string) {
	ap, err := netip.ParseAddrPort(remote)
	if err != nil {
		return "", ""
	}
	pubKey, fqdn, _ = client.IdentityForIP(ap.Addr())
	return pubKey, fqdn
}
