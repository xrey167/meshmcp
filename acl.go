package main

import (
	"net"
	"net/netip"
	"path"
	"strings"

	"github.com/netbirdio/netbird/client/embed"
)

// acl decides which mesh peers may use a backend.
// Patterns are FQDN globs ("laptop-*.netbird.cloud") or "pubkey:<key>".
// An empty pattern list allows every mesh peer (the mesh itself is
// already the outer boundary).
type acl struct {
	patterns []string
}

func newACL(patterns []string) acl {
	return acl{patterns: patterns}
}

func (a acl) allows(pubKey, fqdn string) bool {
	// Fail closed on an unidentifiable peer: if the transport could not resolve
	// any cryptographic identity (both key and FQDN empty), deny — an
	// unattributable caller must never be admitted, even to an open backend.
	if pubKey == "" && fqdn == "" {
		return false
	}
	if len(a.patterns) == 0 {
		return true
	}
	for _, p := range a.patterns {
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
