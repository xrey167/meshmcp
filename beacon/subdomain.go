// Package beacon is meshmcp's outbound rendezvous relay: the "zero inbound
// ports" ingress for hosted MCP clients (e.g. claude.ai custom connectors) that
// cannot join the mesh. A gateway dials OUT to a beacon and holds a reverse
// tunnel; the beacon owns a public name and routes inbound TLS connections to
// the right gateway by their cleartext SNI, splicing raw bytes without ever
// terminating TLS. TLS terminates on the GATEWAY with the gateway's OWN
// certificate, so the beacon holds no key and sees no plaintext — only ciphertext
// and the SNI routing label it assigned. The gateway's trust core (OAuth, the
// capability + policy double-gate, the fail-closed audit ledger) is unchanged.
//
// See docs/design/HOSTED-CLIENT-INGRESS.md — this package is the Phase-0 MVP of
// the recommended passthrough beacon: the rendezvous, the SNI-routed splice, and
// the gateway-side listener. Real ACME DNS-01 provisioning, authoritative DNS,
// multi-tenant leasing, and HA are Phase-1 hardening layered on top.
package beacon

import (
	"crypto/sha256"
	"encoding/base32"
	"strings"
)

// labelLen is the number of base32 characters kept from the hash. 16 chars of
// base32 carry 80 bits — far more than enough to make accidental collisions
// negligible while staying a short, DNS-label-safe name.
const labelLen = 16

// SubdomainLabel derives the stable DNS label for a gateway from its public key:
// the lowercased, unpadded base32 of sha256(pubKey), truncated to labelLen. It is
// deterministic (so a gateway's public name survives restarts — satisfying the
// hosted connector's stable-URL requirement), collision-resistant, and
// DNS-label-safe (the base32 alphabet is A–Z/2–7, lowercased to a–z/2–7, all
// valid label characters). The gateway's public name is "<label>.<zone>".
func SubdomainLabel(pubKey []byte) string {
	sum := sha256.Sum256(pubKey)
	enc := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(sum[:])
	return strings.ToLower(enc[:labelLen])
}

// labelFromSNI extracts the gateway label from a fully-qualified SNI name for the
// given zone: "gw-abc.beacon.example" with zone "beacon.example" yields "gw-abc".
// An SNI that is not within the zone yields "" (no route).
func labelFromSNI(sni, zone string) string {
	sni = strings.ToLower(strings.TrimSuffix(sni, "."))
	zone = strings.ToLower(strings.TrimPrefix(strings.TrimSuffix(zone, "."), "."))
	suffix := "." + zone
	if !strings.HasSuffix(sni, suffix) {
		return ""
	}
	label := strings.TrimSuffix(sni, suffix)
	// Only a single left-most label routes; reject nested names.
	if label == "" || strings.Contains(label, ".") {
		return ""
	}
	return label
}
