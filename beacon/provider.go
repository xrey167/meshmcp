package beacon

import (
	"context"
	"strings"

	"github.com/libdns/libdns"
)

// DNSProvider is the gateway-side libdns provider that satisfies certmagic's
// DNS-01 solver (RecordAppender + RecordDeleter). It "publishes" DNS records by
// asking the beacon to serve them over the already-open reverse tunnel — so a
// gateway completes an ACME DNS-01 challenge for its beacon-assigned name without
// running any DNS server or opening any inbound port. Only TXT records (the
// DNS-01 challenge) are brokered; the beacon rejects anything but the gateway's
// own _acme-challenge name.
type DNSProvider struct {
	tun *Tunnel
}

// NewDNSProvider returns a libdns provider bound to an open tunnel.
func NewDNSProvider(tun *Tunnel) *DNSProvider { return &DNSProvider{tun: tun} }

// AppendRecords publishes the given TXT records via the beacon.
func (p *DNSProvider) AppendRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	for _, r := range recs {
		if !strings.EqualFold(r.Type, "TXT") {
			continue
		}
		if err := p.tun.sendControlLine("TXT-SET " + absName(r.Name, zone) + " " + r.Value); err != nil {
			return nil, err
		}
	}
	return recs, nil
}

// DeleteRecords clears the given TXT records at the beacon.
func (p *DNSProvider) DeleteRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	for _, r := range recs {
		if !strings.EqualFold(r.Type, "TXT") {
			continue
		}
		if err := p.tun.sendControlLine("TXT-CLEAR " + absName(r.Name, zone) + " " + r.Value); err != nil {
			return nil, err
		}
	}
	return recs, nil
}

// absName resolves a libdns record name (relative to zone) to the fully-qualified
// name the beacon keys on, lowercased and without a trailing dot.
func absName(name, zone string) string {
	return strings.ToLower(strings.TrimSuffix(libdns.AbsoluteName(name, zone), "."))
}
