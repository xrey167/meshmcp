package beacon

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/miekg/dns"
)

const dnsTTL = 60

// challengeName is the DNS-01 record name for a gateway label,
// "_acme-challenge.<label>.<zone>". No lock is taken (callers may hold s.mu).
func (s *Server) challengeName(label string) string {
	return "_acme-challenge." + label + "." + s.zone
}

// setTXT records a DNS-01 challenge value a gateway published — but ONLY for the
// gateway's OWN challenge name, so one gateway can never poison another's
// challenge (or publish arbitrary records in the zone).
func (s *Server) setTXT(gw *gwConn, name, value string) {
	want := s.challengeName(gw.label)
	if value == "" || len(value) > maxTXTValueLen || !dnsEqual(name, want) {
		s.logf("beacon: rejected TXT-SET %q from %s (only %q, <=%d bytes, is allowed)", name, gw.label, want, maxTXTValueLen)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, v := range s.txt[want] {
		if v == value {
			return // idempotent
		}
	}
	if len(s.txt[want]) >= maxTXTPerGateway {
		s.logf("beacon: TXT limit (%d) reached for %s, dropping", maxTXTPerGateway, want)
		return
	}
	s.txt[want] = append(s.txt[want], value)
}

// clearTXT removes a published challenge value (or all values for the gateway's
// challenge name when value is empty).
func (s *Server) clearTXT(gw *gwConn, name, value string) {
	want := s.challengeName(gw.label)
	if !dnsEqual(name, want) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if value == "" {
		delete(s.txt, want)
		return
	}
	kept := s.txt[want][:0]
	for _, v := range s.txt[want] {
		if v != value {
			kept = append(kept, v)
		}
	}
	if len(kept) == 0 {
		delete(s.txt, want)
	} else {
		s.txt[want] = kept
	}
}

// dnsEqual compares two DNS names case-insensitively, tolerating a trailing dot.
func dnsEqual(a, b string) bool {
	return strings.EqualFold(strings.TrimSuffix(a, "."), strings.TrimSuffix(b, "."))
}

// ServeDNS runs the authoritative DNS server on addr (e.g. ":53") until ctx is
// cancelled. It answers A for <label>.<zone> (the beacon's public IP, where
// hosted clients connect) and TXT for _acme-challenge.<label>.<zone> (the DNS-01
// challenges gateways publish over the tunnel) — so a gateway obtains a
// publicly-trusted cert for its derived name via ACME DNS-01 with no inbound port
// of its own. The beacon zone must be delegated to this server out of band.
func (s *Server) ServeDNS(ctx context.Context, addr string) error {
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return fmt.Errorf("beacon: dns listen %s: %w", addr, err)
	}
	return s.serveDNSPacketConn(ctx, pc)
}

func (s *Server) serveDNSPacketConn(ctx context.Context, pc net.PacketConn) error {
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(s.handleDNS)}
	go func() {
		<-ctx.Done()
		_ = srv.Shutdown()
	}()
	return srv.ActivateAndServe()
}

func (s *Server) handleDNS(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true
	if len(r.Question) == 1 {
		ans := s.dnsAnswer(r.Question[0])
		m.Answer = append(m.Answer, ans...)
		if len(ans) == 0 {
			m.Ns = append(m.Ns, s.soa()) // NODATA/negative: authority section
		}
	}
	_ = w.WriteMsg(m)
}

func (s *Server) dnsAnswer(q dns.Question) []dns.RR {
	name := strings.ToLower(strings.TrimSuffix(q.Name, "."))
	switch q.Qtype {
	case dns.TypeTXT:
		s.mu.Lock()
		vals := append([]string(nil), s.txt[name]...)
		s.mu.Unlock()
		if len(vals) == 0 {
			return nil
		}
		return []dns.RR{&dns.TXT{Hdr: rrHeader(q.Name, dns.TypeTXT), Txt: vals}}
	case dns.TypeA:
		s.mu.Lock()
		ip := s.publicIP
		s.mu.Unlock()
		if ip == nil || ip.To4() == nil || !s.isGatewayName(name) {
			return nil
		}
		return []dns.RR{&dns.A{Hdr: rrHeader(q.Name, dns.TypeA), A: ip.To4()}}
	case dns.TypeSOA:
		if name == s.zone {
			return []dns.RR{s.soa()}
		}
	}
	return nil
}

// isGatewayName reports whether name is a single label under the zone
// ("<label>.<zone>").
func (s *Server) isGatewayName(name string) bool {
	suffix := "." + s.zone
	if !strings.HasSuffix(name, suffix) {
		return false
	}
	label := strings.TrimSuffix(name, suffix)
	return label != "" && !strings.Contains(label, ".")
}

func rrHeader(name string, t uint16) dns.RR_Header {
	return dns.RR_Header{Name: dns.Fqdn(name), Rrtype: t, Class: dns.ClassINET, Ttl: dnsTTL}
}

func (s *Server) soa() dns.RR {
	return &dns.SOA{
		Hdr:     dns.RR_Header{Name: dns.Fqdn(s.zone), Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: dnsTTL},
		Ns:      dns.Fqdn("ns." + s.zone),
		Mbox:    dns.Fqdn("hostmaster." + s.zone),
		Serial:  1,
		Refresh: 3600,
		Retry:   600,
		Expire:  604800,
		Minttl:  dnsTTL,
	}
}
