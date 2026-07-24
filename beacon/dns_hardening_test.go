package beacon

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// TestBeaconDNSOverTCP proves the authoritative server answers over TCP as well as
// UDP — the escape hatch a rate-limited or truncated resolver retries on.
func TestBeaconDNSOverTCP(t *testing.T) {
	const zone = "beacon.test"
	s := NewServer(zone)
	s.SetPublicIP(net.ParseIP("192.0.2.10"))

	// Bind UDP and TCP on the SAME port so one addr string serves both.
	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := tcpLn.Addr().String()
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = s.serveDNS(ctx, pc, tcpLn) }()

	// Register a gateway so its A name resolves.
	id := newTestIdentity(t)
	label := SubdomainLabel(id.PubKeyRaw())
	s.mu.Lock()
	s.gateways[label] = &gwConn{label: label}
	s.mu.Unlock()
	fqdn := label + "." + zone

	c := &dns.Client{Net: "tcp", Timeout: 3 * time.Second}
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(fqdn), dns.TypeA)
	resp, _, err := c.Exchange(m, addr)
	if err != nil {
		t.Fatalf("TCP exchange: %v", err)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("A over TCP: got %d answers, want 1", len(resp.Answer))
	}
	if a, ok := resp.Answer[0].(*dns.A); !ok || a.A.String() != "192.0.2.10" {
		t.Fatalf("A over TCP = %v, want 192.0.2.10", resp.Answer[0])
	}
}

// fakeDNSWriter is a dns.ResponseWriter that captures the written message and
// reports a caller-chosen remote address (so a test can present a non-loopback,
// UDP source and exercise RRL, which exempts loopback).
type fakeDNSWriter struct {
	remote  net.Addr
	written *dns.Msg
}

func (w *fakeDNSWriter) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 53}
}
func (w *fakeDNSWriter) RemoteAddr() net.Addr      { return w.remote }
func (w *fakeDNSWriter) WriteMsg(m *dns.Msg) error { w.written = m; return nil }
func (w *fakeDNSWriter) Write(b []byte) (int, error) {
	m := new(dns.Msg)
	_ = m.Unpack(b)
	w.written = m
	return len(b), nil
}
func (w *fakeDNSWriter) Close() error        { return nil }
func (w *fakeDNSWriter) TsigStatus() error   { return nil }
func (w *fakeDNSWriter) TsigTimersOnly(bool) {}
func (w *fakeDNSWriter) Hijack()             {}

// TestHandleDNSRRLSlipsUnderFlood proves that once a (non-loopback) UDP source
// exceeds its budget, the handler stops sending full amplifiable answers and
// instead either drops (no write) or slips (a small TC=1 answer forcing TCP) — so
// the beacon cannot be used as a reflection amplifier.
func TestHandleDNSRRLSlipsUnderFlood(t *testing.T) {
	const zone = "beacon.test"
	s := NewServer(zone)
	s.SetPublicIP(net.ParseIP("192.0.2.10"))
	id := newTestIdentity(t)
	label := SubdomainLabel(id.PubKeyRaw())
	s.mu.Lock()
	s.gateways[label] = &gwConn{label: label}
	s.mu.Unlock()
	fqdn := label + "." + zone

	attacker := &net.UDPAddr{IP: net.ParseIP("203.0.113.9"), Port: 5300}
	makeQuery := func() *dns.Msg {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(fqdn), dns.TypeA)
		return m
	}

	var full, truncated, dropped int
	for i := 0; i < int(rrlBurst)+40; i++ {
		w := &fakeDNSWriter{remote: attacker}
		s.handleDNS(w, makeQuery())
		switch {
		case w.written == nil:
			dropped++
		case w.written.Truncated:
			truncated++
		case len(w.written.Answer) == 1:
			full++
		}
	}
	if full == 0 || full > int(rrlBurst) {
		t.Fatalf("full answers = %d, want in (0, %d] (burst then throttle)", full, int(rrlBurst))
	}
	if truncated == 0 && dropped == 0 {
		t.Fatal("no throttling observed after the burst — RRL not applied")
	}
	// Every full answer must fit a UDP datagram; none should amplify unbounded.
	if truncated == 0 {
		t.Fatal("expected some slipped (TC=1) responses so a legit resolver can escape to TCP")
	}

	// A DIFFERENT prefix is unaffected (no cross-prefix collateral) and a loopback
	// source is never rate-limited.
	wOther := &fakeDNSWriter{remote: &net.UDPAddr{IP: net.ParseIP("198.51.100.7"), Port: 5300}}
	s.handleDNS(wOther, makeQuery())
	if wOther.written == nil || len(wOther.written.Answer) != 1 {
		t.Fatal("an unrelated prefix was throttled")
	}
	wLoop := &fakeDNSWriter{remote: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 5300}}
	for i := 0; i < int(rrlBurst)*3; i++ {
		s.handleDNS(wLoop, makeQuery())
	}
	if wLoop.written == nil || len(wLoop.written.Answer) != 1 {
		t.Fatal("loopback source was rate-limited (should be exempt)")
	}
}
