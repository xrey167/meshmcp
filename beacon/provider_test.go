package beacon

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/libdns/libdns"
	"github.com/miekg/dns"
)

// dnsQuery sends one question to the beacon's DNS server and returns the reply.
func dnsQuery(t *testing.T, server, name string, qtype uint16) *dns.Msg {
	t.Helper()
	c := &dns.Client{Timeout: 3 * time.Second}
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	resp, _, err := c.Exchange(m, server)
	if err != nil {
		t.Fatalf("dns exchange %s %s: %v", name, dns.TypeToString[qtype], err)
	}
	return resp
}

func txtValues(m *dns.Msg) []string {
	var out []string
	for _, rr := range m.Answer {
		if t, ok := rr.(*dns.TXT); ok {
			out = append(out, t.Txt...)
		}
	}
	return out
}

// TestBeaconDNS01Brokering proves the DNS-01 path end to end (no Let's Encrypt): a
// gateway publishes a challenge TXT through the libdns provider over the tunnel,
// the beacon's authoritative DNS server serves it, and clearing removes it — while
// the beacon answers A for the gateway's derived name and rejects a gateway trying
// to poison another label's challenge.
func TestBeaconDNS01Brokering(t *testing.T) {
	const zone = "beacon.test"

	publicLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	controlLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := NewServer(zone)
	s.SetPublicIP(net.ParseIP("192.0.2.10"))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = s.Run(ctx, publicLn, controlLn) }()

	dnsPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = s.serveDNSPacketConn(ctx, dnsPC) }()
	dnsAddr := dnsPC.LocalAddr().String()

	pub := []byte("gateway-key")
	dial := func(ctx context.Context, addr string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	}
	tun, err := Dial(ctx, controlLn.Addr().String(), pub, dial)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer tun.Close()
	label := SubdomainLabel(pub)
	fqdn := label + "." + zone

	// A record for the derived name resolves to the beacon's public IP.
	a := dnsQuery(t, dnsAddr, fqdn, dns.TypeA)
	if len(a.Answer) != 1 {
		t.Fatalf("A %s: got %d answers, want 1", fqdn, len(a.Answer))
	}
	if arr, ok := a.Answer[0].(*dns.A); !ok || arr.A.String() != "192.0.2.10" {
		t.Fatalf("A %s = %v, want 192.0.2.10", fqdn, a.Answer[0])
	}

	prov := NewDNSProvider(tun)
	chRel := "_acme-challenge." + label // relative to zone, as certmagic passes it
	chFQDN := "_acme-challenge." + fqdn

	// Publish a challenge and wait for the async control frame to land.
	if _, err := prov.AppendRecords(ctx, zone, []libdns.Record{{Type: "TXT", Name: chRel, Value: "tokenABC"}}); err != nil {
		t.Fatalf("AppendRecords: %v", err)
	}
	if !waitTXT(t, dnsAddr, chFQDN, "tokenABC") {
		t.Fatalf("challenge TXT %s was not served", chFQDN)
	}

	// Clearing removes it.
	if _, err := prov.DeleteRecords(ctx, zone, []libdns.Record{{Type: "TXT", Name: chRel, Value: "tokenABC"}}); err != nil {
		t.Fatalf("DeleteRecords: %v", err)
	}
	if !waitTXT(t, dnsAddr, chFQDN, "") {
		t.Fatalf("challenge TXT %s was not cleared", chFQDN)
	}

	// A gateway cannot publish a TXT for a DIFFERENT label's challenge.
	if _, err := prov.AppendRecords(ctx, zone, []libdns.Record{{Type: "TXT", Name: "_acme-challenge.someone-else", Value: "evil"}}); err != nil {
		t.Fatalf("AppendRecords(foreign): %v", err)
	}
	// Give the frame time to be processed and rejected, then confirm nothing serves.
	time.Sleep(150 * time.Millisecond)
	if got := txtValues(dnsQuery(t, dnsAddr, "_acme-challenge.someone-else."+zone, dns.TypeTXT)); len(got) != 0 {
		t.Fatalf("cross-gateway TXT poisoning succeeded: %v", got)
	}
}

// waitTXT polls the beacon DNS until the challenge TXT matches want ("" = gone).
func waitTXT(t *testing.T, dnsAddr, name, want string) bool {
	t.Helper()
	for i := 0; i < 200; i++ {
		got := txtValues(dnsQuery(t, dnsAddr, name, dns.TypeTXT))
		if want == "" && len(got) == 0 {
			return true
		}
		if want != "" && len(got) == 1 && got[0] == want {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}
