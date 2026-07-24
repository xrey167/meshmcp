package beacon

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

// waitFor polls cond until true or a short deadline elapses.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for i := 0; i < 400; i++ {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func plainDial(ctx context.Context, addr string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, "tcp", addr)
}

// gwProxyNegotiated reports whether the beacon has confirmed PROXY v2 for label.
func (s *Server) gwProxyNegotiated(label string) bool {
	s.mu.Lock()
	gw := s.gateways[label]
	s.mu.Unlock()
	if gw == nil {
		return false
	}
	gw.writeMu.Lock()
	defer gw.writeMu.Unlock()
	return gw.proxyProto
}

func (s *Server) gwConnIDBindNegotiated(label string) bool {
	s.mu.Lock()
	gw := s.gateways[label]
	s.mu.Unlock()
	if gw == nil {
		return false
	}
	gw.writeMu.Lock()
	defer gw.writeMu.Unlock()
	return gw.connidBind
}

// TestBeaconProxyProtoPassthrough proves the gateway's Accept()ed connection
// reports the REAL public client's address (via the PROXY v2 header the beacon
// prepends), not the beacon's — so the gateway's rate limiters and audit see the
// true source.
func TestBeaconProxyProtoPassthrough(t *testing.T) {
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
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = s.Run(ctx, publicLn, controlLn) }()

	id := newTestIdentity(t)
	label := SubdomainLabel(id.PubKeyRaw())
	fqdn := label + "." + zone
	tun, err := Dial(ctx, controlLn.Addr().String(), id, plainDial)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer tun.Close()

	// PROXY v2 does not require TLS; wait until FEATURES negotiation lands.
	waitFor(t, "proxy-v2 negotiation", func() bool { return s.gwProxyNegotiated(label) })

	// A public client connects and sends a ClientHello (SNI routes it). We only need
	// its ClientHello to reach the beacon; the handshake need not complete.
	cc, err := net.Dial("tcp", publicLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer cc.Close()
	clientSrc := cc.LocalAddr().(*net.TCPAddr)
	go func() {
		_ = tls.Client(cc, &tls.Config{ServerName: fqdn, InsecureSkipVerify: true}).Handshake()
	}()

	done := make(chan net.Addr, 1)
	go func() {
		conn, aerr := tun.Accept()
		if aerr != nil {
			done <- nil
			return
		}
		done <- conn.RemoteAddr()
	}()

	select {
	case ra := <-done:
		tcp, ok := ra.(*net.TCPAddr)
		if !ok {
			t.Fatalf("gateway RemoteAddr = %v (%T), want *net.TCPAddr", ra, ra)
		}
		if !tcp.IP.Equal(clientSrc.IP) || tcp.Port != clientSrc.Port {
			t.Fatalf("gateway saw %v, want the real client %v — PROXY passthrough failed", tcp, clientSrc)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("gateway never accepted the spliced connection")
	}
}

// TestConnIDBindingRejectsForgedDATA proves handleData verifies the connID HMAC
// BEFORE evicting the pending waiter: a DATA frame with a wrong MAC is closed and
// the legitimate pending entry survives, while the correctly-MAC'd DATA pairs.
func TestConnIDBindingRejectsForgedDATA(t *testing.T) {
	s := NewServer("beacon.test")
	key := bytes.Repeat([]byte{0x5a}, 32)
	const connID = "00112233445566778899aabbccddeeff"
	ch := make(chan net.Conn, 1)
	s.pending[connID] = &pendingSplice{ch: ch, label: "gw", macKey: key}
	s.pendingLabel["gw"] = 1

	// Forged DATA: valid connID, wrong MAC. handleData must close the conn and leave
	// the pending entry intact.
	forged, peer := net.Pipe()
	go s.handleData(forged, connID+" "+hex.EncodeToString(bytes.Repeat([]byte{0}, 16)))
	_ = peer.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, rerr := peer.Read(make([]byte, 1)); rerr == nil || isTimeout(rerr) {
		t.Fatalf("forged DATA conn was not closed (err=%v)", rerr)
	}
	s.mu.Lock()
	_, stillPending := s.pending[connID]
	s.mu.Unlock()
	if !stillPending {
		t.Fatal("a forged DATA frame evicted the legitimate pending entry")
	}
	select {
	case <-ch:
		t.Fatal("forged conn was delivered to the splicer")
	default:
	}

	// Legitimate DATA: correct MAC pairs and removes the pending entry.
	legit, _ := net.Pipe()
	go s.handleData(legit, connID+" "+hex.EncodeToString(dataMAC(key, connID)))
	select {
	case got := <-ch:
		if got != legit {
			t.Fatal("splicer received the wrong conn")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("correctly-MAC'd DATA was not paired")
	}
	s.mu.Lock()
	_, still := s.pending[connID]
	s.mu.Unlock()
	if still {
		t.Fatal("a valid DATA did not remove the pending entry")
	}
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// TestBeaconOverPinnedControlChannel is the composed proof: a gateway dials the
// beacon over a TLS-PINNED control channel, negotiates connID HMAC binding (only
// possible over TLS) AND PROXY passthrough, and serves a real HTTPS request end to
// end with its OWN certificate — the beacon splicing ciphertext throughout.
func TestBeaconOverPinnedControlChannel(t *testing.T) {
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
	controlCert, pin, err := SelfSignedControlCert(zone)
	if err != nil {
		t.Fatal(err)
	}
	s.SetControlCert(controlCert)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = s.Run(ctx, publicLn, controlLn) }()

	id := newTestIdentity(t)
	label := SubdomainLabel(id.PubKeyRaw())
	fqdn := label + "." + zone

	pinnedDial := PinnedDial(plainDial, zone, pin)
	tun, err := Dial(ctx, controlLn.Addr().String(), id, pinnedDial)
	if err != nil {
		t.Fatalf("Dial over pinned control channel: %v", err)
	}
	defer tun.Close()
	if tun.FQDN != fqdn {
		t.Fatalf("assigned FQDN = %q, want %q", tun.FQDN, fqdn)
	}

	// Over the pinned (TLS) channel, BOTH hardening features negotiate.
	waitFor(t, "connid-bind negotiation", func() bool { return s.gwConnIDBindNegotiated(label) })
	waitFor(t, "proxy-v2 negotiation", func() bool { return s.gwProxyNegotiated(label) })

	cert, pool := selfSignedCert(t, fqdn)
	const body = "hello over a pinned beacon with connID binding"
	gwSrv := &http.Server{
		Handler:   http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, body) }),
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"http/1.1"}},
	}
	go func() { _ = gwSrv.ServeTLS(tun, "", "") }()
	defer gwSrv.Close()

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				raw, derr := (&net.Dialer{}).DialContext(ctx, "tcp", publicLn.Addr().String())
				if derr != nil {
					return nil, derr
				}
				tc := tls.Client(raw, &tls.Config{ServerName: fqdn, RootCAs: pool, NextProtos: []string{"http/1.1"}})
				if herr := tc.HandshakeContext(ctx); herr != nil {
					raw.Close()
					return nil, herr
				}
				return tc, nil
			},
		},
	}
	resp, err := client.Get("https://" + fqdn + "/")
	if err != nil {
		t.Fatalf("request through the pinned beacon failed: %v", err)
	}
	defer resp.Body.Close()
	got, _ := io.ReadAll(resp.Body)
	if string(got) != body {
		t.Fatalf("body = %q, want %q", got, body)
	}
}
