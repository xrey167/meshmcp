package beacon

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"net/http"
	"testing"
	"time"
)

// selfSignedCert returns a gateway certificate (and a pool that trusts it) for
// dnsName. The gateway holds this cert; the beacon never does.
func selfSignedCert(t *testing.T, dnsName string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: dnsName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{dnsName},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}

// TestBeaconEndToEnd is the load-bearing proof: a gateway dials the beacon,
// registers, and serves TLS with ITS OWN cert over the reverse tunnel; a client
// reaches the beacon's PUBLIC address with SNI = the assigned FQDN and pins the
// gateway's cert. That the client's handshake validates against a cert the beacon
// does not hold proves TLS terminated on the GATEWAY and the beacon merely
// spliced ciphertext.
func TestBeaconEndToEnd(t *testing.T) {
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

	pub := []byte("gateway-public-key-example")
	wantFQDN := SubdomainLabel(pub) + "." + zone

	dial := func(ctx context.Context, addr string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	}
	tun, err := Dial(ctx, controlLn.Addr().String(), pub, dial)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer tun.Close()
	if tun.FQDN != wantFQDN {
		t.Fatalf("assigned FQDN = %q, want %q", tun.FQDN, wantFQDN)
	}

	// Gateway terminates TLS with its own cert over the tunnel listener.
	cert, pool := selfSignedCert(t, wantFQDN)
	const body = "hello from the gateway over the beacon"
	gwSrv := &http.Server{
		Handler:   http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, body) }),
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"http/1.1"}},
	}
	go func() { _ = gwSrv.ServeTLS(tun, "", "") }()
	defer gwSrv.Close()

	// Client reaches the beacon public port, SNI = FQDN, pinning the gateway cert.
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				raw, derr := (&net.Dialer{}).DialContext(ctx, "tcp", publicLn.Addr().String())
				if derr != nil {
					return nil, derr
				}
				tc := tls.Client(raw, &tls.Config{ServerName: wantFQDN, RootCAs: pool, NextProtos: []string{"http/1.1"}})
				if herr := tc.HandshakeContext(ctx); herr != nil {
					raw.Close()
					return nil, herr
				}
				return tc, nil
			},
		},
	}
	resp, err := client.Get("https://" + wantFQDN + "/")
	if err != nil {
		t.Fatalf("request through the beacon failed: %v", err)
	}
	defer resp.Body.Close()
	got, _ := io.ReadAll(resp.Body)
	if string(got) != body {
		t.Fatalf("body = %q, want %q", got, body)
	}

	// An SNI with no registered gateway must not route: the handshake fails.
	raw, err := net.Dial("tcp", publicLn.Addr().String())
	if err != nil {
		t.Fatalf("dial public: %v", err)
	}
	_ = raw.SetDeadline(time.Now().Add(3 * time.Second))
	tc := tls.Client(raw, &tls.Config{ServerName: "nosuchgateway." + zone, RootCAs: pool})
	if err := tc.Handshake(); err == nil {
		t.Error("handshake for an unregistered SNI unexpectedly succeeded")
	}
	raw.Close()
}

// TestPeekClientHelloReplays proves the SNI peek reads the server name without
// consuming the stream: the replayed reader reproduces the original ClientHello
// byte-for-byte, so the gateway's real handshake still sees an intact stream.
func TestPeekClientHelloReplays(t *testing.T) {
	// Capture a real ClientHello with SNI by letting tls.Client write one to a
	// write-only sink (the handshake aborts on the EOF read, after writing it).
	var hello bytes.Buffer
	_ = tls.Client(writeOnlyConn{w: &hello}, &tls.Config{
		ServerName:         "gw-xyz.beacon.test",
		InsecureSkipVerify: true,
	}).Handshake()
	if hello.Len() == 0 {
		t.Fatal("no ClientHello captured")
	}
	original := hello.Bytes()

	sni, replay, err := peekClientHello(bytes.NewReader(original))
	if err != nil {
		t.Fatalf("peek: %v", err)
	}
	if sni != "gw-xyz.beacon.test" {
		t.Fatalf("peeked SNI = %q, want %q", sni, "gw-xyz.beacon.test")
	}
	replayed, err := io.ReadAll(replay)
	if err != nil {
		t.Fatalf("read replay: %v", err)
	}
	if !bytes.Equal(replayed, original) {
		t.Fatalf("replayed stream differs from original (%d vs %d bytes)", len(replayed), len(original))
	}
}

// writeOnlyConn captures writes and returns EOF on read, so a tls.Client writes
// exactly one ClientHello and then aborts.
type writeOnlyConn struct{ w io.Writer }

func (c writeOnlyConn) Write(p []byte) (int, error)   { return c.w.Write(p) }
func (writeOnlyConn) Read([]byte) (int, error)        { return 0, io.EOF }
func (writeOnlyConn) Close() error                    { return nil }
func (writeOnlyConn) LocalAddr() net.Addr             { return nil }
func (writeOnlyConn) RemoteAddr() net.Addr            { return nil }
func (writeOnlyConn) SetDeadline(time.Time) error     { return nil }
func (writeOnlyConn) SetReadDeadline(time.Time) error { return nil }
func (writeOnlyConn) SetWriteDeadline(time.Time) error {
	return nil
}
