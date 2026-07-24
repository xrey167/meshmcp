package beacon

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// testIdentity is a gateway Ed25519 key pair satisfying beacon.Identity (the
// registration proof-of-possession).
type testIdentity struct {
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
}

func newTestIdentity(t *testing.T) *testIdentity {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &testIdentity{pub: pub, priv: priv}
}

func (i *testIdentity) PubKeyRaw() []byte         { return i.pub }
func (i *testIdentity) SignRaw(msg []byte) []byte { return ed25519.Sign(i.priv, msg) }

// TestBeaconRegistrationRequiresKeyPossession proves a client cannot claim a
// label for a public key it does not hold the private key for: presenting a
// victim's pubkey without a valid signature over the beacon's challenge is
// refused, and the victim's label is never bound.
func TestBeaconRegistrationRequiresKeyPossession(t *testing.T) {
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

	victim := newTestIdentity(t) // the identity an attacker wants to impersonate

	conn, err := net.Dial("tcp", controlLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	br := bufio.NewReader(conn)

	// Present the victim's PUBLIC key (which is not secret)...
	fmt.Fprintf(conn, "REGISTER %s\n", base64.RawURLEncoding.EncodeToString(victim.PubKeyRaw()))
	chLine, err := br.ReadString('\n')
	if err != nil || !strings.HasPrefix(chLine, "CHALLENGE ") {
		t.Fatalf("want CHALLENGE, got %q (err %v)", chLine, err)
	}
	// ...but answer with a signature the attacker cannot actually produce.
	fmt.Fprintf(conn, "AUTH %s\n", base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0}, ed25519.SignatureSize)))
	reply, _ := br.ReadString('\n')
	if !strings.HasPrefix(reply, "ERR") {
		t.Fatalf("forged registration accepted: %q", reply)
	}

	// The victim's label must not be bound.
	s.mu.Lock()
	_, bound := s.gateways[SubdomainLabel(victim.PubKeyRaw())]
	s.mu.Unlock()
	if bound {
		t.Fatal("victim label was bound despite failed proof-of-possession")
	}
}

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

	id := newTestIdentity(t)
	wantFQDN := SubdomainLabel(id.PubKeyRaw()) + "." + zone

	dial := func(ctx context.Context, addr string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	}
	tun, err := Dial(ctx, controlLn.Addr().String(), id, dial)
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
