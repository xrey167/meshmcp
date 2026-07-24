package beacon

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xrey167/meshmcp/edge"
	"github.com/xrey167/meshmcp/policy"
	"github.com/xrey167/meshmcp/protocol/authorization"
)

// TestEdgeOverBeacon is the full-stack proof: a real edge.Server, serving over a
// beacon reverse tunnel with the gateway's OWN certificate, answers an OAuth
// discovery request made THROUGH the beacon to the public port. It exercises the
// exact composition cmdEdge performs in beacon mode — derive the public name from
// the signing key, terminate TLS on the gateway, splice ciphertext at the beacon.
func TestEdgeOverBeacon(t *testing.T) {
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

	// The gateway identity is its signing key; the public name is derived from it.
	signer, err := policy.GenerateSigner()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := hex.DecodeString(signer.PubKeyHex())
	if err != nil {
		t.Fatal(err)
	}
	fqdn := SubdomainLabel(pub) + "." + zone

	// The gateway holds a cert for its derived name (files mode; ACME DNS-01 later).
	cert, pool := selfSignedCert(t, fqdn)
	dir := t.TempDir()
	certPath, keyPath := writeCertKeyPEM(t, dir, cert)

	cfg := edge.Config{
		PublicURL:  "https://" + fqdn, // cmdEdge derives this before New; mirror it here
		StateDir:   dir,
		AuditLog:   filepath.Join(dir, "audit.jsonl"),
		SigningKey: filepath.Join(dir, "key.json"), // unused: Signer supplied via Options
		Beacon:     &edge.BeaconConfig{Control: controlLn.Addr().String(), Zone: zone},
		TLS:        edge.TLSConfig{CertFile: certPath, KeyFile: keyPath},
		Backend: edge.BackendConfig{
			Name:   "docs",
			Addr:   "gateway.mesh:9101",
			Tools:  []string{"search_*"},
			Policy: policy.Policy{DefaultAllow: false},
		},
	}
	edgeSrv, err := edge.New(cfg, edge.Options{
		Signer:      signer,
		AuditWriter: &bytes.Buffer{},
		Now:         func() time.Time { return time.Unix(1_700_000_000, 0).UTC() },
	})
	if err != nil {
		t.Fatalf("edge.New (beacon mode): %v", err)
	}

	dial := func(ctx context.Context, addr string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	}
	tun, err := Dial(ctx, controlLn.Addr().String(), pub, dial)
	if err != nil {
		t.Fatalf("beacon Dial: %v", err)
	}
	defer tun.Close()
	if tun.FQDN != fqdn {
		t.Fatalf("assigned FQDN = %q, want %q", tun.FQDN, fqdn)
	}
	go func() { _ = edgeSrv.ServeOverListener(ctx, tun) }()

	// Reach the OAuth protected-resource metadata THROUGH the beacon's public port,
	// SNI = fqdn, pinning the gateway cert. Success proves: TLS terminated on the
	// gateway (beacon holds no key), and the real edge OAuth surface answered.
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

	metaURL := "https://" + fqdn + "/.well-known/" + authorization.WellKnownProtectedResource
	var resp *http.Response
	for i := 0; i < 200; i++ {
		resp, err = client.Get(metaURL)
		if err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("discovery through the beacon failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("discovery status = %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	// The metadata's resource/authorization_server carry the beacon-derived public
	// URL — proof the edge served its real OAuth surface at the assigned name.
	if !strings.Contains(string(body), fqdn) {
		t.Fatalf("discovery body does not carry the derived public name %q:\n%s", fqdn, body)
	}
}

// writeCertKeyPEM writes a tls.Certificate's leaf + EC key as PEM files for the
// edge's tls.cert_file/key_file mode.
func writeCertKeyPEM(t *testing.T, dir string, cert tls.Certificate) (certPath, keyPath string) {
	t.Helper()
	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(cert.PrivateKey.(*ecdsa.PrivateKey))
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}
