package beacon

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"net"
	"time"
)

// Control-channel TLS pinning. The gateway's control conn (and every DATA conn it
// dials) carries the routing protocol — connIDs, the DATAKEY, ACME TXT publishes.
// Over plain TCP an on-path attacker could observe or MITM those. Pinning lets the
// gateway wrap all of its dials to the beacon in TLS and verify the beacon by the
// SHA-256 of its SubjectPublicKeyInfo (SPKI), so no public CA and no PKI trust is
// involved and the beacon can rotate its leaf certificate without breaking the pin.
// The PUBLIC listener is untouched — it stays raw TCP because hosted clients bring
// their own end-to-end TLS to the gateway (the beacon only splices ciphertext).

const spkiPinPrefix = "sha256/"

// SPKIPin returns the pin string "sha256/<base64>" for a certificate's
// SubjectPublicKeyInfo — the value a beacon prints and a gateway is configured with.
func SPKIPin(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return spkiPinPrefix + base64.StdEncoding.EncodeToString(sum[:])
}

// pinnedVerify builds a tls.Config.VerifyPeerCertificate that accepts the peer iff
// its leaf SPKI matches pin. It is used together with InsecureSkipVerify: the pin
// REPLACES chain validation rather than supplementing it, which is the point — the
// beacon presents a self-signed or otherwise un-chained certificate.
func pinnedVerify(pin string) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return errors.New("beacon: server presented no certificate to pin")
		}
		leaf, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return fmt.Errorf("beacon: parse server certificate: %w", err)
		}
		got := SPKIPin(leaf)
		if subtle.ConstantTimeCompare([]byte(got), []byte(pin)) != 1 {
			return fmt.Errorf("beacon: control-channel certificate pin mismatch (server presents %s)", got)
		}
		return nil
	}
}

// PinnedDial wraps a base DialFunc so every connection to the beacon is TLS with
// the beacon's SPKI pinned. serverName is sent as SNI (informational — the pin, not
// the name, is what authenticates the beacon).
func PinnedDial(base DialFunc, serverName, pin string) DialFunc {
	return func(ctx context.Context, addr string) (net.Conn, error) {
		raw, err := base(ctx, addr)
		if err != nil {
			return nil, err
		}
		tc := tls.Client(raw, &tls.Config{
			ServerName:            serverName,
			InsecureSkipVerify:    true, // the SPKI pin below is the trust anchor, not PKI
			VerifyPeerCertificate: pinnedVerify(pin),
			MinVersion:            tls.VersionTLS12,
		})
		if err := tc.HandshakeContext(ctx); err != nil {
			raw.Close()
			return nil, fmt.Errorf("beacon: pinned control TLS handshake with %s: %w", addr, err)
		}
		return tc, nil
	}
}

// SelfSignedControlCert generates a fresh self-signed certificate for the beacon's
// control listener and returns it together with its SPKI pin, so a beacon that was
// not given an operator certificate can still offer a pinned control channel and
// print the pin for operators to hand to their gateways.
func SelfSignedControlCert(host string) (tls.Certificate, string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, "", err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else if host != "" {
		tmpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, SPKIPin(leaf), nil
}

// ControlTLSListener wraps ln so the beacon terminates TLS on the control channel
// with cert. Gateways must then dial with a matching pin (see PinnedDial).
func ControlTLSListener(ln net.Listener, cert tls.Certificate) net.Listener {
	return tls.NewListener(ln, &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	})
}
