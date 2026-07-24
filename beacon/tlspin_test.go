package beacon

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"
)

// TestPinnedDialAcceptsMatchingPinRejectsWrong proves a gateway dialing with the
// beacon's SPKI pin succeeds, and dialing the same beacon with a DIFFERENT pin
// fails the handshake (an impersonator with any other key is refused).
func TestPinnedDialAcceptsMatchingPinRejectsWrong(t *testing.T) {
	cert, pin, err := SelfSignedControlCert("beacon.test")
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	tln := ControlTLSListener(ln, cert)

	go func() {
		for {
			c, err := tln.Accept()
			if err != nil {
				return
			}
			go func() {
				// Complete the handshake, echo one line, close.
				_, _ = io.WriteString(c, "OK\n")
				_ = c.(*tls.Conn).CloseWrite()
				c.Close()
			}()
		}
	}()

	base := func(ctx context.Context, addr string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Correct pin: handshake succeeds.
	good := PinnedDial(base, "beacon.test", pin)
	c, err := good(ctx, ln.Addr().String())
	if err != nil {
		t.Fatalf("pinned dial with correct pin failed: %v", err)
	}
	c.Close()

	// Wrong pin (a different self-signed key): handshake must fail.
	_, otherPin, err := SelfSignedControlCert("beacon.test")
	if err != nil {
		t.Fatal(err)
	}
	bad := PinnedDial(base, "beacon.test", otherPin)
	if _, err := bad(ctx, ln.Addr().String()); err == nil {
		t.Fatal("pinned dial with a wrong pin unexpectedly succeeded (impersonation not blocked)")
	}
}

// TestSPKIPinStableAcrossCertsSameKey documents that the pin is over the public
// key, not the whole certificate — but since SelfSignedControlCert makes a fresh
// key each call, here we simply assert the pin format and that two independent
// certs differ.
func TestSPKIPinFormatAndUniqueness(t *testing.T) {
	_, p1, err := SelfSignedControlCert("a.test")
	if err != nil {
		t.Fatal(err)
	}
	_, p2, err := SelfSignedControlCert("a.test")
	if err != nil {
		t.Fatal(err)
	}
	if len(p1) <= len(spkiPinPrefix) || p1[:len(spkiPinPrefix)] != spkiPinPrefix {
		t.Fatalf("pin %q missing %q prefix", p1, spkiPinPrefix)
	}
	if p1 == p2 {
		t.Fatal("two independent keys produced the same pin")
	}
}
