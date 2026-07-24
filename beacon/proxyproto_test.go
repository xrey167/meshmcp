package beacon

import (
	"bytes"
	"io"
	"net"
	"testing"
)

// TestProxyV2RoundTrip proves an encoded header parses back to the same source
// address, for both IPv4 and IPv6, and that the reader consumes EXACTLY the header
// — the trailing payload (a stand-in for the TLS ClientHello) is left intact.
func TestProxyV2RoundTrip(t *testing.T) {
	cases := []struct {
		name string
		src  *net.TCPAddr
		dst  *net.TCPAddr
	}{
		{"ipv4", &net.TCPAddr{IP: net.ParseIP("203.0.113.9"), Port: 54321}, &net.TCPAddr{IP: net.ParseIP("198.51.100.2"), Port: 443}},
		{"ipv6", &net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 40000}, &net.TCPAddr{IP: net.ParseIP("2001:db8::2"), Port: 443}},
	}
	const payload = "\x16\x03\x01 pretend ClientHello bytes"
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hdr := encodeProxyV2(tc.src, tc.dst)
			stream := io.MultiReader(bytes.NewReader(hdr), bytes.NewReader([]byte(payload)))
			got, err := readProxyV2(stream)
			if err != nil {
				t.Fatalf("readProxyV2: %v", err)
			}
			gt, ok := got.(*net.TCPAddr)
			if !ok {
				t.Fatalf("got %T, want *net.TCPAddr", got)
			}
			if !gt.IP.Equal(tc.src.IP) || gt.Port != tc.src.Port {
				t.Fatalf("parsed src = %v, want %v", gt, tc.src)
			}
			rest, _ := io.ReadAll(stream)
			if string(rest) != payload {
				t.Fatalf("payload after header = %q, want %q (header over/under-read)", rest, payload)
			}
		})
	}
}

// TestProxyV2Local proves a non-TCP or mismatched address yields a LOCAL header,
// which parses to a nil address (meaning: use the real connection) and still
// consumes exactly the header.
func TestProxyV2Local(t *testing.T) {
	hdr := encodeProxyV2(&net.UDPAddr{IP: net.ParseIP("203.0.113.9"), Port: 1}, &net.TCPAddr{IP: net.ParseIP("198.51.100.2"), Port: 443})
	const payload = "rest-of-stream"
	stream := io.MultiReader(bytes.NewReader(hdr), bytes.NewReader([]byte(payload)))
	got, err := readProxyV2(stream)
	if err != nil {
		t.Fatalf("readProxyV2: %v", err)
	}
	if got != nil {
		t.Fatalf("LOCAL header parsed to %v, want nil", got)
	}
	rest, _ := io.ReadAll(stream)
	if string(rest) != payload {
		t.Fatalf("payload after LOCAL header = %q, want %q", rest, payload)
	}
}

// TestProxyV2MixedFamilyFallsBackToLocal proves a v4 source with a v6 destination
// (or vice versa) does not produce a malformed header — it falls back to LOCAL.
func TestProxyV2MixedFamilyFallsBackToLocal(t *testing.T) {
	hdr := encodeProxyV2(&net.TCPAddr{IP: net.ParseIP("203.0.113.9"), Port: 1}, &net.TCPAddr{IP: net.ParseIP("2001:db8::2"), Port: 443})
	got, err := readProxyV2(bytes.NewReader(hdr))
	if err != nil {
		t.Fatalf("readProxyV2: %v", err)
	}
	if got != nil {
		t.Fatalf("mixed-family header parsed to %v, want nil (LOCAL)", got)
	}
}

// TestProxyV2BadSignature proves a stream that does not begin with the v2 signature
// is rejected rather than mis-parsed.
func TestProxyV2BadSignature(t *testing.T) {
	if _, err := readProxyV2(bytes.NewReader([]byte("not a proxy header at all, longer than sixteen bytes"))); err == nil {
		t.Fatal("readProxyV2 accepted a stream with no valid signature")
	}
}

// TestProxyV2OversizedLengthRejected proves a header claiming an absurd address
// block length is rejected before any large read.
func TestProxyV2OversizedLengthRejected(t *testing.T) {
	hdr := append([]byte(nil), proxyV2Sig...)
	hdr = append(hdr, proxyV2Cmd, proxyFamTCP4, 0xFF, 0xFF) // length 65535
	if _, err := readProxyV2(bytes.NewReader(hdr)); err == nil {
		t.Fatal("readProxyV2 accepted an oversized address-block length")
	}
}
