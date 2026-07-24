package beacon

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
)

// PROXY protocol v2 (haproxy) support. The beacon splices RAW bytes between a
// public client and the owning gateway, so without help the gateway's edge (its
// rate limiters and audit ledger) sees the BEACON's address as the client. To
// restore the real source, the beacon PREPENDS a PROXY v2 header carrying the
// public client's src/dst to the bytes it splices toward the gateway, and the
// gateway parses it off the front of the data conn and exposes it as RemoteAddr.
//
// We implement only the tiny slice of the protocol we use — emit a v2 PROXY
// command for TCP over IPv4/IPv6 (or a LOCAL header as a safe fall-back), and
// parse those plus LOCAL — rather than take a dependency, keeping the single
// static binary. The header is length-prefixed, so the reader consumes EXACTLY
// the header and never a byte of the TLS ClientHello that follows it.

// proxyV2Sig is the fixed 12-byte PROXY v2 signature.
var proxyV2Sig = []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}

const (
	proxyV2Cmd   = 0x21 // version 2 (0x2_), PROXY command (0x_1)
	proxyV2Local = 0x20 // version 2, LOCAL command (0x_0)

	proxyFamTCP4 = 0x11 // AF_INET  + STREAM
	proxyFamTCP6 = 0x21 // AF_INET6 + STREAM

	// proxyV2MaxAddrLen bounds the declared address-block length we will read, so a
	// peer (or an attacker who reached the data listener) cannot make us allocate/
	// read an arbitrary buffer. We only ever emit 12 (IPv4) or 36 (IPv6) bytes; the
	// generous cap still admits TLV-bearing headers from other senders.
	proxyV2MaxAddrLen = 1024
)

// encodeProxyV2 builds a PROXY v2 header announcing src as the connection's real
// source and dst as its destination. Both must be *net.TCPAddr of the same family;
// anything else yields a LOCAL header (the receiver then keeps the real transport
// addresses — i.e. it degrades to the pre-PROXY behavior rather than lying).
func encodeProxyV2(src, dst net.Addr) []byte {
	st, sok := src.(*net.TCPAddr)
	dt, dok := dst.(*net.TCPAddr)
	if !sok || !dok {
		return encodeProxyV2Local()
	}
	if s4, d4 := st.IP.To4(), dt.IP.To4(); s4 != nil && d4 != nil {
		return proxyV2Header(proxyFamTCP4, s4, d4, uint16(st.Port), uint16(dt.Port))
	}
	// Genuine IPv6 on both ends (To4()==nil rules out v4-mapped addresses).
	if st.IP.To4() == nil && dt.IP.To4() == nil {
		if s16, d16 := st.IP.To16(), dt.IP.To16(); s16 != nil && d16 != nil {
			return proxyV2Header(proxyFamTCP6, s16, d16, uint16(st.Port), uint16(dt.Port))
		}
	}
	return encodeProxyV2Local()
}

func proxyV2Header(famProto byte, src, dst net.IP, sport, dport uint16) []byte {
	addrLen := len(src) + len(dst) + 4 // src + dst + 2 ports
	b := make([]byte, 0, 16+addrLen)
	b = append(b, proxyV2Sig...)
	b = append(b, proxyV2Cmd, famProto)
	b = append(b, byte(addrLen>>8), byte(addrLen))
	b = append(b, src...)
	b = append(b, dst...)
	b = append(b, byte(sport>>8), byte(sport))
	b = append(b, byte(dport>>8), byte(dport))
	return b
}

func encodeProxyV2Local() []byte {
	b := make([]byte, 0, 16)
	b = append(b, proxyV2Sig...)
	b = append(b, proxyV2Local, 0x00, 0x00, 0x00) // LOCAL, AF_UNSPEC, length 0
	return b
}

// readProxyV2 reads exactly one PROXY v2 header from r, consuming the 16-byte
// fixed prefix plus the declared address block and nothing more, so the stream is
// left positioned at the first post-header byte (the TLS ClientHello). It returns
// the announced source address, or nil for a LOCAL/UNSPEC header (meaning: use the
// underlying connection's real address).
func readProxyV2(r io.Reader) (net.Addr, error) {
	var hdr [16]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, fmt.Errorf("beacon: read proxy header: %w", err)
	}
	if !bytes.Equal(hdr[:12], proxyV2Sig) {
		return nil, errors.New("beacon: bad proxy v2 signature")
	}
	if ver := hdr[12] >> 4; ver != 0x2 {
		return nil, fmt.Errorf("beacon: unsupported proxy version %d", ver)
	}
	cmd := hdr[12] & 0x0F
	famProto := hdr[13]
	addrLen := int(hdr[14])<<8 | int(hdr[15])
	if addrLen > proxyV2MaxAddrLen {
		return nil, fmt.Errorf("beacon: proxy address block too large (%d bytes)", addrLen)
	}
	body := make([]byte, addrLen)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, fmt.Errorf("beacon: read proxy address block: %w", err)
	}
	if cmd == 0x0 { // LOCAL: no announced address, use the real connection
		return nil, nil
	}
	if cmd != 0x1 {
		return nil, fmt.Errorf("beacon: unsupported proxy command 0x%x", cmd)
	}
	switch famProto {
	case proxyFamTCP4:
		if addrLen < 12 {
			return nil, errors.New("beacon: short IPv4 proxy address block")
		}
		return &net.TCPAddr{IP: net.IP(append([]byte(nil), body[0:4]...)), Port: int(body[8])<<8 | int(body[9])}, nil
	case proxyFamTCP6:
		if addrLen < 36 {
			return nil, errors.New("beacon: short IPv6 proxy address block")
		}
		return &net.TCPAddr{IP: net.IP(append([]byte(nil), body[0:16]...)), Port: int(body[32])<<8 | int(body[33])}, nil
	default:
		return nil, nil // unknown/UNSPEC family: fall back to the real connection
	}
}

// proxyConn overrides RemoteAddr to report the address announced in a PROXY
// header, delegating every other net.Conn method to the spliced data conn.
type proxyConn struct {
	net.Conn
	remote net.Addr
}

func (c *proxyConn) RemoteAddr() net.Addr { return c.remote }

// CloseWrite forwards to the underlying conn's half-close when supported, so
// wrapping to override RemoteAddr does not strip the CloseWrite the serving path
// (and beacon's closeWrite helper) relies on for one-directional shutdown.
func (c *proxyConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}
