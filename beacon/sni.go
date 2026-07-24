package beacon

import (
	"bytes"
	"io"
	"net"
	"time"

	"crypto/tls"
)

// peekClientHello reads just enough of a TLS ClientHello from r to extract the
// SNI server name WITHOUT terminating TLS, and returns a reader that replays the
// consumed bytes followed by the rest of the stream. The replayed stream is then
// spliced to the gateway, which performs the REAL handshake with its own
// certificate — so the beacon routes on the cleartext SNI alone and never holds a
// key or sees plaintext.
//
// It reuses crypto/tls's own ClientHello parser (via GetConfigForClient) rather
// than hand-rolling a record/extension decoder: the parser fires the callback
// with the parsed hello, then the handshake aborts (the underlying conn is
// read-only, so writing the ServerHello fails) — by which point the SNI is
// already captured.
func peekClientHello(r io.Reader) (sni string, replay io.Reader, err error) {
	peeked := new(bytes.Buffer)
	hello, herr := readClientHello(io.TeeReader(r, peeked))
	replay = io.MultiReader(bytes.NewReader(peeked.Bytes()), r)
	if hello == nil {
		return "", replay, herr
	}
	return hello.ServerName, replay, nil
}

func readClientHello(r io.Reader) (*tls.ClientHelloInfo, error) {
	var hello *tls.ClientHelloInfo
	err := tls.Server(readOnlyConn{reader: r}, &tls.Config{
		GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
			captured := *h
			hello = &captured
			// Returning nil keeps the default (cert-less) config, so the handshake
			// fails right after this callback — we already have what we need.
			return nil, nil
		},
	}).Handshake()
	if hello != nil {
		return hello, nil // the post-callback handshake error is expected and ignored
	}
	return nil, err
}

// readOnlyConn adapts an io.Reader to net.Conn for tls.Server: reads pass
// through, writes fail (aborting the handshake after the ClientHello is parsed),
// and the rest is inert.
type readOnlyConn struct{ reader io.Reader }

func (c readOnlyConn) Read(p []byte) (int, error)    { return c.reader.Read(p) }
func (readOnlyConn) Write([]byte) (int, error)       { return 0, io.ErrClosedPipe }
func (readOnlyConn) Close() error                    { return nil }
func (readOnlyConn) LocalAddr() net.Addr             { return nil }
func (readOnlyConn) RemoteAddr() net.Addr            { return nil }
func (readOnlyConn) SetDeadline(time.Time) error     { return nil }
func (readOnlyConn) SetReadDeadline(time.Time) error { return nil }
func (readOnlyConn) SetWriteDeadline(time.Time) error {
	return nil
}
