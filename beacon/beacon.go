package beacon

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

// DialFunc opens a connection to the beacon. Production passes the mesh dialer
// (client.Dial over WireGuard, BlockInbound=true); tests pass net.Dial. The
// gateway makes ONLY outbound dials — it never listens.
type DialFunc func(ctx context.Context, addr string) (net.Conn, error)

// Identity is the gateway key used to authenticate registration. The gateway
// proves possession of the private key for the Ed25519 public key its subdomain
// label is derived from, so a client can never claim another gateway's label
// (or publish its ACME challenge). meshmcp's policy.Signer satisfies it.
type Identity interface {
	PubKeyRaw() []byte         // raw Ed25519 public key (32 bytes)
	SignRaw(msg []byte) []byte // Ed25519 signature over msg
}

// registerChallengePrefix domain-separates the registration signature from any
// other use of the gateway key (a signature over a beacon nonce can never be
// replayed as, say, an audit checkpoint signature, and vice versa).
const registerChallengePrefix = "meshmcp-beacon-register-v1\n"

func registerChallenge(nonce []byte) []byte {
	return append([]byte(registerChallengePrefix), nonce...)
}

// defaults for the control protocol.
const (
	maxLineLen      = 4 << 10
	defaultDataWait = 15 * time.Second
	peekTimeout     = 10 * time.Second
	// maxPendingSplices bounds public connections awaiting a gateway data conn,
	// so a flood of connections (or a gateway that stops answering OPEN) cannot
	// grow the pending map without limit.
	maxPendingSplices = 1024
	// maxTXTPerGateway bounds how many ACME challenge values a single gateway may
	// publish, so a malicious gateway cannot flood the TXT store (ACME DNS-01
	// needs at most a couple at once).
	maxTXTPerGateway = 8
)

// ---------------------------------------------------------------------------
// Beacon (public) side
// ---------------------------------------------------------------------------

// Server is the public relay. It accepts gateway tunnel connections on a control
// listener and inbound TLS connections on a public listener, routing each public
// connection to a gateway by its cleartext SNI and splicing raw bytes. It
// terminates NO TLS and holds NO gateway key: the gateway performs the real
// handshake with its own certificate, so the beacon sees only ciphertext and the
// SNI routing label.
type Server struct {
	zone     string
	dataWait time.Duration
	logf     func(format string, args ...any)

	mu       sync.Mutex
	publicIP net.IP                   // A-record answer for <label>.<zone> (DNS server)
	gateways map[string]*gwConn       // label -> live control conn
	pending  map[string]chan net.Conn // connID -> waiter for the gateway's data conn
	txt      map[string][]string      // fqdn -> ACME DNS-01 TXT values a gateway published
}

type gwConn struct {
	label   string
	control net.Conn
	writeMu sync.Mutex // serialize OPEN frames written to the control conn
}

// NewServer builds a beacon for the given DNS zone (e.g. "beacon.example.com").
func NewServer(zone string) *Server {
	return &Server{
		zone:     strings.ToLower(strings.TrimSuffix(zone, ".")),
		dataWait: defaultDataWait,
		logf:     func(string, ...any) {},
		gateways: map[string]*gwConn{},
		pending:  map[string]chan net.Conn{},
		txt:      map[string][]string{},
	}
}

// SetLogf installs a log sink (default no-op).
func (s *Server) SetLogf(f func(format string, args ...any)) {
	if f != nil {
		s.logf = f
	}
}

// SetPublicIP sets the address the authoritative DNS server answers for
// <label>.<zone> A queries — the beacon's own public IP, where hosted clients
// connect. Required only when the beacon runs its DNS server (ServeDNS).
func (s *Server) SetPublicIP(ip net.IP) {
	s.mu.Lock()
	s.publicIP = ip
	s.mu.Unlock()
}

// Run serves until ctx is cancelled or a listener fails. publicLn carries inbound
// TLS from hosted clients; controlLn carries gateway tunnel connections
// (REGISTER control conns and DATA conns). Both are closed on return.
func (s *Server) Run(ctx context.Context, publicLn, controlLn net.Listener) error {
	go func() {
		<-ctx.Done()
		publicLn.Close()
		controlLn.Close()
	}()
	errCh := make(chan error, 2)
	go func() { errCh <- s.acceptLoop(controlLn, s.handleTunnelConn) }()
	go func() { errCh <- s.acceptLoop(publicLn, s.handlePublicConn) }()
	err := <-errCh
	publicLn.Close()
	controlLn.Close()
	if ctx.Err() != nil {
		return nil
	}
	return err
}

func (s *Server) acceptLoop(ln net.Listener, handle func(net.Conn)) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go handle(conn)
	}
}

// handleTunnelConn reads the first control line and dispatches: REGISTER makes
// this a gateway control conn; DATA pairs this conn with a waiting public conn.
func (s *Server) handleTunnelConn(conn net.Conn) {
	_ = conn.SetReadDeadline(time.Now().Add(peekTimeout))
	line, err := readLine(conn)
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil {
		conn.Close()
		return
	}
	verb, rest, _ := strings.Cut(line, " ")
	switch verb {
	case "REGISTER":
		s.handleRegister(conn, strings.TrimSpace(rest))
	case "DATA":
		s.handleData(conn, strings.TrimSpace(rest))
	default:
		conn.Close()
	}
}

func (s *Server) handleRegister(conn net.Conn, b64Key string) {
	pub, err := base64.RawURLEncoding.DecodeString(b64Key)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		fmt.Fprintf(conn, "ERR bad register\n")
		conn.Close()
		return
	}
	// Prove possession of the private key for the presented public key BEFORE
	// binding its derived label: send a fresh nonce and require an Ed25519
	// signature over it. Without this, any client could claim another gateway's
	// subdomain and publish its ACME challenge (cert/namespace hijack).
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		conn.Close()
		return
	}
	if _, err := fmt.Fprintf(conn, "CHALLENGE %s\n", base64.RawURLEncoding.EncodeToString(nonce[:])); err != nil {
		conn.Close()
		return
	}
	_ = conn.SetReadDeadline(time.Now().Add(peekTimeout))
	authLine, err := readLine(conn)
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil {
		conn.Close()
		return
	}
	verb, sigB64, _ := strings.Cut(authLine, " ")
	sig, derr := base64.RawURLEncoding.DecodeString(strings.TrimSpace(sigB64))
	if verb != "AUTH" || derr != nil || !ed25519.Verify(ed25519.PublicKey(pub), registerChallenge(nonce[:]), sig) {
		fmt.Fprintf(conn, "ERR auth failed\n")
		conn.Close()
		return
	}

	label := SubdomainLabel(pub)
	gw := &gwConn{label: label, control: conn}

	s.mu.Lock()
	if old := s.gateways[label]; old != nil {
		old.control.Close() // last registration wins; drop the stale tunnel
	}
	s.gateways[label] = gw
	s.mu.Unlock()

	if _, err := fmt.Fprintf(conn, "OK %s.%s\n", label, s.zone); err != nil {
		s.deregister(gw)
		conn.Close()
		return
	}
	s.logf("beacon: gateway registered %s.%s", label, s.zone)

	// The control conn stays open: the beacon WRITES OPEN frames to it and READS
	// gateway control frames from it (ACME DNS-01 TXT publish/clear). Loop until
	// the tunnel closes, then deregister and drop any TXT it left behind.
	for {
		line, err := readLine(conn)
		if err != nil {
			break
		}
		s.handleControlFrame(gw, line)
	}
	s.deregister(gw)
	conn.Close()
}

// handleControlFrame dispatches a gateway->beacon control line. Only DNS-01 TXT
// publish/clear for the gateway's OWN challenge name is honoured.
func (s *Server) handleControlFrame(gw *gwConn, line string) {
	verb, rest, _ := strings.Cut(line, " ")
	switch verb {
	case "TXT-SET":
		if name, value, ok := strings.Cut(strings.TrimSpace(rest), " "); ok {
			s.setTXT(gw, name, value)
		}
	case "TXT-CLEAR":
		name, value, _ := strings.Cut(strings.TrimSpace(rest), " ")
		s.clearTXT(gw, strings.TrimSpace(name), value)
	}
}

func (s *Server) deregister(gw *gwConn) {
	s.mu.Lock()
	if s.gateways[gw.label] == gw {
		delete(s.gateways, gw.label)
		delete(s.txt, s.challengeName(gw.label)) // drop any DNS-01 TXT it left
		s.logf("beacon: gateway deregistered %s.%s", gw.label, s.zone)
	}
	s.mu.Unlock()
}

func (s *Server) handleData(conn net.Conn, connID string) {
	s.mu.Lock()
	ch := s.pending[connID]
	delete(s.pending, connID)
	s.mu.Unlock()
	if ch == nil {
		conn.Close() // no waiter (timed out or unknown id)
		return
	}
	ch <- conn // hand ownership to the public-conn splicer
}

// handlePublicConn peeks the SNI, finds the gateway, asks it (over the control
// conn) to open a data conn, and splices the two once it arrives.
func (s *Server) handlePublicConn(pconn net.Conn) {
	_ = pconn.SetReadDeadline(time.Now().Add(peekTimeout))
	sni, replay, err := peekClientHello(pconn)
	_ = pconn.SetReadDeadline(time.Time{})
	if err != nil {
		pconn.Close()
		return
	}
	label := labelFromSNI(sni, s.zone)
	if label == "" {
		s.logf("beacon: no route for SNI %q", sni)
		pconn.Close()
		return
	}
	s.mu.Lock()
	gw := s.gateways[label]
	s.mu.Unlock()
	if gw == nil {
		s.logf("beacon: no gateway for label %q (SNI %q)", label, sni)
		pconn.Close()
		return
	}

	connID, err := newConnID()
	if err != nil {
		pconn.Close()
		return
	}
	ch := make(chan net.Conn, 1)
	s.mu.Lock()
	if len(s.pending) >= maxPendingSplices {
		s.mu.Unlock()
		s.logf("beacon: pending-splice limit (%d) reached, dropping connection for %q", maxPendingSplices, label)
		pconn.Close()
		return
	}
	s.pending[connID] = ch
	s.mu.Unlock()

	gw.writeMu.Lock()
	_, werr := fmt.Fprintf(gw.control, "OPEN %s\n", connID)
	gw.writeMu.Unlock()
	if werr != nil {
		s.mu.Lock()
		delete(s.pending, connID)
		s.mu.Unlock()
		pconn.Close()
		return
	}

	select {
	case dconn := <-ch:
		splice(pconn, replay, dconn)
	case <-time.After(s.dataWait):
		s.mu.Lock()
		delete(s.pending, connID)
		s.mu.Unlock()
		pconn.Close()
	}
}

// splice joins the public conn and the gateway data conn. The client's bytes
// (including the peeked ClientHello, replayed here) flow to the gateway, and the
// gateway's bytes flow back — raw, undecrypted.
func splice(pconn net.Conn, replay io.Reader, dconn net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _, _ = io.Copy(dconn, replay); closeWrite(dconn) }()
	go func() { defer wg.Done(); _, _ = io.Copy(pconn, dconn); closeWrite(pconn) }()
	wg.Wait()
	pconn.Close()
	dconn.Close()
}

// ---------------------------------------------------------------------------
// Gateway side: dial out, register, expose a net.Listener
// ---------------------------------------------------------------------------

// Tunnel is the gateway's outbound reverse tunnel to a beacon. It implements
// net.Listener: each Accept returns one spliced client connection, which the
// caller terminates TLS on with the gateway's OWN certificate (e.g.
// http.Server.ServeTLS(tunnel, "", "")). The gateway holds the cert and the key;
// the beacon never does.
type Tunnel struct {
	// FQDN is the public name the beacon assigned this gateway
	// ("<label>.<zone>"). It is the OAuth issuer / public_url the hosted client
	// reaches — stable across restarts (derived from the gateway key).
	FQDN string

	beaconAddr string
	dial       DialFunc
	conns      chan net.Conn
	control    net.Conn
	controlWr  sync.Mutex // serialize gateway->beacon control writes
	closeOnce  sync.Once
	done       chan struct{}
}

// sendControlLine writes one gateway->beacon control frame on the tunnel's
// control connection (used to publish/clear ACME DNS-01 TXT records).
func (t *Tunnel) sendControlLine(line string) error {
	t.controlWr.Lock()
	defer t.controlWr.Unlock()
	_, err := fmt.Fprintf(t.control, "%s\n", line)
	return err
}

// Dial opens the reverse tunnel: it dials the beacon's control address, registers
// the gateway by proving possession of id's private key, and returns a Tunnel
// (net.Listener) plus nil error once the beacon has assigned the public FQDN. The
// FQDN is derived from id's public key, so a gateway can only ever be assigned the
// name it holds the key for.
func Dial(ctx context.Context, beaconAddr string, id Identity, dial DialFunc) (*Tunnel, error) {
	control, err := dial(ctx, beaconAddr)
	if err != nil {
		return nil, fmt.Errorf("beacon: dial control %s: %w", beaconAddr, err)
	}
	if _, err := fmt.Fprintf(control, "REGISTER %s\n", base64.RawURLEncoding.EncodeToString(id.PubKeyRaw())); err != nil {
		control.Close()
		return nil, fmt.Errorf("beacon: register: %w", err)
	}
	// Answer the beacon's proof-of-possession challenge.
	_ = control.SetReadDeadline(time.Now().Add(peekTimeout))
	chLine, err := readLine(control)
	if err != nil {
		control.Close()
		return nil, fmt.Errorf("beacon: challenge: %w", err)
	}
	cv, nonceB64, _ := strings.Cut(chLine, " ")
	nonce, derr := base64.RawURLEncoding.DecodeString(strings.TrimSpace(nonceB64))
	if cv != "CHALLENGE" || derr != nil || len(nonce) == 0 {
		control.Close()
		return nil, fmt.Errorf("beacon: unexpected challenge %q", chLine)
	}
	sig := id.SignRaw(registerChallenge(nonce))
	if _, err := fmt.Fprintf(control, "AUTH %s\n", base64.RawURLEncoding.EncodeToString(sig)); err != nil {
		control.Close()
		return nil, fmt.Errorf("beacon: auth: %w", err)
	}
	line, err := readLine(control)
	_ = control.SetReadDeadline(time.Time{})
	if err != nil {
		control.Close()
		return nil, fmt.Errorf("beacon: register reply: %w", err)
	}
	verb, rest, _ := strings.Cut(line, " ")
	if verb != "OK" || strings.TrimSpace(rest) == "" {
		control.Close()
		return nil, fmt.Errorf("beacon: registration refused: %q", line)
	}
	t := &Tunnel{
		FQDN:       strings.TrimSpace(rest),
		beaconAddr: beaconAddr,
		dial:       dial,
		conns:      make(chan net.Conn),
		control:    control,
		done:       make(chan struct{}),
	}
	go t.readControl()
	return t, nil
}

// readControl reads OPEN frames from the beacon and, for each, dials a fresh data
// conn (outbound) and delivers it to Accept. When the control conn closes, the
// listener returns ErrClosed.
func (t *Tunnel) readControl() {
	defer t.Close()
	for {
		line, err := readLine(t.control)
		if err != nil {
			return
		}
		verb, rest, _ := strings.Cut(line, " ")
		if verb != "OPEN" {
			continue
		}
		go t.openData(strings.TrimSpace(rest))
	}
}

func (t *Tunnel) openData(connID string) {
	d, err := t.dial(context.Background(), t.beaconAddr)
	if err != nil {
		return
	}
	if _, err := fmt.Fprintf(d, "DATA %s\n", connID); err != nil {
		d.Close()
		return
	}
	select {
	case t.conns <- d:
	case <-t.done:
		d.Close()
	}
}

// Accept returns the next spliced client connection. It blocks until one arrives
// or the tunnel closes.
func (t *Tunnel) Accept() (net.Conn, error) {
	select {
	case c, ok := <-t.conns:
		if !ok {
			return nil, net.ErrClosed
		}
		return c, nil
	case <-t.done:
		return nil, net.ErrClosed
	}
}

// Close tears the tunnel down: the control conn is closed and Accept returns.
func (t *Tunnel) Close() error {
	t.closeOnce.Do(func() {
		close(t.done)
		t.control.Close()
	})
	return nil
}

// Addr reports the public FQDN the tunnel serves.
func (t *Tunnel) Addr() net.Addr { return fqdnAddr(t.FQDN) }

type fqdnAddr string

func (fqdnAddr) Network() string  { return "beacon" }
func (a fqdnAddr) String() string { return string(a) }

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// readLine reads a single '\n'-terminated line one byte at a time (so a data
// conn's header is read without consuming any of the raw stream that follows it),
// trimming a trailing '\r'. It is bounded by maxLineLen.
func readLine(r io.Reader) (string, error) {
	var b strings.Builder
	buf := make([]byte, 1)
	for b.Len() < maxLineLen {
		n, err := r.Read(buf)
		if n == 1 {
			if buf[0] == '\n' {
				return strings.TrimSuffix(b.String(), "\r"), nil
			}
			b.WriteByte(buf[0])
		}
		if err != nil {
			if b.Len() > 0 && errors.Is(err, io.EOF) {
				return strings.TrimSuffix(b.String(), "\r"), nil
			}
			return "", err
		}
	}
	return "", fmt.Errorf("beacon: control line exceeded %d bytes", maxLineLen)
}

func newConnID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// closeWrite half-closes the write side when supported (TCP), so the peer sees
// EOF on one direction while the other keeps flowing.
func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}
