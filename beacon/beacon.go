package beacon

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
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

// DialFunc opens a connection to the beacon. The gateway makes ONLY outbound
// dials — it never listens. The client's TLS is end-to-end to the gateway (the
// beacon splices ciphertext), but the control-protocol frames themselves travel
// on this connection: today the edge wiring dials the public beacon over plain
// TCP, so an on-path attacker could observe/race control frames. Pinning the
// beacon's identity (TLS-wrapping the control channel) is a documented follow-up;
// callers may also pass a mesh dialer here.
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

// dataMACPrefix domain-separates the per-session DATA-connection MAC (connID
// binding) from every other use of the session key.
const dataMACPrefix = "meshmcp-beacon-data-v1\n"

// dataMAC is the connID-binding tag a gateway attaches to a DATA frame: a
// truncated HMAC-SHA256 over the connID under the per-session key the beacon
// handed it (over the confidential control channel). Only the gateway that
// registered this session can produce it, so a third party that learns a connID
// still cannot claim the data conn.
func dataMAC(key []byte, connID string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(dataMACPrefix))
	m.Write([]byte(connID))
	return m.Sum(nil)[:16] // 128-bit truncation — ample for an online-only check
}

// verifyDataMAC constant-time-checks a hex-encoded DATA MAC.
func verifyDataMAC(key []byte, connID, macHex string) bool {
	got, err := hex.DecodeString(macHex)
	if err != nil {
		return false
	}
	return hmac.Equal(dataMAC(key, connID), got)
}

// Control-protocol capability tokens the gateway advertises (FEATURES) and the
// beacon confirms (FEATURES-ACK). Unknown tokens are ignored by both sides, so
// old and new peers interoperate: a feature is used for a gateway only when both
// ends confirm it. See docs/design/HOSTED-CLIENT-INGRESS.md.
const (
	featProxyV2    = "proxy-v2"    // PROXY protocol v2 source-IP passthrough on spliced conns
	featConnIDBind = "connid-bind" // per-session HMAC binding of DATA conns to the session
)

// defaults for the control protocol.
const (
	maxLineLen      = 4 << 10
	defaultDataWait = 15 * time.Second
	peekTimeout     = 10 * time.Second
	// maxPendingSplices bounds public connections awaiting a gateway data conn,
	// so a flood of connections (or a gateway that stops answering OPEN) cannot
	// grow the pending map without limit.
	maxPendingSplices = 1024
	// maxPendingPerLabel bounds pending splices for a SINGLE gateway label, so one
	// tenant (or an attacker flooding one name) cannot consume the whole global
	// budget and starve routing for every other gateway.
	maxPendingPerLabel = 128
	// maxTXTPerGateway bounds how many ACME challenge values a single gateway may
	// publish, so a malicious gateway cannot flood the TXT store (ACME DNS-01
	// needs at most a couple at once).
	maxTXTPerGateway = 8
	// maxTXTValueLen bounds a single TXT value (a DNS string is 255 bytes max);
	// a longer value is rejected rather than producing a malformed DNS answer.
	maxTXTValueLen = 255
	// maxGateways caps concurrently-registered gateways, so an attacker that can
	// pass proof-of-possession (with fresh keys) cannot exhaust memory by binding
	// unbounded labels.
	maxGateways = 65536
	// maxConnsPerListener bounds concurrent connections accepted on each listener,
	// shedding load past the cap so a connection flood cannot exhaust goroutines
	// or file descriptors. A coarse backstop; per-IP rate limiting is a follow-up.
	maxConnsPerListener = 8192
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

	// controlCert, when set, lets the beacon terminate TLS on the control channel:
	// a control/data conn whose first byte is a TLS record (0x16) is wrapped in
	// tls.Server with this cert, and a plaintext conn is served as before — so
	// pinned (new) and plaintext (old) gateways coexist on one port with no flag
	// day. Gateways verify the beacon by pinning this cert's SPKI (see PinnedDial).
	controlCert *tls.Certificate
	rrl         *rrl // authoritative-DNS response rate limiter (anti-amplification)

	mu           sync.Mutex
	publicIP     net.IP                    // A-record answer for <label>.<zone> (DNS server)
	gateways     map[string]*gwConn        // label -> live control conn
	pending      map[string]*pendingSplice // connID -> waiter for the gateway's data conn
	pendingLabel map[string]int            // label -> in-flight pending count (per-tenant fairness)
	txt          map[string][]string       // fqdn -> ACME DNS-01 TXT values a gateway published
}

// pendingSplice is a public connection awaiting its gateway data conn. sendProxy
// and macKey are latched at OPEN-write time (under the gateway's writeMu) so the
// splice/verify behavior for this connID is fixed the instant its OPEN goes out —
// never re-read from the live per-gateway flags, which could have flipped since.
type pendingSplice struct {
	ch        chan net.Conn
	label     string
	sendProxy bool   // prepend a PROXY v2 header to the bytes spliced to the gateway
	macKey    []byte // require HMAC(macKey, connID) on the DATA frame (nil = accept bare)
}

// gwConn is a live gateway control connection. The negotiated-feature fields and
// the per-session dataKey are written and read ONLY under writeMu — the same lock
// that serializes OPEN frames — so a feature flip, its FEATURES-ACK, and every
// OPEN's latch of that flip are one consistent, race-free order on the wire.
type gwConn struct {
	label      string
	pubKey     []byte
	control    net.Conn
	controlTLS bool       // this control conn is TLS (enables connid-bind negotiation)
	writeMu    sync.Mutex // serialize all beacon->gateway control writes (OPEN, FEATURES-ACK)
	proxyProto bool       // gateway confirmed PROXY v2 passthrough
	connidBind bool       // gateway confirmed connID HMAC binding (TLS control only)
	dataKey    []byte     // per-session HMAC key handed to the gateway (set iff connidBind)
}

// NewServer builds a beacon for the given DNS zone (e.g. "beacon.example.com").
func NewServer(zone string) *Server {
	return &Server{
		zone:         strings.ToLower(strings.TrimSuffix(zone, ".")),
		dataWait:     defaultDataWait,
		logf:         func(string, ...any) {},
		rrl:          newRRL(),
		gateways:     map[string]*gwConn{},
		pending:      map[string]*pendingSplice{},
		pendingLabel: map[string]int{},
		txt:          map[string][]string{},
	}
}

// SetControlCert enables TLS on the control channel: control/data conns that begin
// with a TLS handshake are terminated with cert, while plaintext conns still work
// (so old gateways are not cut off). Gateways pin cert's SPKI to authenticate the
// beacon; only over such a pinned channel is connID HMAC binding negotiated.
func (s *Server) SetControlCert(cert tls.Certificate) {
	s.mu.Lock()
	c := cert
	s.controlCert = &c
	s.mu.Unlock()
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
	// Separate concurrency budgets per listener so a flood on one cannot starve
	// the other (a public-conn flood must not block gateway registration).
	go func() { errCh <- s.acceptLoop(controlLn, make(chan struct{}, maxConnsPerListener), s.handleTunnelConn) }()
	go func() { errCh <- s.acceptLoop(publicLn, make(chan struct{}, maxConnsPerListener), s.handlePublicConn) }()
	err := <-errCh
	publicLn.Close()
	controlLn.Close()
	if ctx.Err() != nil {
		return nil
	}
	return err
}

func (s *Server) acceptLoop(ln net.Listener, sem chan struct{}, handle func(net.Conn)) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		// Shed load past the per-listener concurrency cap rather than spawning an
		// unbounded number of connection goroutines under a flood.
		select {
		case sem <- struct{}{}:
		default:
			conn.Close()
			continue
		}
		// Keepalive so a dead peer (no FIN) is eventually detected and torn down,
		// rather than leaking a spliced or control connection indefinitely.
		if tc, ok := conn.(*net.TCPConn); ok {
			_ = tc.SetKeepAlive(true)
			_ = tc.SetKeepAlivePeriod(60 * time.Second)
		}
		go func() {
			defer func() { <-sem }()
			handle(conn)
		}()
	}
}

// handleTunnelConn reads the first control line and dispatches: REGISTER makes
// this a gateway control conn; DATA pairs this conn with a waiting public conn.
// The read deadline set here bounds the optional TLS handshake, the first-line
// read, and (for REGISTER) is re-armed around the proof-of-possession exchange.
func (s *Server) handleTunnelConn(conn net.Conn) {
	_ = conn.SetReadDeadline(time.Now().Add(peekTimeout))
	conn, isTLS, err := s.maybeTLS(conn)
	if err != nil {
		conn.Close()
		return
	}
	line, err := readLine(conn)
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil {
		conn.Close()
		return
	}
	verb, rest, _ := strings.Cut(line, " ")
	switch verb {
	case "REGISTER":
		s.handleRegister(conn, isTLS, strings.TrimSpace(rest))
	case "DATA":
		s.handleData(conn, strings.TrimSpace(rest))
	default:
		conn.Close()
	}
}

// maybeTLS demultiplexes a freshly-accepted control/data conn: if the beacon has a
// control certificate and the first byte is a TLS handshake record (0x16), the
// conn is wrapped in tls.Server; otherwise it is served as plaintext. The peeked
// byte is replayed either way, so no bytes are lost. This lets pinned and legacy
// gateways share one control port without a coordinated cutover.
func (s *Server) maybeTLS(conn net.Conn) (net.Conn, bool, error) {
	s.mu.Lock()
	cert := s.controlCert
	s.mu.Unlock()
	if cert == nil {
		return conn, false, nil
	}
	var b [1]byte
	if _, err := io.ReadFull(conn, b[:]); err != nil {
		return conn, false, err
	}
	pc := &prefixConn{Conn: conn, prefix: b[:]}
	if b[0] == 0x16 { // TLS handshake record ContentType
		return tls.Server(pc, &tls.Config{Certificates: []tls.Certificate{*cert}, MinVersion: tls.VersionTLS12}), true, nil
	}
	return pc, false, nil
}

// prefixConn replays a small already-read prefix before the rest of the stream,
// so a peeked byte (TLS demux) is not consumed.
type prefixConn struct {
	net.Conn
	prefix []byte
	off    int
}

func (c *prefixConn) Read(p []byte) (int, error) {
	if c.off < len(c.prefix) {
		n := copy(p, c.prefix[c.off:])
		c.off += n
		return n, nil
	}
	return c.Conn.Read(p)
}

func (s *Server) handleRegister(conn net.Conn, isTLS bool, b64Key string) {
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
	gw := &gwConn{label: label, pubKey: pub, control: conn, controlTLS: isTLS}

	s.mu.Lock()
	old := s.gateways[label]
	if old == nil && len(s.gateways) >= maxGateways {
		s.mu.Unlock()
		fmt.Fprintf(conn, "ERR at capacity\n")
		conn.Close()
		return
	}
	if old != nil {
		old.control.Close() // last registration (same key) wins; drop the stale tunnel
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

// handleControlFrame dispatches a gateway->beacon control line: DNS-01 TXT
// publish/clear for the gateway's OWN challenge name, and the FEATURES capability
// advertisement. Unknown verbs are ignored (forward compatibility).
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
	case "FEATURES":
		s.handleFeatures(gw, rest)
	}
}

// handleFeatures negotiates the gateway's advertised capabilities and replies with
// exactly ONE frame — "FEATURES-ACK <confirmed...> [key=<b64>]" — written under
// writeMu so the flag flip, the ACK, and the (folded-in) session key are one
// atomic, deadline-bounded write that no OPEN frame can interleave. connid-bind is
// confirmed only over a TLS control conn (its key would otherwise cross the wire in
// the clear, making the binding inert). Backward compatible: an old gateway never
// sends FEATURES, so nothing is confirmed and every feature stays off.
func (s *Server) handleFeatures(gw *gwConn, rest string) {
	offered := map[string]bool{}
	for _, f := range strings.Fields(rest) {
		offered[f] = true
	}
	gw.writeMu.Lock()
	defer gw.writeMu.Unlock()

	var confirmed []string
	if offered[featProxyV2] {
		gw.proxyProto = true
		confirmed = append(confirmed, featProxyV2)
	}
	if offered[featConnIDBind] && gw.controlTLS {
		key := make([]byte, 32)
		if _, err := rand.Read(key); err == nil {
			gw.connidBind = true
			gw.dataKey = key
			confirmed = append(confirmed, featConnIDBind)
		}
	}

	ack := "FEATURES-ACK " + strings.Join(confirmed, " ")
	if gw.connidBind {
		ack += " key=" + base64.RawURLEncoding.EncodeToString(gw.dataKey)
	}
	_ = gw.control.SetWriteDeadline(time.Now().Add(peekTimeout))
	_, _ = fmt.Fprintf(gw.control, "%s\n", ack)
	_ = gw.control.SetWriteDeadline(time.Time{})
	s.logf("beacon: %s negotiated features %v (tls=%v)", gw.label, confirmed, gw.controlTLS)
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

// removePendingLocked deletes a pending entry and decrements its label counter.
// The caller holds s.mu. Returns the removed entry (nil if already gone).
func (s *Server) removePendingLocked(connID string) *pendingSplice {
	ps := s.pending[connID]
	if ps == nil {
		return nil
	}
	delete(s.pending, connID)
	if s.pendingLabel[ps.label]--; s.pendingLabel[ps.label] <= 0 {
		delete(s.pendingLabel, ps.label)
	}
	return ps
}

func (s *Server) handleData(conn net.Conn, rest string) {
	connID, macHex, _ := strings.Cut(rest, " ")
	connID = strings.TrimSpace(connID)
	macHex = strings.TrimSpace(macHex)

	s.mu.Lock()
	ps := s.pending[connID] // peek; do NOT remove until the MAC (if required) verifies
	if ps == nil {
		s.mu.Unlock()
		conn.Close() // no waiter (timed out or unknown id)
		return
	}
	if ps.macKey != nil && !verifyDataMAC(ps.macKey, connID, macHex) {
		// A DATA frame with a bad/absent MAC must NOT evict the legitimate waiter:
		// close this conn and leave the pending entry so the real gateway's DATA (or
		// the dataWait timeout) still reclaims it.
		s.mu.Unlock()
		conn.Close()
		s.logf("beacon: rejected DATA %s with invalid connID binding", connID)
		return
	}
	s.removePendingLocked(connID)
	s.mu.Unlock()
	ps.ch <- conn // hand ownership to the public-conn splicer (buffered: never blocks)
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

	// Latch this connection's per-splice behavior AND write its OPEN as one
	// gw.writeMu-serialized step (a stuck gateway must not wedge routing, so the
	// write is deadline-bounded). Reading the feature flags under the same lock that
	// FEATURES-ACK flips them under makes the snapshot consistent with the wire order
	// of this OPEN vs that ACK. The OPEN is self-describing ("proxy"/"mac" tokens) so
	// the gateway decides per-connection from the very frame that triggers its data
	// conn — never from a separately-timed flag.
	gw.writeMu.Lock()
	sendProxy := gw.proxyProto
	var macKey []byte
	if gw.connidBind {
		macKey = gw.dataKey
	}
	s.mu.Lock()
	if len(s.pending) >= maxPendingSplices || s.pendingLabel[label] >= maxPendingPerLabel {
		s.mu.Unlock()
		gw.writeMu.Unlock()
		s.logf("beacon: pending-splice limit reached, dropping connection for %q", label)
		pconn.Close()
		return
	}
	s.pending[connID] = &pendingSplice{ch: ch, label: label, sendProxy: sendProxy, macKey: macKey}
	s.pendingLabel[label]++
	s.mu.Unlock()

	open := "OPEN " + connID
	if sendProxy {
		open += " proxy"
	}
	if macKey != nil {
		open += " mac"
	}
	_ = gw.control.SetWriteDeadline(time.Now().Add(peekTimeout))
	_, werr := fmt.Fprintf(gw.control, "%s\n", open)
	_ = gw.control.SetWriteDeadline(time.Time{})
	gw.writeMu.Unlock()
	if werr != nil {
		s.mu.Lock()
		s.removePendingLocked(connID)
		s.mu.Unlock()
		pconn.Close()
		return
	}

	select {
	case dconn := <-ch:
		r := replay
		if sendProxy {
			// Prepend a PROXY v2 header so the gateway's edge sees the real client
			// address (not the beacon's) in its rate limiters and audit ledger. The
			// header's trust equals the beacon's authenticity — pin the control channel
			// (SetControlCert / beacon.pin) in production; see the design doc.
			r = io.MultiReader(bytes.NewReader(encodeProxyV2(pconn.RemoteAddr(), pconn.LocalAddr())), replay)
		}
		splice(pconn, r, dconn)
	case <-time.After(s.dataWait):
		s.mu.Lock()
		ps := s.removePendingLocked(connID)
		s.mu.Unlock()
		if ps == nil {
			// handleData claimed the slot between the timeout and the delete and is
			// delivering the data conn; take it off the channel and close it rather
			// than leak the file descriptor.
			if dconn := <-ch; dconn != nil {
				dconn.Close()
			}
		}
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
	// dataKey is the per-session connID-binding key the beacon assigns in its
	// FEATURES-ACK. It is written and read ONLY by the single readControl goroutine
	// (set when the ACK arrives, read when an OPEN is dispatched), so no
	// synchronization is needed and openData receives it as a value argument.
	dataKey []byte
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
	// Advertise hardening capabilities fire-and-forget: a beacon that supports them
	// replies with a FEATURES-ACK that readControl applies asynchronously; an old
	// beacon simply never ACKs and every feature stays off. Startup NEVER blocks on
	// the ACK, so this is backward compatible in both directions.
	_ = t.sendControlLine("FEATURES " + featProxyV2 + " " + featConnIDBind)
	go t.readControl()
	return t, nil
}

// readControl reads control frames from the beacon in a single goroutine: it
// applies FEATURES-ACK (recording the negotiated session key) and, for each OPEN,
// dials a fresh data conn. Because this loop is single-threaded and the beacon
// writes the ACK before any OPEN that depends on it, the per-connection decisions
// derived here are consistent with the beacon's. When the control conn closes,
// Accept returns ErrClosed. Non-OPEN, non-ACK verbs are ignored (compatibility).
func (t *Tunnel) readControl() {
	defer t.Close()
	for {
		line, err := readLine(t.control)
		if err != nil {
			return
		}
		verb, rest, _ := strings.Cut(line, " ")
		switch verb {
		case "FEATURES-ACK":
			t.applyFeaturesAck(rest)
		case "OPEN":
			connID, flags, _ := strings.Cut(strings.TrimSpace(rest), " ")
			expectProxy := containsField(flags, "proxy")
			var key []byte
			if containsField(flags, "mac") {
				key = t.dataKey // set from a prior FEATURES-ACK on this same goroutine
			}
			go t.openData(strings.TrimSpace(connID), expectProxy, key)
		}
	}
}

// applyFeaturesAck records the session key the beacon folded into its ACK
// ("key=<base64>"). Feature tokens are informational here — the authoritative
// per-connection decision rides each OPEN frame — but the key is needed to compute
// DATA-frame MACs, and it arrives atomically in this same frame.
func (t *Tunnel) applyFeaturesAck(rest string) {
	for _, f := range strings.Fields(rest) {
		if v, ok := strings.CutPrefix(f, "key="); ok {
			if key, err := base64.RawURLEncoding.DecodeString(v); err == nil {
				t.dataKey = key
			}
		}
	}
}

func (t *Tunnel) openData(connID string, expectProxy bool, dataKey []byte) {
	d, err := t.dial(context.Background(), t.beaconAddr)
	if err != nil {
		return
	}
	frame := "DATA " + connID
	if dataKey != nil {
		frame += " " + hex.EncodeToString(dataMAC(dataKey, connID))
	}
	if _, err := fmt.Fprintf(d, "%s\n", frame); err != nil {
		d.Close()
		return
	}
	if expectProxy {
		// Consume the beacon's PROXY v2 header (exactly, no over-read) under a
		// deadline so a stalled/partial header can't wedge this goroutine and its fd.
		_ = d.SetReadDeadline(time.Now().Add(peekTimeout))
		src, perr := readProxyV2(d)
		_ = d.SetReadDeadline(time.Time{})
		if perr != nil {
			d.Close()
			return
		}
		if src != nil { // nil = LOCAL/UNSPEC: keep the data conn's real address
			d = &proxyConn{Conn: d, remote: src}
		}
	}
	select {
	case t.conns <- d:
	case <-t.done:
		d.Close()
	}
}

// containsField reports whether space-separated fields contains tok.
func containsField(fields, tok string) bool {
	for _, f := range strings.Fields(fields) {
		if f == tok {
			return true
		}
	}
	return false
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
