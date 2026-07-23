package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xrey167/meshmcp/mcp"
	"github.com/xrey167/meshmcp/mcpclient"
	"github.com/xrey167/meshmcp/policy"
)

// recordingRWC records everything the filter forwards to the backend, so a
// test can prove the delegation token was stripped before the backend.
type recordingRWC struct {
	inner io.ReadWriteCloser
	mu    *sync.Mutex
	buf   *bytes.Buffer
}

func (r *recordingRWC) Read(p []byte) (int, error) { return r.inner.Read(p) }
func (r *recordingRWC) Write(p []byte) (int, error) {
	r.mu.Lock()
	r.buf.Write(p)
	r.mu.Unlock()
	return r.inner.Write(p)
}
func (r *recordingRWC) Close() error { return r.inner.Close() }

// startFilteredUpstream serves an mcp.Server behind a per-connection policy
// filter on loopback TCP — the test stand-in for a real gateway backend with
// router-delegation enforcement.
func startFilteredUpstream(t *testing.T, configure func(*mcp.Server), makeFilter func(inner io.ReadWriteCloser) io.ReadWriteCloser) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := mcp.New("upstream", "1.0")
	configure(s)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				c2sR, c2sW := io.Pipe()
				s2cR, s2cW := io.Pipe()
				go func() { _ = s.Serve(context.Background(), c2sR, s2cW); s2cW.Close() }()
				f := makeFilter(rwPair{r: s2cR, w: c2sW})
				go func() { _, _ = io.Copy(f, c); f.Close() }()
				_, _ = io.Copy(c, f)
			}(conn)
		}
	}()
	return ln.Addr().String(), func() { ln.Close() }
}

// delegUpstream builds a pinned, delegation-required filtered upstream serving
// addTool, recording backend-received bytes into backendBuf.
func delegUpstream(t *testing.T, authority *policy.Signer, rules []policy.Rule, required bool,
	backendMu *sync.Mutex, backendBuf *bytes.Buffer) (string, func()) {
	t.Helper()
	eng := policy.NewEngine(&policy.Policy{DefaultAllow: false, Rules: rules}, nil, nil)
	verifier, err := policy.NewDelegationVerifier([]string{authority.PubKeyHex()}, "GWKEY", policy.NewMemNonceStore(), nil)
	if err != nil {
		t.Fatal(err)
	}
	makeFilter := func(inner io.ReadWriteCloser) io.ReadWriteCloser {
		rec := &recordingRWC{inner: inner, mu: backendMu, buf: backendBuf}
		f := policy.NewFilterEngine(rec, policy.Caller{Backend: "svc", Peer: "router.mesh", PeerKey: "ROUTERKEY"},
			eng, policy.NewAuditLog(nil, nil), nil)
		f.SetDelegationVerifier(verifier, required)
		return f
	}
	return startFilteredUpstream(t, func(s *mcp.Server) { s.AddTool(addTool()) }, makeFilter)
}

// TestRouterDelegationEndToEnd: a router with a delegation key calling an
// audience-pinned, delegation-required gateway. The call succeeds; the token
// is on the router→gateway wire but never reaches the backend; a captured
// token replays to a denial; and a direct (token-less) client is refused.
func TestRouterDelegationEndToEnd(t *testing.T) {
	authority, _ := policy.GenerateSigner()
	rules := []policy.Rule{{Peers: []string{"pubkey:ROUTERKEY", "pubkey:CALLERKEY"}, Tools: []string{"add"}, Allow: true}}
	var backendMu sync.Mutex
	var backendBuf bytes.Buffer
	addr, stop := delegUpstream(t, authority, rules, true, &backendMu, &backendBuf)
	defer stop()

	// Router side: capture the router→gateway wire.
	var wireMu sync.Mutex
	var wire bytes.Buffer
	dial := func(ctx context.Context, a string) (net.Conn, error) {
		c, err := loopbackDial(ctx, a)
		if err != nil {
			return nil, err
		}
		return &captureConn{Conn: c, mu: &wireMu, buf: &wire}, nil
	}
	minter := &delegationMinter{signer: authority, routerKey: "ROUTERKEY", callerKey: "CALLERKEY"}
	agg, cleanup := buildAggregate(context.Background(), dial,
		map[string]Upstream{"svc": {Addrs: []string{addr}, Audience: "GWKEY"}}, nil, nil, minter)
	defer cleanup()

	mc := clientTo(agg)
	defer mc.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := mc.Initialize(ctx, "test"); err != nil {
		t.Fatalf("initialize: %v", err)
	}
	res, err := mc.CallTool(ctx, "svc.add", map[string]any{"a": 2, "b": 40}, false)
	if err != nil {
		t.Fatalf("delegated call failed: %v", err)
	}
	if got := firstText(res); got != "42" {
		t.Fatalf("svc.add = %q, want 42", got)
	}

	// The token was presented on the wire...
	wireMu.Lock()
	sent := wire.String()
	wireMu.Unlock()
	if !strings.Contains(sent, policy.DelegationMetaKey) {
		t.Fatalf("router→gateway wire carries no delegation token:\n%s", sent)
	}
	// ...but never reached the backend.
	backendMu.Lock()
	saw := backendBuf.String()
	backendMu.Unlock()
	if !strings.Contains(saw, "tools/call") {
		t.Fatalf("backend never received the call: %q", saw)
	}
	if strings.Contains(saw, policy.DelegationMetaKey) {
		t.Fatalf("delegation token must be stripped before the backend: %q", saw)
	}

	// Replay: re-present the captured token-bearing line on a fresh connection —
	// the shared nonce store must deny it.
	var tokenLine string
	for _, ln := range strings.Split(sent, "\n") {
		if strings.Contains(ln, policy.DelegationMetaKey) {
			tokenLine = ln
			break
		}
	}
	if tokenLine == "" {
		t.Fatal("no token-bearing line captured")
	}
	raw, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if _, err := raw.Write([]byte(tokenLine + "\n")); err != nil {
		t.Fatal(err)
	}
	raw.SetReadDeadline(time.Now().Add(5 * time.Second))
	replyBuf := make([]byte, 4096)
	n, err := raw.Read(replyBuf)
	if err != nil {
		t.Fatalf("no reply to the replayed line: %v", err)
	}
	if reply := string(replyBuf[:n]); !strings.Contains(reply, "replay") {
		t.Fatalf("replayed token must be denied as a replay, got %q", reply)
	}

	// A direct client with no token is refused on a required surface.
	direct, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	dc := mcpclient.New(direct, nil)
	defer dc.Close()
	if _, err := dc.Initialize(ctx, "direct"); err != nil {
		t.Fatalf("initialize (ungoverned) should pass the filter: %v", err)
	}
	if _, err := dc.CallTool(ctx, "add", map[string]any{"a": 1, "b": 2}, false); err == nil || !strings.Contains(err.Error(), "router delegation required") {
		t.Fatalf("token-less direct call must be refused, got %v", err)
	}
}

// TestRouterDelegationScopeIntersectionE2E: the upstream narrows to the
// intersection — a token-caller the upstream denies is refused even though the
// router is allowed, and vice versa.
func TestRouterDelegationScopeIntersectionE2E(t *testing.T) {
	cases := []struct {
		name       string
		allowPeers []string
		wantDenial string
	}{
		{"caller denied", []string{"pubkey:ROUTERKEY"}, "denied by caller policy"},
		{"router denied", []string{"pubkey:CALLERKEY"}, "denied by router policy"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			authority, _ := policy.GenerateSigner()
			rules := []policy.Rule{{Peers: tc.allowPeers, Tools: []string{"add"}, Allow: true}}
			var backendMu sync.Mutex
			var backendBuf bytes.Buffer
			addr, stop := delegUpstream(t, authority, rules, true, &backendMu, &backendBuf)
			defer stop()

			minter := &delegationMinter{signer: authority, routerKey: "ROUTERKEY", callerKey: "CALLERKEY"}
			agg, cleanup := buildAggregate(context.Background(), loopbackDial,
				map[string]Upstream{"svc": {Addrs: []string{addr}, Audience: "GWKEY"}}, nil, nil, minter)
			defer cleanup()

			mc := clientTo(agg)
			defer mc.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if _, err := mc.Initialize(ctx, "test"); err != nil {
				t.Fatalf("initialize: %v", err)
			}
			res, err := mc.CallTool(ctx, "svc.add", map[string]any{"a": 2, "b": 40}, false)
			if err != nil {
				t.Fatalf("unexpected transport error: %v", err)
			}
			if got := firstText(res); !strings.Contains(got, tc.wantDenial) {
				t.Fatalf("want %q, got %q", tc.wantDenial, got)
			}
			backendMu.Lock()
			saw := backendBuf.String()
			backendMu.Unlock()
			if strings.Contains(saw, `"name":"add"`) {
				t.Fatalf("a denied delegated call reached the backend: %q", saw)
			}
		})
	}
}

// TestRouterDelegationMintFailureDenies: a call whose token cannot be minted
// (here: no caller identity) is DENIED at the router — never forwarded
// unsigned to a pinned upstream.
func TestRouterDelegationMintFailureDenies(t *testing.T) {
	addr, stop := startLoopbackServer(t, func(s *mcp.Server) { s.AddTool(addTool()) })
	defer stop()

	authority, _ := policy.GenerateSigner()
	var wireMu sync.Mutex
	var wire bytes.Buffer
	dial := func(ctx context.Context, a string) (net.Conn, error) {
		c, err := loopbackDial(ctx, a)
		if err != nil {
			return nil, err
		}
		return &captureConn{Conn: c, mu: &wireMu, buf: &wire}, nil
	}
	minter := &delegationMinter{signer: authority, routerKey: "ROUTERKEY", callerKey: ""} // mint must fail
	pool := newUpstreamPool("svc", Upstream{Addrs: []string{addr}, Audience: "GWKEY"}, dial, nil, minter,
		func(string, json.RawMessage) {}, nil)
	defer pool.closeAll()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := pool.call(ctx, "tools/call", map[string]any{"name": "add", "arguments": map[string]any{"a": 1, "b": 2}}); err == nil || !strings.Contains(err.Error(), "not minted") {
		t.Fatalf("mint failure must deny the call, got %v", err)
	}
	wireMu.Lock()
	sent := wire.String()
	wireMu.Unlock()
	if strings.Contains(sent, "tools/call") {
		t.Fatalf("a call denied at mint time must never be dispatched: %q", sent)
	}
}

// TestRouterDelegationSameTokenAcrossRetry: a retry_tools re-dispatch after an
// ambiguous failure presents the SAME token (one nonce per logical call) —
// today's per-gateway nonce stores make cross-gateway failover clean, and a
// future shared store would fail closed rather than double-authorize.
func TestRouterDelegationSameTokenAcrossRetry(t *testing.T) {
	handler := func(s *mcp.Server) {
		s.AddTool(mcp.Tool{Name: "search", Handler: addTool().Handler})
	}
	addrGood, stopGood := startLoopbackServer(t, handler)
	defer stopGood()
	addrFlaky, stopFlaky := startLoopbackServer(t, handler)
	defer stopFlaky()

	authority, _ := policy.GenerateSigner()
	var wireMu sync.Mutex
	var wire bytes.Buffer
	dial := func(ctx context.Context, a string) (net.Conn, error) {
		c, err := loopbackDial(ctx, a)
		if err != nil {
			return nil, err
		}
		c = &captureConn{Conn: c, mu: &wireMu, buf: &wire}
		if a == addrFlaky {
			return &flakyConn{Conn: c}, nil
		}
		return c, nil
	}
	minter := &delegationMinter{signer: authority, routerKey: "ROUTERKEY", callerKey: "CALLERKEY"}
	pool := newUpstreamPool("svc", Upstream{Addrs: []string{addrFlaky, addrGood}, RetryTools: []string{"search"}, Audience: "GWKEY"},
		dial, nil, minter, func(string, json.RawMessage) {}, nil)
	defer pool.closeAll()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := pool.call(ctx, "tools/call", map[string]any{"name": "search", "arguments": map[string]any{}}); err != nil {
		t.Fatalf("classified tool was not retried: %v", err)
	}
	wireMu.Lock()
	captured := wire.String()
	wireMu.Unlock()
	marker := `"` + policy.DelegationMetaKey + `":"`
	first := strings.Index(captured, marker)
	if first < 0 {
		t.Fatalf("no delegation token on the wire:\n%s", captured)
	}
	rest := captured[first+len(marker):]
	tok := rest[:strings.Index(rest, `"`)]
	if got := strings.Count(captured, marker+tok); got != 2 {
		t.Fatalf("the SAME token must ride every dispatch of one logical call: token appeared %d time(s), want 2", got)
	}
}

// TestRouterDelegationLegacyUnchanged: no delegation key + no pin — the wire
// carries no token, the informational origin _meta is still present, and the
// call is allowed exactly as before.
func TestRouterDelegationLegacyUnchanged(t *testing.T) {
	addr, stop := startLoopbackServer(t, func(s *mcp.Server) { s.AddTool(addTool()) })
	defer stop()

	var wireMu sync.Mutex
	var wire bytes.Buffer
	dial := func(ctx context.Context, a string) (net.Conn, error) {
		c, err := loopbackDial(ctx, a)
		if err != nil {
			return nil, err
		}
		return &captureConn{Conn: c, mu: &wireMu, buf: &wire}, nil
	}
	origin := map[string]any{"meshmcpOriginPeer": "c.mesh", "meshmcpOriginKey": "CALLERKEY"}
	agg, cleanup := buildAggregate(context.Background(), dial,
		map[string]Upstream{"svc": {Addrs: []string{addr}}}, origin, nil, nil)
	defer cleanup()

	mc := clientTo(agg)
	defer mc.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := mc.Initialize(ctx, "test"); err != nil {
		t.Fatalf("initialize: %v", err)
	}
	res, err := mc.CallTool(ctx, "svc.add", map[string]any{"a": 2, "b": 40}, false)
	if err != nil {
		t.Fatalf("legacy call failed: %v", err)
	}
	if got := firstText(res); got != "42" {
		t.Fatalf("svc.add = %q, want 42", got)
	}
	wireMu.Lock()
	sent := wire.String()
	wireMu.Unlock()
	if strings.Contains(sent, policy.DelegationMetaKey) {
		t.Fatalf("legacy path must not mint tokens: %q", sent)
	}
	if !strings.Contains(sent, "meshmcpOriginKey") {
		t.Fatalf("informational origin _meta must still ride along: %q", sent)
	}
}

// TestRouterDelegationConfigValidation pins the fail-closed config surface:
// key⇔audience cross-validation, the fatal missing-key-file path with its
// keygen hint, and the keygen round-trip.
func TestRouterDelegationConfigValidation(t *testing.T) {
	dir := t.TempDir()
	writeCfg := func(body string) string {
		p := dir + "/router.yaml"
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	base := "listen_port: 9100\nallow:\n  - \"pubkey:K\"\n"

	// delegation_key without an audience pin on a static upstream → refuse.
	noAud := base + "delegation_key: " + dir + "/missing.key\nupstreams:\n  svc: \"100.64.0.2:9101\"\n"
	if _, err := loadRouterConfig(writeCfg(noAud)); err == nil || !strings.Contains(err.Error(), "audience") {
		t.Fatalf("delegation_key without audience must fail startup, got %v", err)
	}

	// audience pin without delegation_key → refuse.
	noKey := base + "upstreams:\n  svc:\n    addrs: [\"100.64.0.2:9101\"]\n    audience: GWKEY\n"
	if _, err := loadRouterConfig(writeCfg(noKey)); err == nil || !strings.Contains(err.Error(), "delegation_key") {
		t.Fatalf("audience without delegation_key must fail startup, got %v", err)
	}

	// Both set → loads (key-file existence is checked by cmdRouter, fatally).
	both := base + "delegation_key: " + dir + "/missing.key\nupstreams:\n  svc:\n    addrs: [\"100.64.0.2:9101\"]\n    audience: GWKEY\n"
	cfgPath := writeCfg(both)
	if _, err := loadRouterConfig(cfgPath); err != nil {
		t.Fatalf("valid delegation config should load: %v", err)
	}

	// cmdRouter with a missing key file is fatal, with the keygen hint (and
	// fails BEFORE any mesh startup).
	if err := cmdRouter([]string{"-config", cfgPath}); err == nil || !strings.Contains(err.Error(), "router keygen") {
		t.Fatalf("missing delegation key file must be fatal with a keygen hint, got %v", err)
	}

	// Keygen round-trips into a loadable signer.
	keyPath := dir + "/router-delegation.key"
	if err := routerKeygen([]string{"-out", keyPath}); err != nil {
		t.Fatalf("router keygen: %v", err)
	}
	if _, err := policy.LoadSigner(keyPath); err != nil {
		t.Fatalf("generated key must load: %v", err)
	}
}

// TestGatewayRouterDelegationConfigValidation pins the gateway-side
// router_delegation config checks (stdio-only, policy required, pinned keys).
func TestGatewayRouterDelegationConfigValidation(t *testing.T) {
	dir := t.TempDir()
	goodKey := strings.Repeat("ab", 32)
	writeCfg := func(body string) string {
		p := dir + "/gw.yaml"
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	head := "backends:\n  - name: svc\n    port: 9101\n"
	stdio := "    stdio: [\"cmd\"]\n"
	pol := "    policy:\n      default_allow: false\n"

	cases := []struct {
		name    string
		body    string
		wantErr string // "" = must load
	}{
		{"valid", head + stdio + pol + "    router_delegation:\n      required: true\n      trusted_public_keys: [\"" + goodKey + "\"]\n", ""},
		{"http backend", head + "    http: \"http://127.0.0.1:9\"\n" + pol + "    router_delegation:\n      trusted_public_keys: [\"" + goodKey + "\"]\n", "stdio"},
		{"no policy", head + stdio + "    router_delegation:\n      trusted_public_keys: [\"" + goodKey + "\"]\n", "policy"},
		{"no keys", head + stdio + pol + "    router_delegation:\n      required: true\n", "trusted_public_keys"},
		{"bad key", head + stdio + pol + "    router_delegation:\n      trusted_public_keys: [\"nothex\"]\n", "Ed25519"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := loadConfig(writeCfg(tc.body))
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("should load: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}
