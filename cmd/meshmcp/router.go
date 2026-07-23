package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path"
	"sync"
	"time"

	"github.com/netbirdio/netbird/client/embed"
	"gopkg.in/yaml.v3"

	"github.com/xrey167/meshmcp/mcp"
	"github.com/xrey167/meshmcp/mcpclient"
	"github.com/xrey167/meshmcp/policy"
	"github.com/xrey167/meshmcp/registry"
)

// RouterConfig configures the aggregating router: it joins the mesh, listens
// on one port, and presents the namespaced union of its upstream backends as
// a single MCP endpoint. Each upstream may have several replica addresses,
// across which the router load-balances and fails over.
type RouterConfig struct {
	Mesh       MeshConfig          `yaml:"mesh"`
	ListenPort int                 `yaml:"listen_port"`
	Upstreams  map[string]Upstream `yaml:"upstreams"` // static: name -> one or more peer:port
	Registry   string              `yaml:"registry"`  // dir: discover upstreams dynamically
	// Allow lists the mesh identities permitted to use the router
	// ("pubkey:<key>" or an FQDN glob). The router is DEFAULT-DENY: reaching its
	// port is not enough, and an empty allow list is a startup error. This keeps
	// the router from acting as an unrestricted confused deputy (delegated
	// identity to upstreams is still experimental — see docs/spec/ROUTER-DELEGATION.md).
	Allow []string `yaml:"allow"`
	// Policy, when set, is enforced at the router on every forwarded tools/call,
	// keyed by the ORIGINAL caller's transport identity and the namespaced tool
	// name (e.g. "svca.transfer"). It narrows what an admitted caller may drive
	// through the router from "any upstream tool" to exactly what the policy
	// allows — the confused-deputy blast-radius reduction the router owns locally,
	// independent of the (Labs) signed-delegation upstream verification. Router
	// policy should use allow/deny/rate rules; a require_cosign rule denies here
	// (the router is not a co-sign enforcement point). Optional; when unset the
	// router only does mesh + caller-ACL admission (prior behavior).
	Policy *policy.Policy `yaml:"policy"`
	// DelegationKey is the router's delegation-authority Ed25519 key file
	// (create it with "meshmcp router keygen"). When set, the router mints a
	// signed, short-lived, per-call DelegationToken for every forwarded
	// tools/call to an audience-pinned upstream, carried in
	// params._meta["com.meshmcp/delegation"]; a pinned upstream gateway
	// verifies it and authorizes the intersection of the ORIGINAL caller's and
	// the router's permissions (docs/spec/ROUTER-DELEGATION.md). A configured
	// but missing/unreadable key is FATAL at startup (S13 pattern) — never a
	// silent downgrade to unsigned forwarding. Requires every static upstream
	// to carry an `audience` pin.
	DelegationKey string `yaml:"delegation_key"`
}

// toolEnforcer authorizes one forwarded tools/call by its namespaced name and
// arguments, returning a non-nil error (a denial) when the router policy forbids
// it. nil means no router-side tool policy is configured.
type toolEnforcer func(namespacedTool string, args json.RawMessage) error

// callerAllowed reports whether a caller may use the router. Default-deny: an
// empty allow list admits no one.
func routerCallerAllowed(allow acl, pubKey, fqdn string) bool {
	return !allow.empty() && allow.allows(pubKey, fqdn)
}

// Upstream is a set of interchangeable replica addresses for one logical
// upstream. In YAML it may be written as a single string, a list, or a mapping
// with `addrs` and options.
type Upstream struct {
	Addrs []string
	// RetryTools lists tool-name globs the OPERATOR classifies as safe to
	// re-dispatch to another replica after an ambiguous transport failure
	// (idempotent or read-only tools). Every dispatch of a matching tools/call
	// carries the same _meta idempotency key so a cooperating backend can
	// deduplicate. Unlisted tools keep the deny-default: never auto-retried
	// after dispatch.
	RetryTools []string
	// Audience is the upstream gateway's mesh public key, pinned by the
	// operator (settles ROUTER-DELEGATION.md decision (a): the router learns
	// each upstream's identity by pin, not discovery). It becomes the `aud`
	// claim of every delegation token minted for this upstream, so a token for
	// one upstream never verifies at another. Required on every static
	// upstream when delegation_key is set.
	Audience string
}

func (u *Upstream) UnmarshalYAML(value *yaml.Node) error {
	var one string
	if err := value.Decode(&one); err == nil {
		u.Addrs = []string{one}
		return nil
	}
	var many []string
	if err := value.Decode(&many); err == nil {
		u.Addrs = many
		return nil
	}
	var m struct {
		Addrs      []string `yaml:"addrs"`
		RetryTools []string `yaml:"retry_tools"`
		Audience   string   `yaml:"audience"`
	}
	if err := value.Decode(&m); err == nil && len(m.Addrs) > 0 {
		u.Addrs = m.Addrs
		u.RetryTools = m.RetryTools
		u.Audience = m.Audience
		return nil
	}
	return fmt.Errorf("upstream must be a string, a list of strings, or a mapping with addrs (+ optional retry_tools, audience)")
}

// upstreamSet copies the static upstream map so discovery can merge registry
// entries without mutating config.
func (c *RouterConfig) upstreamSet() map[string]Upstream {
	m := make(map[string]Upstream, len(c.Upstreams))
	for name, up := range c.Upstreams {
		m[name] = up
	}
	return m
}

func loadRouterConfig(path string) (*RouterConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var cfg RouterConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	if cfg.ListenPort <= 0 || cfg.ListenPort > 65535 {
		return nil, errors.New("listen_port must be 1-65535")
	}
	if len(cfg.Upstreams) == 0 && cfg.Registry == "" {
		return nil, errors.New("at least one upstream or a registry is required")
	}
	if len(cfg.Allow) == 0 {
		return nil, errors.New("router requires an allow list (default-deny): set 'allow' to the mesh identities (pubkey:<key> or FQDN globs) permitted to use the router")
	}
	for name, up := range cfg.Upstreams {
		if len(up.Addrs) == 0 {
			return nil, fmt.Errorf("upstream %q: at least one address required", name)
		}
		// Fail-closed cross-validation, both directions: with a delegation key,
		// a static upstream without an audience pin would silently be called
		// UNSIGNED — refuse at startup instead. An audience pin without the key
		// is a token that can never be minted — also a config error.
		if cfg.DelegationKey != "" && up.Audience == "" {
			return nil, fmt.Errorf("upstream %q: delegation_key is set but this upstream has no audience pin — every static upstream must pin its gateway's mesh public key (audience: <key>), or calls to it would be forwarded unsigned", name)
		}
		if cfg.DelegationKey == "" && up.Audience != "" {
			return nil, fmt.Errorf("upstream %q: audience is pinned but delegation_key is not set — the router cannot mint delegation tokens without its authority key (run 'meshmcp router keygen')", name)
		}
	}
	return &cfg, nil
}

// cmdRouter runs the aggregating router (or its keygen subcommand).
func cmdRouter(args []string) error {
	if len(args) > 0 && args[0] == "keygen" {
		return routerKeygen(args[1:])
	}
	fs := flag.NewFlagSet("router", flag.ExitOnError)
	cfgPath := fs.String("config", "router.yaml", "path to the router config file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := loadRouterConfig(*cfgPath)
	if err != nil {
		return err
	}

	// Load the delegation authority key BEFORE joining the mesh: a configured
	// but missing/unreadable key is FATAL (S13 pattern), never a silent
	// downgrade to unsigned forwarding.
	var delegSigner *policy.Signer
	if cfg.DelegationKey != "" {
		delegSigner, err = policy.LoadSigner(cfg.DelegationKey)
		if err != nil {
			return fmt.Errorf("router delegation_key %s: %w — run 'meshmcp router keygen --out %s' to create the router authority key", cfg.DelegationKey, err, cfg.DelegationKey)
		}
	}

	client, err := startMesh(cfg.Mesh.options(), os.Stderr)
	if err != nil {
		return err
	}
	defer stopMesh(client)

	routerKey := ""
	if st, err := client.Status(); err == nil {
		routerKey = st.LocalPeerState.PubKey
		log.Printf("router up: %s (%s) — %d upstreams on port %d",
			st.LocalPeerState.IP, st.LocalPeerState.FQDN, len(cfg.Upstreams), cfg.ListenPort)
	}
	if delegSigner != nil && routerKey == "" {
		// A token with an empty router claim cannot be minted (IssueDelegation
		// rejects it); fail at startup with a clear error, not at first call.
		return fmt.Errorf("router delegation: the mesh reports no local public key — cannot mint delegation tokens (the token's router claim would be empty)")
	}
	if delegSigner != nil {
		log.Printf("router: delegation active (authority %s…) — every tools/call to an audience-pinned upstream carries a signed per-call token", delegSigner.PubKeyHex()[:16])
	}

	ln, err := client.ListenTCP(fmt.Sprintf(":%d", cfg.ListenPort))
	if err != nil {
		return fmt.Errorf("listen on mesh port %d: %w", cfg.ListenPort, err)
	}

	// discover merges the static upstreams with the registry (if configured),
	// re-read per connection so new backends are picked up dynamically.
	var reg *registry.FileRegistry
	if cfg.Registry != "" {
		if reg, err = registry.NewFileRegistry(cfg.Registry); err != nil {
			return fmt.Errorf("registry %s: %w", cfg.Registry, err)
		}
		log.Printf("router: dynamic discovery via registry %s", cfg.Registry)
		if delegSigner != nil {
			// Registry-discovered upstreams have no operator audience pin, so no
			// token can be minted for them: calls take the legacy unsigned path.
			log.Printf("router: registry-discovered upstreams carry no audience pin — calls to them are NOT delegated (legacy unsigned path)")
		}
	}
	discover := func() map[string]Upstream {
		m := cfg.upstreamSet()
		if reg != nil {
			if rm, err := reg.Lookup(); err == nil {
				for name, addrs := range rm {
					up := m[name]
					up.Addrs = dedupeAddrs(append(up.Addrs, addrs...))
					m[name] = up
				}
			}
		}
		return m
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, shutdownSignals...)
	go func() { <-sig; ln.Close() }()

	allow := newACL(cfg.Allow)
	log.Printf("router: caller allow list active (%v)", cfg.Allow)
	var eng *policy.Engine
	if cfg.Policy != nil {
		eng = policy.NewEngine(cfg.Policy, func() time.Time { return time.Now() }, nil)
		log.Printf("router: tool policy active (%d rules, default_allow=%v) — forwarded tools/call is authorized per caller",
			len(cfg.Policy.Rules), cfg.Policy.DefaultAllow)
	}
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println("router shutting down")
			return nil
		}
		go handleRouterConn(client, conn, discover(), allow, eng, delegSigner, routerKey)
	}
}

func dedupeAddrs(addrs []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, a := range addrs {
		if !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	return out
}

// dialFunc opens a transport connection to an upstream address. In
// production it dials over the mesh; tests supply a loopback dialer.
type dialFunc func(ctx context.Context, addr string) (net.Conn, error)

// handleRouterConn serves one downstream client: it discovers every
// upstream, presents their union, and routes calls until the client leaves.
// delegSigner/routerKey, when set, make every forwarded tools/call to an
// audience-pinned upstream carry a signed per-call DelegationToken binding
// THIS client's transport-proven identity as the original caller.
func handleRouterConn(client *embed.Client, conn net.Conn, upstreams map[string]Upstream, allow acl, eng *policy.Engine, delegSigner *policy.Signer, routerKey string) {
	defer conn.Close()
	ctx := context.Background()

	// The end client's cryptographic mesh identity, carried through to
	// upstreams as an "on behalf of" hint in request _meta.
	pubKey, fqdn := peerIdentity(client, conn.RemoteAddr())
	// Default-deny caller ACL: the router only serves explicitly-allowed mesh
	// identities, so it cannot be used as an open confused deputy.
	if !routerCallerAllowed(allow, pubKey, fqdn) {
		log.Printf("router: DENIED client %s (%s) — not on the caller allow list", fqdn, conn.RemoteAddr())
		return
	}
	log.Printf("router: serving client %s (%s)", fqdn, conn.RemoteAddr())
	origin := map[string]any{"meshmcpOriginPeer": fqdn, "meshmcpOriginKey": pubKey}

	// When a router policy is configured, authorize every forwarded tools/call
	// against the ORIGINAL caller's transport identity (never _meta). This is a
	// router-local enforcement point: it cannot be used to widen a caller's
	// authority, only to narrow it.
	var enforce toolEnforcer
	if eng != nil {
		enforce = func(namespacedTool string, _ json.RawMessage) error {
			dec := eng.DecideToolCall(fqdn, pubKey, namespacedTool, nil)
			if dec.Outcome != policy.OutcomeAllow {
				reason := dec.Reason
				if reason == "" {
					reason = "not permitted by router policy"
				}
				log.Printf("router: DENY tool %q for %s (%s): %s", namespacedTool, fqdn, pubKey, reason)
				return fmt.Errorf("router policy denies %q: %s", namespacedTool, reason)
			}
			return nil
		}
	}

	dial := func(ctx context.Context, addr string) (net.Conn, error) {
		return client.Dial(ctx, "tcp", addr)
	}
	// The minter binds this connection's transport-proven caller identity —
	// never anything the client sent in-band.
	var minter *delegationMinter
	if delegSigner != nil {
		minter = &delegationMinter{signer: delegSigner, routerKey: routerKey, callerKey: pubKey}
	}
	s, cleanup := buildAggregate(ctx, dial, upstreams, origin, enforce, minter)
	defer cleanup()
	_ = s.Serve(ctx, conn, conn)
}

// delegationMinter mints per-call DelegationTokens for one downstream client:
// signer is the router's delegation authority key, routerKey the router's own
// mesh public key (the token's router claim), and callerKey the ORIGINAL
// caller's transport-proven key (the token's caller claim).
type delegationMinter struct {
	signer    *policy.Signer
	routerKey string
	callerKey string
}

// withDelegation returns a copy of tools/call params carrying a freshly minted
// delegation token in _meta["com.meshmcp/delegation"]. The token's req_hash
// covers exactly the arguments being forwarded (canonically hashed), so _meta
// injection cannot perturb it. Any failure is an error — the caller must DENY
// the call rather than forward it unsigned (fail-closed).
func (m *delegationMinter) withDelegation(params any, audience, backend string) (any, error) {
	pm, ok := params.(map[string]any)
	if !ok {
		return nil, errors.New("tools/call params are not an object")
	}
	name, _ := pm["name"].(string)
	if name == "" {
		return nil, errors.New("tools/call params carry no tool name")
	}
	// Marshal the exact arguments being forwarded; a nil/absent value hashes as
	// JSON null, matching what the upstream classifier will see on the wire.
	args, err := json.Marshal(pm["arguments"])
	if err != nil {
		return nil, fmt.Errorf("marshal arguments: %w", err)
	}
	tok, err := m.signer.IssueDelegation(policy.DelegationClaims{
		Caller: m.callerKey, Router: m.routerKey, Audience: audience,
		Backend: backend, Tool: name, Args: args,
	}, time.Now())
	if err != nil {
		return nil, err
	}
	enc, err := policy.EncodeDelegation(tok)
	if err != nil {
		return nil, err
	}
	cp := make(map[string]any, len(pm)+1)
	for k, v := range pm {
		cp[k] = v
	}
	meta := map[string]any{}
	if prior, ok := cp["_meta"].(map[string]any); ok {
		for k, v := range prior {
			meta[k] = v
		}
	}
	meta[policy.DelegationMetaKey] = enc
	cp["_meta"] = meta
	return cp, nil
}

// replicaCooldown is how long a failed replica is skipped before a retry.
const replicaCooldown = 5 * time.Second

// replica is one interchangeable backend address for an upstream.
type replica struct {
	addr     string
	client   *mcpclient.Client
	failedAt time.Time
}

// upstreamPool load-balances calls across an upstream's replicas
// (round-robin) and fails over around dead ones, re-dialing lazily.
type upstreamPool struct {
	name       string
	dial       dialFunc
	origin     map[string]any
	retryTools []string // operator-classified retry-safe tool globs (see Upstream)
	minter     *delegationMinter
	audience   string // operator-pinned upstream gateway key ("" = no delegation)
	notify     func(method string, params json.RawMessage)
	relay      func(ctx context.Context, method string, params json.RawMessage) (json.RawMessage, *mcpclient.RPCError)

	mu       sync.Mutex
	replicas []*replica
	next     int
}

func newUpstreamPool(name string, up Upstream, dial dialFunc, origin map[string]any, minter *delegationMinter,
	notify func(string, json.RawMessage),
	relay func(context.Context, string, json.RawMessage) (json.RawMessage, *mcpclient.RPCError)) *upstreamPool {
	p := &upstreamPool{
		name: name, dial: dial, origin: origin, minter: minter, audience: up.Audience,
		notify: notify, relay: relay,
		retryTools: append([]string(nil), up.RetryTools...),
	}
	for _, a := range up.Addrs {
		p.replicas = append(p.replicas, &replica{addr: a})
	}
	return p
}

// get returns a connected client for r, dialing + initializing on demand and
// respecting the cooldown after a recent failure. Caller holds p.mu.
func (p *upstreamPool) get(ctx context.Context, r *replica) (*mcpclient.Client, error) {
	if r.client != nil {
		return r.client, nil
	}
	if !r.failedAt.IsZero() && time.Since(r.failedAt) < replicaCooldown {
		return nil, fmt.Errorf("replica %s in cooldown", r.addr)
	}
	conn, err := p.dial(ctx, r.addr)
	if err != nil {
		r.failedAt = time.Now()
		return nil, err
	}
	uc := mcpclient.New(conn, p.notify)
	uc.RequestMeta = p.origin
	uc.SetOnRequest(p.relay) // relay upstream reverse-requests (sampling, ...) to the client
	if _, err := uc.Initialize(ctx, "meshmcp-router"); err != nil {
		uc.Close()
		r.failedAt = time.Now()
		return nil, err
	}
	r.client = uc
	r.failedAt = time.Time{}
	return uc, nil
}

func (p *upstreamPool) markDown(r *replica) {
	if r.client != nil {
		r.client.Close()
		r.client = nil
	}
	r.failedAt = time.Now()
}

// any returns any healthy client (for discovery). Caller must not hold p.mu.
func (p *upstreamPool) any(ctx context.Context) (*mcpclient.Client, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	var lastErr error
	for i := 0; i < len(p.replicas); i++ {
		r := p.replicas[p.next%len(p.replicas)]
		p.next++
		if uc, err := p.get(ctx, r); err == nil {
			return uc, nil
		} else {
			lastErr = err
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("upstream %q: no replicas", p.name)
	}
	return nil, lastErr
}

// safeToRetryAfterDispatch reports whether a method may be re-sent to another
// replica AFTER it was already dispatched on a live connection but the transport
// failed before a response arrived. Such a failure is an AMBIGUOUS outcome: the
// upstream may have already executed the request. Only read-only methods (no
// side effects) are safe to repeat. tools/call is treated as potentially
// mutating (unknown), so it is never auto-retried after dispatch — repeating it
// could execute a non-idempotent side effect (a payment, a deploy) twice.
//
// The one exception is operator classification: an upstream's `retry_tools`
// globs mark specific tools as idempotent/read-only, and a matching tools/call
// is dispatched with a stable _meta idempotency key so a cooperating backend
// can deduplicate a re-send (see retryEligibleToolCall). Everything else stays
// non-retryable. See docs/THREAT-MODEL.md (delivery vs. execution).
func safeToRetryAfterDispatch(method string) bool {
	switch method {
	case "resources/read", "resources/list", "resources/templates/list",
		"tools/list", "prompts/list", "prompts/get", "initialize", "ping":
		return true
	default:
		return false
	}
}

// call routes one JSON-RPC request to a healthy replica. It fails over freely
// when a replica cannot be reached at all (the request was never sent). But once
// a request has been DISPATCHED on a live connection and the transport then
// fails, the outcome is unknown: it re-sends only methods that are safe to
// repeat (see safeToRetryAfterDispatch) and otherwise surfaces the ambiguous
// failure to the caller rather than risk double-executing a side effect. An
// application-level RPC error is returned as-is (the replica is healthy — the
// tool just returned an error).
func (p *upstreamPool) call(ctx context.Context, method string, params any) (json.RawMessage, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.replicas) == 0 {
		return nil, fmt.Errorf("upstream %q: no replicas", p.name)
	}
	// Delegation: mint ONE token per logical tools/call, before the replica
	// loop, so every dispatch attempt of this call presents the same token and
	// nonce (a token is single-use at the upstream — replay is keyed on the
	// nonce, and today's nonce stores are per-gateway-process, so a failover to
	// a DIFFERENT gateway re-presents it cleanly; a future shared store would
	// fail closed on such a failover). A mint failure DENIES the call — it is
	// never forwarded unsigned. Only static, audience-pinned upstreams are
	// delegated; registry-discovered ones (no pin) keep the legacy path.
	if method == "tools/call" && p.minter != nil && p.audience != "" {
		decorated, err := p.minter.withDelegation(params, p.audience, p.name)
		if err != nil {
			return nil, fmt.Errorf("upstream %q: delegation token not minted — call denied (fail-closed, never forwarded unsigned): %w", p.name, err)
		}
		params = decorated
	}
	retryable := safeToRetryAfterDispatch(method)
	if !retryable && p.retryEligibleToolCall(method, params) {
		// Attach the idempotency key once, so every dispatch attempt of this
		// logical call presents the same key. If no key can be attached, the
		// call stays non-retryable (deny-default).
		if decorated, ok := withIdempotencyKey(params); ok {
			params = decorated
			retryable = true
		}
	}
	var lastErr error
	for i := 0; i < len(p.replicas); i++ {
		r := p.replicas[p.next%len(p.replicas)]
		p.next++
		uc, err := p.get(ctx, r)
		if err != nil {
			// Never connected/initialized on this replica: the request was not
			// sent here, so trying another replica is safe for any method.
			lastErr = err
			continue
		}
		res, err := uc.Call(ctx, method, params)
		if err == nil {
			return res, nil
		}
		if _, isRPC := err.(*mcpclient.RPCError); isRPC {
			return nil, err // healthy replica, application error
		}
		// Transport error after dispatch: the upstream may have executed this
		// request. Mark the replica down, but only fail over for methods that are
		// safe to repeat; for a potentially-mutating call, stop and report the
		// ambiguity instead of silently retrying it elsewhere.
		p.markDown(r)
		lastErr = err
		if !retryable {
			return nil, fmt.Errorf("upstream %q: %s not retried after an ambiguous transport failure (outcome unknown — the upstream may have already executed it): %w", p.name, method, err)
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("upstream %q: all replicas failed", p.name)
	}
	return nil, lastErr
}

// retryEligibleToolCall reports whether this tools/call names a tool the
// operator classified as retry-safe for this upstream (`retry_tools` globs).
// Anything unparseable is not eligible — deny-default.
func (p *upstreamPool) retryEligibleToolCall(method string, params any) bool {
	if method != "tools/call" || len(p.retryTools) == 0 {
		return false
	}
	pm, ok := params.(map[string]any)
	if !ok {
		return false
	}
	name, ok := pm["name"].(string)
	if !ok || name == "" {
		return false
	}
	for _, g := range p.retryTools {
		if ok, _ := path.Match(g, name); ok {
			return true
		}
	}
	return false
}

// withIdempotencyKey returns a copy of params carrying a fresh random key in
// _meta["meshmcp.io/idempotency-key"], so a re-dispatched call presents the
// same key and a cooperating backend can deduplicate. ok is false when no key
// could be attached; the caller must then not retry.
func withIdempotencyKey(params any) (any, bool) {
	pm, ok := params.(map[string]any)
	if !ok {
		return params, false
	}
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return params, false
	}
	cp := make(map[string]any, len(pm)+1)
	for k, v := range pm {
		cp[k] = v
	}
	meta := map[string]any{}
	if prior, ok := cp["_meta"].(map[string]any); ok {
		for k, v := range prior {
			meta[k] = v
		}
	}
	meta["meshmcp.io/idempotency-key"] = hex.EncodeToString(b[:])
	cp["_meta"] = meta
	return cp, true
}

func (p *upstreamPool) closeAll() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, r := range p.replicas {
		if r.client != nil {
			r.client.Close()
			r.client = nil
		}
	}
}

// healthInterval is how often the pool proactively re-dials down replicas.
var healthInterval = 3 * time.Second

// healthCheck proactively re-dials replicas that are down and past their
// cooldown, so a recovered replica is ready before the next call needs it.
func (p *upstreamPool) healthCheck(ctx context.Context) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, r := range p.replicas {
		if r.client == nil && (r.failedAt.IsZero() || time.Since(r.failedAt) >= replicaCooldown) {
			_, _ = p.get(ctx, r) // dials+inits; sets failedAt again on failure
		}
	}
}

func (p *upstreamPool) runHealth(stop <-chan struct{}) {
	t := time.NewTicker(healthInterval)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			p.healthCheck(context.Background())
		}
	}
}

// buildAggregate discovers each upstream via a healthy replica and registers
// proxy tools/resources/prompts (tools and prompts namespaced by upstream
// name; resources keyed by URI, first owner wins). Calls are load-balanced
// and failed over across replicas; upstream notifications are forwarded to
// the client and origin identity is stamped into every request's _meta.
func buildAggregate(ctx context.Context, dial dialFunc, upstreams map[string]Upstream, origin map[string]any, enforce toolEnforcer, minter *delegationMinter) (*mcp.Server, func()) {
	s := mcp.New("meshmcp-router", "0.1.0")
	var pools []*upstreamPool
	seenURI := map[string]bool{}

	// relay forwards an upstream's server->client request down to the end
	// client and returns its response (full bidirectional MCP through the hop).
	relay := func(ctx context.Context, method string, params json.RawMessage) (json.RawMessage, *mcpclient.RPCError) {
		res, err := s.Request(ctx, method, params)
		if err != nil {
			return nil, &mcpclient.RPCError{Code: -32000, Message: err.Error()}
		}
		return res, nil
	}

	for name, up := range upstreams {
		pool := newUpstreamPool(name, up, dial, origin, minter, func(method string, params json.RawMessage) {
			s.Notify(method, json.RawMessage(params))
		}, relay)
		pools = append(pools, pool)

		uc, err := pool.any(ctx)
		if err != nil {
			log.Printf("router: upstream %q discovery failed: %v", name, err)
			continue
		}
		if tools, err := uc.ListTools(ctx); err == nil {
			for _, t := range tools {
				registerProxyTool(s, name, t, pool, enforce)
			}
		}
		if res, err := uc.ListResources(ctx); err == nil {
			for _, r := range res {
				if seenURI[r.URI] {
					continue
				}
				seenURI[r.URI] = true
				registerProxyResource(s, r, pool)
			}
		}
		if prompts, err := uc.ListPrompts(ctx); err == nil {
			for _, pr := range prompts {
				registerProxyPrompt(s, name, pr, pool)
			}
		}
		log.Printf("router: upstream %q ready (%d replicas)", name, len(up.Addrs))
	}

	// Proactively re-dial down replicas in the background.
	stop := make(chan struct{})
	for _, pool := range pools {
		go pool.runHealth(stop)
	}

	return s, func() {
		close(stop)
		for _, p := range pools {
			p.closeAll()
		}
	}
}

func registerProxyTool(s *mcp.Server, ns string, t mcpclient.Tool, pool *upstreamPool, enforce toolEnforcer) {
	var schema map[string]any
	if len(t.InputSchema) > 0 {
		_ = json.Unmarshal(t.InputSchema, &schema)
	}
	namespaced := ns + "." + t.Name
	s.AddTool(mcp.Tool{
		Name:        namespaced,
		Description: t.Description,
		InputSchema: schema,
		Handler: func(ctx context.Context, args json.RawMessage) (mcp.ToolResult, error) {
			// Authorize against the router's own policy BEFORE forwarding, so an
			// admitted caller can drive only the tools the router permits — never
			// the full upstream surface.
			if enforce != nil {
				if err := enforce(namespaced, args); err != nil {
					return mcp.ToolResult{}, err
				}
			}
			raw, err := pool.call(ctx, "tools/call", map[string]any{"name": t.Name, "arguments": args})
			if err != nil {
				return mcp.ToolResult{}, err
			}
			var tr mcp.ToolResult
			if err := json.Unmarshal(raw, &tr); err != nil {
				return mcp.ToolResult{}, err
			}
			return tr, nil
		},
	})
}

func registerProxyResource(s *mcp.Server, r mcpclient.Resource, pool *upstreamPool) {
	s.AddResource(mcp.Resource{
		URI:         r.URI,
		Name:        r.Name,
		Description: r.Description,
		MimeType:    r.MimeType,
		Read: func(ctx context.Context) (mcp.ResourceContents, error) {
			raw, err := pool.call(ctx, "resources/read", map[string]any{"uri": r.URI})
			if err != nil {
				return mcp.ResourceContents{}, err
			}
			var out struct {
				Contents []mcp.ResourceContents `json:"contents"`
			}
			if err := json.Unmarshal(raw, &out); err != nil || len(out.Contents) == 0 {
				return mcp.ResourceContents{URI: r.URI}, err
			}
			return out.Contents[0], nil
		},
	})
}

// routerKeygen generates the router's delegation-authority Ed25519 key and
// prints the public key upstream gateways pin (router_delegation.trusted_public_keys).
func routerKeygen(args []string) error {
	fs := flag.NewFlagSet("router keygen", flag.ContinueOnError)
	out := fs.String("out", "router-delegation.key", "path to write the router authority key (0600)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	s, err := policy.GenerateSigner()
	if err != nil {
		return err
	}
	if err := s.SaveSigner(*out); err != nil {
		return err
	}
	fmt.Printf("wrote router delegation authority key to %s\n", *out)
	fmt.Printf("public key: %s\n", s.PubKeyHex())
	fmt.Printf("\nrouter config:\n  delegation_key: %s\n", *out)
	fmt.Printf("\npin it on an upstream gateway backend:\n  router_delegation:\n    trusted_public_keys: [\"%s\"]\n    required: true\n", s.PubKeyHex())
	return nil
}

func registerProxyPrompt(s *mcp.Server, ns string, p mcpclient.Prompt, pool *upstreamPool) {
	var argsList []mcp.PromptArg
	if len(p.Arguments) > 0 {
		_ = json.Unmarshal(p.Arguments, &argsList)
	}
	s.AddPrompt(mcp.Prompt{
		Name:        ns + "." + p.Name,
		Description: p.Description,
		Arguments:   argsList,
		Get: func(ctx context.Context, args map[string]string) (mcp.PromptResult, error) {
			raw, err := pool.call(ctx, "prompts/get", map[string]any{"name": p.Name, "arguments": args})
			if err != nil {
				return mcp.PromptResult{}, err
			}
			var pr mcp.PromptResult
			if err := json.Unmarshal(raw, &pr); err != nil {
				return mcp.PromptResult{}, err
			}
			return pr, nil
		},
	})
}
