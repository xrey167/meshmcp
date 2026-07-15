package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"time"

	"github.com/netbirdio/netbird/client/embed"
	"gopkg.in/yaml.v3"

	"meshmcp/mcp"
	"meshmcp/mcpclient"
	"meshmcp/registry"
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
}

// Upstream is a set of interchangeable replica addresses for one logical
// upstream. In YAML it may be written as a single string or a list.
type Upstream struct {
	Addrs []string
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
	return fmt.Errorf("upstream must be a string or a list of strings")
}

// addrs flattens the config into name -> replica addresses.
func (c *RouterConfig) addrs() map[string][]string {
	m := make(map[string][]string, len(c.Upstreams))
	for name, up := range c.Upstreams {
		m[name] = up.Addrs
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
	for name, up := range cfg.Upstreams {
		if len(up.Addrs) == 0 {
			return nil, fmt.Errorf("upstream %q: at least one address required", name)
		}
	}
	return &cfg, nil
}

// cmdRouter runs the aggregating router.
func cmdRouter(args []string) error {
	fs := flag.NewFlagSet("router", flag.ExitOnError)
	cfgPath := fs.String("config", "router.yaml", "path to the router config file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := loadRouterConfig(*cfgPath)
	if err != nil {
		return err
	}

	client, err := startMesh(cfg.Mesh.options(), os.Stderr)
	if err != nil {
		return err
	}
	defer stopMesh(client)

	if st, err := client.Status(); err == nil {
		log.Printf("router up: %s (%s) — %d upstreams on port %d",
			st.LocalPeerState.IP, st.LocalPeerState.FQDN, len(cfg.Upstreams), cfg.ListenPort)
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
	}
	discover := func() map[string][]string {
		m := cfg.addrs()
		if reg != nil {
			if rm, err := reg.Lookup(); err == nil {
				for name, addrs := range rm {
					m[name] = dedupeAddrs(append(m[name], addrs...))
				}
			}
		}
		return m
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	go func() { <-sig; ln.Close() }()

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println("router shutting down")
			return nil
		}
		go handleRouterConn(client, conn, discover())
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
func handleRouterConn(client *embed.Client, conn net.Conn, upstreams map[string][]string) {
	defer conn.Close()
	ctx := context.Background()

	// The end client's cryptographic mesh identity, carried through to
	// upstreams as an "on behalf of" hint in request _meta.
	pubKey, fqdn := peerIdentity(client, conn.RemoteAddr())
	log.Printf("router: serving client %s (%s)", fqdn, conn.RemoteAddr())
	origin := map[string]any{"meshmcpOriginPeer": fqdn, "meshmcpOriginKey": pubKey}

	dial := func(ctx context.Context, addr string) (net.Conn, error) {
		return client.Dial(ctx, "tcp", addr)
	}
	s, cleanup := buildAggregate(ctx, dial, upstreams, origin)
	defer cleanup()
	_ = s.Serve(ctx, conn, conn)
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
	name   string
	dial   dialFunc
	origin map[string]any
	notify func(method string, params json.RawMessage)
	relay  func(ctx context.Context, method string, params json.RawMessage) (json.RawMessage, *mcpclient.RPCError)

	mu       sync.Mutex
	replicas []*replica
	next     int
}

func newUpstreamPool(name string, addrs []string, dial dialFunc, origin map[string]any,
	notify func(string, json.RawMessage),
	relay func(context.Context, string, json.RawMessage) (json.RawMessage, *mcpclient.RPCError)) *upstreamPool {
	p := &upstreamPool{name: name, dial: dial, origin: origin, notify: notify, relay: relay}
	for _, a := range addrs {
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

// call routes one JSON-RPC request to a healthy replica, failing over on a
// transport error. An application-level RPC error is returned as-is (the
// replica is healthy — the tool just returned an error).
func (p *upstreamPool) call(ctx context.Context, method string, params any) (json.RawMessage, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.replicas) == 0 {
		return nil, fmt.Errorf("upstream %q: no replicas", p.name)
	}
	var lastErr error
	for i := 0; i < len(p.replicas); i++ {
		r := p.replicas[p.next%len(p.replicas)]
		p.next++
		uc, err := p.get(ctx, r)
		if err != nil {
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
		p.markDown(r) // transport error: fail over
		lastErr = err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("upstream %q: all replicas failed", p.name)
	}
	return nil, lastErr
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
func buildAggregate(ctx context.Context, dial dialFunc, upstreams map[string][]string, origin map[string]any) (*mcp.Server, func()) {
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

	for name, addrs := range upstreams {
		pool := newUpstreamPool(name, addrs, dial, origin, func(method string, params json.RawMessage) {
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
				registerProxyTool(s, name, t, pool)
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
		log.Printf("router: upstream %q ready (%d replicas)", name, len(addrs))
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

func registerProxyTool(s *mcp.Server, ns string, t mcpclient.Tool, pool *upstreamPool) {
	var schema map[string]any
	if len(t.InputSchema) > 0 {
		_ = json.Unmarshal(t.InputSchema, &schema)
	}
	s.AddTool(mcp.Tool{
		Name:        ns + "." + t.Name,
		Description: t.Description,
		InputSchema: schema,
		Handler: func(ctx context.Context, args json.RawMessage) (mcp.ToolResult, error) {
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
