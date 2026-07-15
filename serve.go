package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"os/signal"
	"strings"
	"sync"
	"time"

	"github.com/netbirdio/netbird/client/embed"

	"meshmcp/policy"
	"meshmcp/registry"
	"meshmcp/session"
)

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	cfgPath := fs.String("config", "meshmcp.yaml", "path to the meshmcp config file")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		return err
	}

	tracer, err := buildTracer(cfg.Trace)
	if err != nil {
		return err
	}
	if tracer != nil {
		log.Printf("tracing all MCP messages to %s (payloads=%v)", cfg.Trace.Log, cfg.Trace.Payloads)
	}

	client, err := startMesh(cfg.Mesh.options(), os.Stderr)
	if err != nil {
		return err
	}
	defer stopMesh(client)

	meshIP := ""
	if st, err := client.Status(); err == nil {
		log.Printf("mesh peer up: %s (%s)", st.LocalPeerState.IP, st.LocalPeerState.FQDN)
		meshIP = strings.SplitN(st.LocalPeerState.IP, "/", 2)[0]
	}

	// Optionally advertise backends in the discovery registry so a router can
	// find them dynamically.
	if cfg.Registry != "" && meshIP != "" {
		if reg, err := registry.NewFileRegistry(cfg.Registry); err != nil {
			log.Printf("registry %s unusable: %v", cfg.Registry, err)
		} else {
			for _, b := range cfg.Backends {
				addr := fmt.Sprintf("%s:%d", meshIP, b.Port)
				_ = reg.Register(b.Name, addr)
			}
			log.Printf("registered %d backend(s) in %s", len(cfg.Backends), cfg.Registry)
			defer func() {
				for _, b := range cfg.Backends {
					_ = reg.Deregister(b.Name, fmt.Sprintf("%s:%d", meshIP, b.Port))
				}
			}()
		}
	}

	shutdown := make(chan struct{})
	var wg sync.WaitGroup
	var listeners []net.Listener
	for _, b := range cfg.Backends {
		ln, err := client.ListenTCP(fmt.Sprintf(":%d", b.Port))
		if err != nil {
			close(shutdown)
			for _, l := range listeners {
				l.Close()
			}
			wg.Wait()
			return fmt.Errorf("backend %q: listen on mesh port %d: %w", b.Name, b.Port, err)
		}
		listeners = append(listeners, ln)
		allow := "any mesh peer"
		if len(b.Allow) > 0 {
			allow = fmt.Sprintf("%v", b.Allow)
		}
		policyNote := ""
		if b.Policy != nil {
			policyNote = fmt.Sprintf(", policy: %d rules, default %s", len(b.Policy.Rules), allowWord(b.Policy.DefaultAllow))
		}
		log.Printf("backend %q: %s on mesh port %d (allow: %s%s)", b.Name, b.kind(), b.Port, allow, policyNote)

		// The backend factory (subprocess + policy/trace filter) applies only
		// to stdio backends; HTTP backends are reverse-proxied and never use it.
		var factory session.BackendFactory
		if b.HTTP == "" {
			audit, err := auditSink(b)
			if err != nil {
				close(shutdown)
				for _, l := range listeners {
					l.Close()
				}
				wg.Wait()
				return err
			}
			factory = backendFactory(b, audit, tracer)
		}

		wg.Add(1)
		go func(b *Backend, ln net.Listener, factory session.BackendFactory) {
			defer wg.Done()
			switch {
			case b.HTTP != "":
				serveHTTP(client, b, ln)
			case b.Resumable:
				serveResumable(client, b, ln, shutdown, factory)
			default:
				serveStdio(client, b, ln, shutdown, factory)
			}
		}(b, ln, factory)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	<-sig

	log.Println("shutting down")
	close(shutdown)
	for _, ln := range listeners {
		ln.Close()
	}
	wg.Wait()
	return nil
}

// serveStdio accepts mesh connections and, per connection, spawns a
// backend (optionally wrapped by the policy filter) and bridges bytes
// both ways.
func serveStdio(client *embed.Client, b *Backend, ln net.Listener, shutdown <-chan struct{}, factory session.BackendFactory) {
	checker := newACL(b.Allow)
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-shutdown:
			default:
				log.Printf("backend %q: accept: %v", b.Name, err)
			}
			return
		}

		pubKey, fqdn := peerIdentity(client, conn.RemoteAddr())
		if !checker.allows(pubKey, fqdn) {
			log.Printf("backend %q: DENIED peer %s (%s, key %s)", b.Name, fqdn, conn.RemoteAddr(), pubKey)
			conn.Close()
			continue
		}
		log.Printf("backend %q: session opened by %s (%s)", b.Name, fqdn, conn.RemoteAddr())

		go func(conn net.Conn, fqdn, pubKey string) {
			defer conn.Close()
			backend, err := factory(session.Meta{PeerFQDN: fqdn, PeerAddr: conn.RemoteAddr().String(), PeerKey: pubKey})
			if err != nil {
				log.Printf("backend %q: start: %v", b.Name, err)
				return
			}
			bridgeConn(conn, backend)
			log.Printf("backend %q: session closed by %s", b.Name, fqdn)
		}(conn, fqdn, pubKey)
	}
}

// serveResumable exposes a stdio backend as a resumable session: the
// backend subprocess is kept alive across client reconnects and missed
// messages are replayed, so the logical MCP session survives the mesh
// connection dropping (peer roaming, sleep/wake, relay switch).
func serveResumable(client *embed.Client, b *Backend, ln net.Listener, shutdown <-chan struct{}, factory session.BackendFactory) {
	checker := newACL(b.Allow)
	ttl := time.Duration(b.SessionTTLSeconds) * time.Second
	srv := session.NewServer(factory, ttl, func(format string, a ...any) {
		log.Printf("backend %q: "+format, append([]any{b.Name}, a...)...)
	})
	if b.SessionStore != "" {
		store, err := session.NewFileStore(b.SessionStore)
		if err != nil {
			log.Printf("backend %q: session_store %s unusable: %v (migration disabled)", b.Name, b.SessionStore, err)
		} else {
			mode := session.MigrateHandshake
			switch b.SessionStoreMode {
			case "full":
				mode = session.MigrateFull
			case "backend":
				mode = session.MigrateBackend
			}
			srv = srv.WithStore(store, mode)
			modeName := b.SessionStoreMode
			if modeName == "" {
				modeName = "handshake"
			}
			log.Printf("backend %q: session migration enabled via %s (mode=%s)", b.Name, b.SessionStore, modeName)
		}
	}

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-shutdown:
			default:
				log.Printf("backend %q: accept: %v", b.Name, err)
			}
			return
		}

		pubKey, fqdn := peerIdentity(client, conn.RemoteAddr())
		if !checker.allows(pubKey, fqdn) {
			log.Printf("backend %q: DENIED peer %s (%s, key %s)", b.Name, fqdn, conn.RemoteAddr(), pubKey)
			conn.Close()
			continue
		}
		go srv.Handle(conn, session.Meta{
			PeerFQDN: fqdn,
			PeerAddr: conn.RemoteAddr().String(),
			PeerKey:  pubKey,
		})
	}
}

// bridgeConn pipes a mesh connection to a backend both ways until either
// side ends.
func bridgeConn(conn net.Conn, backend session.Backend) {
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(backend, conn); backend.Close(); done <- struct{}{} }()
	go func() { _, _ = io.Copy(conn, backend); conn.Close(); done <- struct{}{} }()
	<-done
	<-done
}

// backendFactory builds the per-session backend for a stdio backend. It
// wraps the subprocess with the inspection filter when a policy is set OR a
// tracer is configured; with neither, the raw subprocess is used.
func backendFactory(b *Backend, audit *policy.AuditLog, tracer *policy.Tracer) session.BackendFactory {
	exec := session.ExecBackendFactory(b.Stdio[0], b.Stdio[1:], os.Environ())
	if b.Policy == nil && tracer == nil {
		return exec
	}
	return func(meta session.Meta) (session.Backend, error) {
		inner, err := exec(meta)
		if err != nil {
			return nil, err
		}
		return policy.NewFilter(inner, policy.Caller{
			Backend:  b.Name,
			Peer:     meta.PeerFQDN,
			PeerKey:  meta.PeerKey,
			PeerAddr: meta.PeerAddr,
		}, b.Policy, audit, tracer), nil
	}
}

// buildTracer opens the gateway-wide trace sink, or returns nil if tracing
// is not configured. A configured but unopenable file is a hard error.
func buildTracer(cfg *TraceConfig) (*policy.Tracer, error) {
	if cfg == nil || cfg.Log == "" {
		return nil, nil
	}
	f, err := os.OpenFile(cfg.Log, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, fmt.Errorf("open trace log %s: %w", cfg.Log, err)
	}
	return policy.NewTracer(f, func() string {
		return time.Now().UTC().Format("2006-01-02T15:04:05.000Z07:00")
	}, policy.TraceOptions{Payloads: cfg.Payloads, MaxBytes: cfg.MaxBytes}), nil
}

// auditSink opens the audit destination for a policy-enabled backend.
// A configured file that cannot be opened is a hard error: an audit sink
// is a security control, not best-effort.
func auditSink(b *Backend) (*policy.AuditLog, error) {
	if b.Policy == nil {
		return nil, nil
	}
	var w io.Writer = os.Stderr
	if b.AuditLog != "" {
		f, err := os.OpenFile(b.AuditLog, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			return nil, fmt.Errorf("backend %q: open audit log %s: %w", b.Name, b.AuditLog, err)
		}
		w = f
	}
	return policy.NewAuditLog(w, func() string { return time.Now().UTC().Format(time.RFC3339) }), nil
}

func allowWord(allow bool) string {
	if allow {
		return "allow"
	}
	return "deny"
}

// serveHTTP reverse-proxies mesh connections to a local HTTP MCP server,
// enforcing the ACL and stamping the caller's mesh identity onto each
// request so the backend can do per-agent authorization and audit.
func serveHTTP(client *embed.Client, b *Backend, ln net.Listener) {
	checker := newACL(b.Allow)
	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(b.httpURL)
			pr.SetXForwarded()
		},
		// MCP Streamable HTTP uses SSE; flush every write immediately.
		FlushInterval: -1,
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pubKey, fqdn := peerIdentityStr(client, r.RemoteAddr)
		if !checker.allows(pubKey, fqdn) {
			log.Printf("backend %q: DENIED peer %s (%s)", b.Name, fqdn, r.RemoteAddr)
			http.Error(w, "forbidden: mesh peer not in backend ACL", http.StatusForbidden)
			return
		}
		// Identity headers are set by the gateway, never trusted from input.
		r.Header.Del("X-Meshmcp-Peer")
		r.Header.Del("X-Meshmcp-Peer-Key")
		r.Header.Set("X-Meshmcp-Peer", fqdn)
		r.Header.Set("X-Meshmcp-Peer-Key", pubKey)
		proxy.ServeHTTP(w, r)
	})

	srv := &http.Server{Handler: handler}
	if err := srv.Serve(ln); err != nil &&
		!errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
		log.Printf("backend %q: serve: %v", b.Name, err)
	}
}
