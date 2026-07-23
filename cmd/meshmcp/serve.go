package main

import (
	"bytes"
	"encoding/json"
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

	"github.com/xrey167/meshmcp/air"
	"github.com/xrey167/meshmcp/pgstore"
	"github.com/xrey167/meshmcp/policy"
	"github.com/xrey167/meshmcp/registry"
	"github.com/xrey167/meshmcp/secrets"
	"github.com/xrey167/meshmcp/session"
)

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	cfgPath := fs.String("config", defaultConfigPath(), "path to the meshmcp config file")
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

	meshIP, meshFQDN, meshPubKey := "", "", ""
	if st, err := client.Status(); err == nil {
		log.Printf("mesh peer up: %s (%s)", st.LocalPeerState.IP, st.LocalPeerState.FQDN)
		meshIP = strings.SplitN(st.LocalPeerState.IP, "/", 2)[0]
		meshFQDN = st.LocalPeerState.FQDN
		meshPubKey = st.LocalPeerState.PubKey
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
	var auditLogs []*policy.AuditLog

	// Live resumable session servers by backend name — the Air control endpoint
	// (Sessions/Steer) reads this. Registered as each resumable backend starts.
	servers := map[string]*session.Server{}
	var serversMu sync.Mutex

	// A gateway-wide shared audit ledger (one hash chain across all backends),
	// so a unified live view reads a single, verifiable stream.
	var sharedAudit *policy.AuditLog
	if cfg.AuditLog != "" {
		seq, lastHash, serr := seedAuditFromExisting(cfg.AuditLog)
		if serr != nil {
			return fmt.Errorf("shared audit log: %w", serr)
		}
		f, err := os.OpenFile(cfg.AuditLog, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			return fmt.Errorf("open shared audit log %s: %w", cfg.AuditLog, err)
		}
		sharedAudit = policy.NewAuditLog(f, func() string { return time.Now().UTC().Format(time.RFC3339) }).
			WithFailClosed(cfg.AuditFailClosed).
			WithSync(auditFsyncEnabled(cfg.AuditFsync))
		if seq > 0 {
			sharedAudit.SeedFrom(seq, lastHash) // continue the chain across restart
			log.Printf("shared audit ledger: resumed from seq %d", seq)
		}
		if cfg.AuditWebhook != "" {
			sharedAudit.AddSink(newWebhookSink(cfg.AuditWebhook, !cfg.AuditWebhookAll))
			log.Printf("audit webhook sink: %s (deny/cosign only=%v)", cfg.AuditWebhook, !cfg.AuditWebhookAll)
		}
		if cfg.MetricsListen != "" {
			sink := newMetricsSink()
			ln, err := net.Listen("tcp", cfg.MetricsListen)
			if err != nil {
				return fmt.Errorf("metrics_listen %s: %w", cfg.MetricsListen, err)
			}
			sharedAudit.AddSink(sink)
			mux := http.NewServeMux()
			mux.Handle("/metrics", sink)
			go func() { _ = http.Serve(ln, mux) }()
			log.Printf("metrics: serving /metrics on %s", cfg.MetricsListen)
		}
		auditLogs = append(auditLogs, sharedAudit)
		log.Printf("shared audit ledger: %s", cfg.AuditLog)
	} else if cfg.MetricsListen != "" {
		// The metrics sink observes the shared ledger; without one it would
		// silently serve empty metrics — refuse instead.
		return fmt.Errorf("metrics_listen requires audit_log (the metrics sink observes the shared ledger)")
	}

	// Optional gateway event hooks: publish every policy decision onto the
	// event bus and/or a webhook. Kept as a nil interface when disabled so the
	// filter never invokes it.
	var hookSink policy.EventHook
	var gatewayHookSink *gatewayHooks
	if cfg.Hooks != nil {
		gh, err := newGatewayHooks(cfg.Hooks, client, sharedAudit)
		if err != nil {
			return fmt.Errorf("hooks: %w", err)
		}
		gatewayHookSink = gh
		defer gh.Close() // safety net; also closed explicitly before the audit flush
		hookSink = gh
		note := []string{}
		if cfg.Hooks.Bus != nil {
			note = append(note, fmt.Sprintf("bus on port %d", cfg.Hooks.Bus.ListenPort))
		}
		if cfg.Hooks.Webhook != nil && cfg.Hooks.Webhook.URL != "" {
			note = append(note, "webhook")
		}
		log.Printf("gateway hooks enabled (%s)", strings.Join(note, ", "))
	}

	// engines holds each policy-bearing backend's running Engine, keyed by name,
	// so a SIGHUP can hot-swap its policy rules in place without a restart.
	engines := map[string]*policy.Engine{}
	// byName retains each backend for the reload path; installing allowACL here
	// (before any accept loop starts) makes every peer-admission check
	// hot-swappable — the accept loops capture copies that share the pattern
	// pointer.
	byName := map[string]*Backend{}
	for _, b := range cfg.Backends {
		b.allowACL = newACL(b.Allow)
		byName[b.Name] = b
	}

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

		// Resolve the audit sink for any policy-bearing backend (stdio OR http):
		// prefer the gateway-wide shared ledger, else a per-backend sink.
		var audit *policy.AuditLog
		if b.Policy != nil || b.HTTP == "" {
			audit = sharedAudit
			if audit == nil || b.Policy == nil {
				var err error
				audit, err = auditSink(b)
				if err != nil {
					close(shutdown)
					for _, l := range listeners {
						l.Close()
					}
					wg.Wait()
					return err
				}
				if audit != nil {
					auditLogs = append(auditLogs, audit)
				}
			}
		}

		// stdio backends run through the byte-stream Filter; HTTP and remote
		// backends with a policy run through the request-level httpEnforcer (F16).
		var factory session.BackendFactory
		var httpEnf *httpEnforcer
		if len(b.Stdio) > 0 {
			var eng *policy.Engine
			factory, eng = backendFactory(b, audit, tracer, hookSink, meshPubKey)
			if eng != nil {
				engines[b.Name] = eng
			}
		} else if b.Policy != nil {
			httpEnf = newHTTPEnforcer(b, audit)
			engines[b.Name] = httpEnf.eng
			log.Printf("backend %q: HTTP policy enforcement on (%d rules)", b.Name, len(b.Policy.Rules))
		}

		// A remote backend's OAuth/DPoP client is built once at startup; a
		// missing or unloadable DPoP key file is fatal (S13 precedent), never
		// silently regenerated.
		var rc *remoteClient
		if b.Remote != nil {
			var rcErr error
			rc, rcErr = buildRemoteClient(b)
			if rcErr != nil {
				close(shutdown)
				for _, l := range listeners {
					l.Close()
				}
				wg.Wait()
				return rcErr
			}
		}

		wg.Add(1)
		go func(b *Backend, ln net.Listener, factory session.BackendFactory, httpEnf *httpEnforcer, rc *remoteClient) {
			defer wg.Done()
			switch {
			case b.Remote != nil:
				serveRemote(client, b, ln, httpEnf, rc)
			case b.HTTP != "":
				serveHTTP(client, b, ln, httpEnf)
			case b.Resumable:
				serveResumable(client, b, ln, shutdown, factory, func(srv *session.Server) {
					serversMu.Lock()
					servers[b.Name] = srv
					serversMu.Unlock()
				})
			default:
				serveStdio(client, b, ln, shutdown, factory)
			}
		}(b, ln, factory, httpEnf, rc)
	}

	// Control-surface ACL handles, retained (when the endpoint is enabled) so a
	// SIGHUP reload can hot-swap the operator/on-behalf allow lists in place.
	var controlAllow, controlOnBehalf acl

	// Optionally serve the Air control endpoint: list and steer live sessions
	// across all resumable backends, gated by identity and audited.
	if cfg.Control != nil && cfg.Control.Port > 0 {
		ln, err := client.ListenTCP(fmt.Sprintf(":%d", cfg.Control.Port))
		if err != nil {
			close(shutdown)
			for _, l := range listeners {
				l.Close()
			}
			wg.Wait()
			return fmt.Errorf("control: listen on mesh port %d: %w", cfg.Control.Port, err)
		}
		listeners = append(listeners, ln)
		// A non-empty control.allow is guaranteed by loadConfig (default-deny);
		// each backend's own allow list adds depth, so the control endpoint
		// re-checks the target backend's ACL (not just the global Control.Allow).
		backendACLs := map[string]acl{}
		for _, b := range cfg.Backends {
			backendACLs[b.Name] = b.peerACL()
		}
		cards, err := buildCatalogBackends(cfg.Backends, meshIP, air.IdentityRef{
			PubKey: meshPubKey,
			FQDN:   meshFQDN,
		})
		if err != nil {
			close(shutdown)
			for _, l := range listeners {
				l.Close()
			}
			wg.Wait()
			return fmt.Errorf("control: build component catalog: %w", err)
		}
		ctl := &gatewayAirControl{
			servers: servers, acls: backendACLs, mu: &serversMu,
			backends: cards,
			gateway:  meshFQDN,
			presence: air.NewRegistry(air.DefaultPresenceRegistryMax),
		}
		identify := func(r *http.Request) (string, string) { return peerIdentityStr(client, r.RemoteAddr) }
		// Configured operators are recognized on the control/steer AND pairing
		// approver surface (both gate on this same acl), so a second operator can
		// approve and pair without being hand-added to control.allow.
		allow := newACL(append(append([]string(nil), cfg.Control.Allow...), operatorPatterns(cfg.Operators)...))
		controlAllow = allow // retained so a SIGHUP reload can hot-swap it
		// Dedicated proxy allow list for X-Air-On-Behalf attestation; empty ⇒
		// no peer may attest (attribution stays the verified connecting peer).
		onBehalfAllow := newACL(cfg.Control.OnBehalfAllow)
		controlOnBehalf = onBehalfAllow
		h := airControlHandler(ctl, identify, allow, onBehalfAllow, airAuditFunc(sharedAudit))
		// Optional pairing surface, mounted on the SAME control listener. Peers
		// request access with `air join` and an operator approves with `air pair`,
		// so recognizing a new peer never means hand-editing this file's allow
		// list. It shares the control endpoint's identity resolution and audit
		// chain. The approve/deny/revoke surface is gated on the SAME operator
		// Allow as list/steer (deny-by-default); the request surface is
		// deliberately open so an un-allowed peer can ask — but a request grants
		// nothing, and approval confers recognition only, never a tool/control ACL.
		if cfg.Control.PairStore != "" {
			pairStore, perr := air.OpenPairedStore(cfg.Control.PairStore)
			if perr != nil {
				close(shutdown)
				for _, l := range listeners {
					l.Close()
				}
				wg.Wait()
				return fmt.Errorf("control: open paired store %s: %w", cfg.Control.PairStore, perr)
			}
			ph := pairControlHandler(pairStore, identify, allow, newRingLimiter(pairRatePerMin), pairAuditFunc(sharedAudit))
			// Longest-prefix routing: pairing paths go to ph, everything else to
			// the existing control handler.
			parent := http.NewServeMux()
			parent.Handle("/v1/pair/", ph)
			parent.Handle("/", h)
			h = parent
			log.Printf("Air pairing enabled (store %s): POST /v1/pair/request · GET /v1/pair/status · GET /v1/pair/pending · POST /v1/pair/approve|deny|revoke", cfg.Control.PairStore)
		}
		obNote := ""
		if len(cfg.Control.OnBehalfAllow) > 0 {
			obNote = fmt.Sprintf(" · on-behalf proxies: %v", cfg.Control.OnBehalfAllow)
		}
		log.Printf("Air control endpoint on mesh port %d (GET/POST/DELETE /v1/presence · GET /v1/sessions · POST /v1/steer · GET %s)%s", cfg.Control.Port, airCatalogPath, obNote)
		wg.Add(1)
		// Read/header timeouts: a mesh peer must not be able to hold the control
		// listener open with a slow/half-open request (Slowloris).
		go func() { defer wg.Done(); _ = newLocalHTTPServer("", h).Serve(ln) }()
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, shutdownSignals...)
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, reloadSignals...)
	log.Printf("send SIGHUP to hot-reload policy rules and peer/control ACLs without a restart")
	// Serve until a shutdown signal; a SIGHUP in between re-reads the config and
	// hot-swaps each backend's policy rules and admission ACLs in place.
waitForShutdown:
	for {
		select {
		case <-hup:
			reloadPolicies(*cfgPath, engines, byName, controlAllow, controlOnBehalf)
		case <-sig:
			break waitForShutdown
		}
	}

	log.Println("shutting down")
	close(shutdown)
	for _, ln := range listeners {
		ln.Close()
	}
	wg.Wait()
	// Close the hook bus before sealing the ledger: its broker writes subscribe
	// records into the shared audit, so it must stop before the final flush or a
	// last-moment bus session could land records after the sealed checkpoint.
	if gatewayHookSink != nil {
		gatewayHookSink.Close()
	}
	// Seal the final partial checkpoint batch so no audit records are left
	// uncommitted by a clean shutdown.
	for _, a := range auditLogs {
		a.Flush()
	}
	return nil
}

// serveStdio accepts mesh connections and, per connection, spawns a
// backend (optionally wrapped by the policy filter) and bridges bytes
// both ways.
func serveStdio(client *embed.Client, b *Backend, ln net.Listener, shutdown <-chan struct{}, factory session.BackendFactory) {
	checker := b.peerACL()
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
// serveResumable runs the resumable accept loop until the listener closes. If
// register is non-nil it is called with the *session.Server before the loop
// starts, so the caller can wire it into the Air control endpoint (Sessions/Steer).
func serveResumable(client *embed.Client, b *Backend, ln net.Listener, shutdown <-chan struct{}, factory session.BackendFactory, register func(*session.Server)) {
	checker := b.peerACL()
	ttl := time.Duration(b.SessionTTLSeconds) * time.Second
	srv := session.NewServer(factory, ttl, func(format string, a ...any) {
		log.Printf("backend %q: "+format, append([]any{b.Name}, a...)...)
	})
	if b.SessionStore != "" {
		var store session.SessionStore
		var err error
		display := b.SessionStore
		if isPostgresDSN(b.SessionStore) {
			display = redactDSN(b.SessionStore)
			store, err = pgstore.Open(b.SessionStore)
		} else {
			store, err = session.NewFileStore(b.SessionStore)
		}
		if err != nil {
			log.Printf("backend %q: session_store %s unusable: %v (migration disabled)", b.Name, display, err)
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
			log.Printf("backend %q: session migration enabled via %s (mode=%s)", b.Name, display, modeName)
		}
	}
	if register != nil {
		register(srv)
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

// reloadPolicies re-reads the config at cfgPath and hot-swaps, matched by
// backend name (SIGHUP): each backend's policy RULES into its running Engine,
// each backend's peer-admission ACL (b.Allow), and the control endpoint's
// operator + on-behalf allow lists. It is fail-safe: a config that no longer
// loads (a bad edit) leaves every running policy and ACL untouched, so a typo
// can never disarm the gateway. Listeners, capability trust roots, and other
// startup wiring stay startup-captured (that is a wider re-plumb). A
// require_cosign approval bound to the old PolicyHash stops verifying after a
// reload changes the rules, by design.
func reloadPolicies(cfgPath string, engines map[string]*policy.Engine, backends map[string]*Backend, controlAllow, controlOnBehalf acl) {
	newCfg, err := loadConfig(cfgPath)
	if err != nil {
		log.Printf("reload: config %s did not load — keeping the running policy and ACLs: %v", cfgPath, err)
		return
	}
	applied, present := 0, map[string]bool{}
	for _, b := range newCfg.Backends {
		present[b.Name] = true
		// Peer-admission ACL: every accept loop holds a copy sharing this handle.
		if running, ok := backends[b.Name]; ok && running.allowACL.p != nil {
			running.allowACL.swap(b.Allow)
		}
		eng, ok := engines[b.Name]
		if !ok {
			continue // backend has no running policy engine (or is newly added — needs a restart to listen)
		}
		pol := b.Policy
		if pol == nil {
			// A capabilities-only backend keeps its synthesized deny-by-default.
			pol = &policy.Policy{DefaultAllow: false}
		}
		eng.SetPolicy(pol)
		applied++
		log.Printf("reload: backend %q policy updated (%d rules, default %s)", b.Name, len(pol.Rules), allowWord(pol.DefaultAllow))
	}
	// Control-surface ACLs. loadConfig guarantees an enabled control endpoint
	// never loads with an empty allow surface, so a swap cannot open it wide.
	if newCfg.Control != nil {
		controlAllow.swap(append(append([]string(nil), newCfg.Control.Allow...), operatorPatterns(newCfg.Operators)...))
		controlOnBehalf.swap(newCfg.Control.OnBehalfAllow)
	}
	for name := range engines {
		if !present[name] {
			log.Printf("reload: backend %q is gone from the config — its running policy is unchanged (remove needs a restart)", name)
		}
	}
	log.Printf("reload: applied %d backend policy update(s) + admission ACLs from %s", applied, cfgPath)
}

// backendFactory builds the per-session backend for a stdio backend. It
// wraps the subprocess with the inspection filter when a policy is set OR a
// tracer is configured; with neither, the raw subprocess is used.
// It also returns the per-backend policy Engine (nil when the backend has no
// policy/capabilities) so the caller can hot-swap its policy on SIGHUP.
// meshPubKey is this gateway's own mesh identity — the AUDIENCE a presented
// router-delegation token must name (empty is fatal when router_delegation is
// configured: every verify would fail closed at the first call, so fail at
// startup with a clear error instead).
func backendFactory(b *Backend, audit *policy.AuditLog, tracer *policy.Tracer, hook policy.EventHook, meshPubKey string) (session.BackendFactory, *policy.Engine) {
	exec := session.ExecBackendFactory(b.Stdio[0], b.Stdio[1:], os.Environ())
	if b.Policy == nil && tracer == nil && b.Capabilities == nil {
		return exec, nil
	}
	// One Engine per backend, shared across all its connections, so rate
	// limits and co-sign approvals are per-identity rather than per-connection.
	// Capabilities need the engine path even without an explicit policy, so a
	// deny-by-default engine is synthesized when only capabilities are set.
	var eng *policy.Engine
	if b.Policy != nil {
		var cosign policy.CosignStore
		if b.CosignStore != "" {
			cosign = &policy.FileCosign{
				Dir: b.CosignStore,
				TTL: time.Duration(b.CosignTTLSeconds) * time.Second,
			}
		}
		eng = policy.NewEngine(b.Policy, func() time.Time { return time.Now() }, cosign)
	} else if b.Capabilities != nil {
		eng = policy.NewEngine(&policy.Policy{DefaultAllow: false}, func() time.Time { return time.Now() }, nil)
	}
	// Attach the group resolver (F17) so rules can match group:<name> peers.
	if eng != nil && len(b.groups) > 0 {
		eng.SetGroupResolver(policy.StaticGroups(b.groups))
	}
	// Capability verifier: pins the backend's trusted authority keys.
	var capVerifier *policy.CapabilityVerifier
	if b.Capabilities != nil {
		v, err := policy.NewCapabilityVerifier(b.Capabilities.TrustedPublicKeys, func() time.Time { return time.Now() })
		if err != nil {
			log.Fatalf("backend %q: capabilities: %v", b.Name, err)
		}
		if b.Capabilities.RevocationStore != "" {
			// Create the store at startup so IsRevoked can later fail closed on a
			// vanished/unavailable store; a store that cannot be created is a
			// security-config error and must fail startup.
			rev, err := policy.NewFileRevocation(b.Capabilities.RevocationStore)
			if err != nil {
				log.Fatalf("backend %q: capability revocation store %s: %v", b.Name, b.Capabilities.RevocationStore, err)
			}
			v = v.WithRevocation(rev.IsRevoked).WithSubjectRevocation(rev.IsSubjectRevoked)
			log.Printf("backend %q: capability revocation store: %s", b.Name, b.Capabilities.RevocationStore)
		}
		capVerifier = v
	}
	// Router-delegation verifier: pins the router-authority keys, binds this
	// gateway's own mesh identity as the audience, and shares ONE in-memory
	// nonce store across the backend's connections (never nil — a nil store
	// would skip replay protection). Per-process only: a multi-gateway HA
	// deployment gets per-gateway replay windows (a shared/pg store is a
	// follow-up, matching the SessionStore precedent).
	var delegVerifier *policy.DelegationVerifier
	if b.RouterDelegation != nil {
		if meshPubKey == "" {
			log.Fatalf("backend %q: router_delegation is configured but the gateway's mesh public key is unavailable — no audience to verify tokens against (fail closed at startup, not at first call)", b.Name)
		}
		v, err := policy.NewDelegationVerifier(b.RouterDelegation.TrustedPublicKeys, meshPubKey, policy.NewMemNonceStore(), nil)
		if err != nil {
			log.Fatalf("backend %q: router_delegation: %v", b.Name, err)
		}
		delegVerifier = v
		log.Printf("backend %q: router-delegation enforcement on (required=%v, %d pinned authority key(s); replay window per-gateway-process)",
			b.Name, b.RouterDelegation.Required, len(b.RouterDelegation.TrustedPublicKeys))
	}
	// Held-request registry lives in the cosign directory, so an approver
	// (a human identity / a phone on the mesh) sees pending calls next to the
	// grants they write.
	var pending *policy.FilePending
	if b.CosignStore != "" {
		pending = &policy.FilePending{Dir: b.CosignStore, TTL: time.Duration(b.CosignTTLSeconds) * time.Second}
	}
	// Request-bound approvals: when a shared approval signing key is configured,
	// a require_cosign call is released only by a signed, single-use token bound
	// to its exact arguments + policy — not an ambient (peer, tool) grant. Load
	// the key fail-closed (a configured-but-unreadable key is a security-config
	// error, never a silent downgrade to the weaker ambient path).
	if eng != nil && b.ApprovalSigningKey != "" {
		signer, err := policy.LoadSigner(b.ApprovalSigningKey)
		if err != nil {
			log.Fatalf("backend %q: approval_signing_key %s: %v", b.Name, b.ApprovalSigningKey, err)
		}
		eng.SetRequestApprovals(policy.NewFileApprovalStore(b.CosignStore, time.Duration(b.CosignTTLSeconds)*time.Second, signer))
		log.Printf("backend %q: request-bound approvals enabled (approver key %s…); ambient co-sign no longer releases held calls", b.Name, signer.PubKeyHex()[:16])
	}
	// One credential broker per backend, sharing the backend's (hash-chained)
	// audit so secret use lands in the same tamper-evident record.
	var broker *secrets.Broker
	if b.Secrets != nil {
		store, err := secretStore(b.Secrets)
		if err != nil {
			log.Fatalf("backend %q: secrets store: %v", b.Name, err)
		}
		broker = secrets.New(store, b.Secrets.Grants, audit)
	}
	// One DLP hook per backend, shared across connections (compiled regexes are
	// stateless). Validated already in loadConfig, so NewPatternDLP won't error.
	var dlpHook *policy.PatternDLPHook
	if len(b.DLP) > 0 {
		h, err := policy.NewPatternDLP(b.DLP)
		if err != nil {
			log.Fatalf("backend %q: dlp: %v", b.Name, err)
		}
		dlpHook = h
	}
	// One shadow-policy hook per backend: it observes and logs where a candidate
	// policy would disagree with the enforced one, without changing enforcement.
	var shadowHook *policy.ShadowHook
	if b.ShadowPolicy != nil {
		name := b.Name
		shadowHook = policy.NewShadowHook(b.ShadowPolicy, func(d policy.ShadowDivergence) {
			log.Printf("backend %q: SHADOW divergence: peer=%s tool=%s live=%s shadow=%s",
				name, d.Peer, d.Tool, d.Live, d.Shadow)
		})
		log.Printf("backend %q: shadow policy active (%d rules) — divergences logged, enforcement unchanged", b.Name, len(b.ShadowPolicy.Rules))
	}
	return func(meta session.Meta) (session.Backend, error) {
		inner, err := exec(meta)
		if err != nil {
			return nil, err
		}
		f := policy.NewFilterEngine(inner, policy.Caller{
			Backend:  b.Name,
			Peer:     meta.PeerFQDN,
			PeerKey:  meta.PeerKey,
			PeerAddr: meta.PeerAddr,
			// Additive SPIFFE label (Feature A): derived here at the edge from
			// the gateway's LOCAL trust domain — never a federation org's.
			// Empty trust_domain (or a malformed key) yields "" and the audit
			// field is elided, leaving records byte-identical to before.
			SpiffeID: policy.SpiffeID(b.trustDomain, meta.PeerKey),
		}, eng, audit, tracer)
		if broker != nil {
			f.SetSecretResolver(broker)
		}
		if pending != nil {
			f.SetPendingStore(pending)
		}
		if capVerifier != nil {
			f.SetCapabilityVerifier(capVerifier, b.Capabilities.Required)
		}
		if delegVerifier != nil {
			f.SetDelegationVerifier(delegVerifier, b.RouterDelegation.Required)
		}
		if dlpHook != nil {
			f.AddDecisionHook(dlpHook)
		}
		if shadowHook != nil {
			f.AddDecisionHook(shadowHook)
		}
		if hook != nil {
			f.SetEventHook(hook)
		}
		return f, nil
	}, eng
}

// secretStore builds the Store for a backend's secrets config: a file layered
// under environment variables when both are set.
func secretStore(cfg *SecretsConfig) (secrets.Store, error) {
	var chain secrets.Chain
	if cfg.File != "" {
		fs, err := secrets.NewFileStore(cfg.File)
		if err != nil {
			return nil, err
		}
		chain = append(chain, fs)
	}
	if cfg.EnvPrefix != "" {
		chain = append(chain, secrets.EnvStore{Prefix: cfg.EnvPrefix})
	}
	return chain, nil
}

// buildTracer opens the gateway-wide trace sink, or returns nil if tracing
// is not configured. A configured but unopenable file is a hard error.
func buildTracer(cfg *TraceConfig) (*policy.Tracer, error) {
	if cfg == nil || cfg.Log == "" {
		return nil, nil
	}
	// 0600: a trace with payloads carries full request/response bodies.
	f, err := os.OpenFile(cfg.Log, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
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
// seedAuditFromExisting verifies an existing audit log and returns its tail
// (last sequence + hash) so a restarting gateway continues the SAME chain
// instead of resetting to seq 1 with a fresh genesis. It refuses to append to a
// malformed or tampered log (fail closed): silently starting a second chain in
// the same file would produce a duplicate seq 1 and make the log unverifiable.
// An absent or empty file returns (0, "", nil).
func seedAuditFromExisting(path string) (seq int, lastHash string, err error) {
	if path == "" {
		return 0, "", nil
	}
	data, rerr := os.ReadFile(path)
	if os.IsNotExist(rerr) {
		return 0, "", nil
	}
	if rerr != nil {
		return 0, "", rerr
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return 0, "", nil
	}
	res, truncateTo, torn := policy.VerifyForRepair(data)
	if res.OK {
		return res.Count, res.LastHash, nil
	}
	if torn {
		// A crash/power-loss left an incomplete trailing record. Everything
		// before it verified, so recover by truncating the torn line — never a
		// complete record — and continue the same chain. A mid-chain tamper is
		// NOT torn and falls through to the hard refusal below.
		if err := os.Truncate(path, truncateTo); err != nil {
			return 0, "", fmt.Errorf("audit log %s: repairing torn tail: %w", path, err)
		}
		log.Printf("audit log %s: recovered an incomplete trailing record (%s); truncated to %d bytes, resuming from seq %d",
			path, res.Reason, truncateTo, res.Count)
		return res.Count, res.LastHash, nil
	}
	return 0, "", fmt.Errorf("existing audit log %s is unverifiable (break at seq %d: %s); refusing to append and reset the chain", path, res.BreakSeq, res.Reason)
}

// seedCheckpointFromExisting returns the last checkpoint's ordinal and hash from
// an existing checkpoints file, so a restart continues one verifiable chain of
// checkpoints. An absent/empty file returns (0, "", nil).
func seedCheckpointFromExisting(path string) (cpSeq int, prevCPHash string, err error) {
	if path == "" {
		return 0, "", nil
	}
	data, rerr := os.ReadFile(path)
	if os.IsNotExist(rerr) {
		return 0, "", nil
	}
	if rerr != nil {
		return 0, "", rerr
	}
	trimmed := bytes.TrimRight(data, "\n")
	if len(bytes.TrimSpace(trimmed)) == 0 {
		return 0, "", nil
	}
	lines := bytes.Split(trimmed, []byte("\n"))
	var cp policy.Checkpoint
	if uerr := json.Unmarshal(lines[len(lines)-1], &cp); uerr != nil {
		return 0, "", fmt.Errorf("existing checkpoints %s: last line is not a checkpoint: %w", path, uerr)
	}
	return cp.Seq, cp.Hash(), nil
}

// seedAnchorFromExisting returns the AnchorLineHash of an existing anchor
// file's last line (the seed for continuing the self-linked witness chain
// across restarts, mirroring seedCheckpointFromExisting). Absent/empty file ⇒
// "". An unreadable record is fatal: appending past it would hide whatever the
// bad line replaced.
func seedAnchorFromExisting(path string) (prevHash string, err error) {
	if path == "" {
		return "", nil
	}
	f, oerr := os.Open(path)
	if os.IsNotExist(oerr) {
		return "", nil
	}
	if oerr != nil {
		return "", oerr
	}
	defer f.Close()
	_, lastHash, rerr := policy.ReadAnchorRecords(f)
	if rerr != nil {
		return "", fmt.Errorf("anchor file %s: %w", path, rerr)
	}
	return lastHash, nil
}

// multiAnchor fans one checkpoint out to several witnesses; every witness
// fires and all failures are reported together (anchoring is evidence, so a
// partial failure must still surface).
type multiAnchor []policy.Anchor

func (m multiAnchor) Anchor(c policy.Checkpoint) error {
	var errs []error
	for _, a := range m {
		if err := a.Anchor(c); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func auditSink(b *Backend) (*policy.AuditLog, error) {
	if b.Policy == nil {
		return nil, nil
	}
	var w io.Writer = os.Stderr
	var seedSeq int
	var seedHash string
	if b.AuditLog != "" {
		var serr error
		seedSeq, seedHash, serr = seedAuditFromExisting(b.AuditLog)
		if serr != nil {
			return nil, fmt.Errorf("backend %q audit log: %w", b.Name, serr)
		}
		f, err := os.OpenFile(b.AuditLog, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			return nil, fmt.Errorf("backend %q: open audit log %s: %w", b.Name, b.AuditLog, err)
		}
		w = f
	}
	now := func() string { return time.Now().UTC().Format(time.RFC3339) }
	// Sync only a real file sink — fsyncing the stderr fallback (a terminal or
	// pipe) can error and would wrongly deny calls under fail-closed.
	audit := policy.NewAuditLog(w, now).
		WithFailClosed(b.AuditFailClosed).
		WithSync(b.AuditLog != "" && auditFsyncEnabled(b.AuditFsync))
	if seedSeq > 0 {
		audit.SeedFrom(seedSeq, seedHash) // continue the chain across restart
		log.Printf("backend %q: audit resumed from seq %d", b.Name, seedSeq)
	}

	if b.AuditCheckpoints != "" {
		cp, err := checkpointer(b, now)
		if err != nil {
			return nil, err
		}
		audit.WithCheckpointer(cp)
	}
	return audit, nil
}

// checkpointer builds a signed-checkpoint sink for a backend, loading or
// generating the gateway signing key.
func checkpointer(b *Backend, now func() string) (*policy.Checkpointer, error) {
	if b.AuditSigningKey == "" {
		return nil, fmt.Errorf("backend %q: audit_checkpoints requires audit_signing_key", b.Name)
	}
	var signer *policy.Signer
	if _, statErr := os.Stat(b.AuditSigningKey); statErr == nil {
		var err error
		signer, err = policy.LoadSigner(b.AuditSigningKey)
		if err != nil {
			return nil, fmt.Errorf("backend %q: load signing key: %w", b.Name, err)
		}
	} else if os.IsNotExist(statErr) {
		// A missing signing key is fatal unless the operator explicitly opted
		// into autogen: silently minting a new key would let anyone who can
		// delete the file force a fresh signing identity that an unpinned
		// verifier would then trust.
		if !b.AuditSigningKeyAutogen {
			return nil, fmt.Errorf("backend %q: audit signing key %s does not exist — run 'meshmcp audit keygen --out %s' (or set audit_signing_key_autogen: true to create it on start)", b.Name, b.AuditSigningKey, b.AuditSigningKey)
		}
		var err error
		signer, err = policy.GenerateSigner()
		if err != nil {
			return nil, err
		}
		if err := signer.SaveSigner(b.AuditSigningKey); err != nil {
			return nil, fmt.Errorf("backend %q: save signing key: %w", b.Name, err)
		}
		log.Printf("backend %q: generated audit signing key %s (public %s)", b.Name, b.AuditSigningKey, signer.PubKeyHex())
	} else {
		return nil, fmt.Errorf("backend %q: stat signing key %s: %w", b.Name, b.AuditSigningKey, statErr)
	}

	cpSeq, prevCPHash, serr := seedCheckpointFromExisting(b.AuditCheckpoints)
	if serr != nil {
		return nil, fmt.Errorf("backend %q: %w", b.Name, serr)
	}
	f, err := os.OpenFile(b.AuditCheckpoints, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, fmt.Errorf("backend %q: open checkpoints %s: %w", b.Name, b.AuditCheckpoints, err)
	}
	name := b.Name
	var anchors []policy.Anchor
	if b.AuditAnchor != "" {
		prevAnchor, aerr := seedAnchorFromExisting(b.AuditAnchor)
		if aerr != nil {
			return nil, fmt.Errorf("backend %q: %w", b.Name, aerr)
		}
		af, err := os.OpenFile(b.AuditAnchor, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			return nil, fmt.Errorf("backend %q: open anchor %s: %w", b.Name, b.AuditAnchor, err)
		}
		anchors = append(anchors, policy.NewFileAnchor(af, prevAnchor))
	}
	if b.AuditAnchorURL != "" {
		// Peer delivery is asynchronous (a slow witness must never stall the
		// audit write path), so its post failures surface through the anchor's
		// own handler rather than the Checkpointer's returned error.
		anchors = append(anchors, policy.NewPeerAnchor(b.AuditAnchorURL).
			WithErrorHandler(func(err error) {
				log.Printf("backend %q: AUDIT CHECKPOINT ERROR: checkpoint anchor: %v", name, err)
			}))
	}
	var anchor policy.Anchor
	switch len(anchors) {
	case 0:
	case 1:
		anchor = anchors[0]
	default:
		anchor = multiAnchor(anchors)
	}
	cp := policy.NewCheckpointer(signer, f, b.AuditCheckpointEvery, now, anchor)
	if cpSeq > 0 {
		cp.SeedFrom(cpSeq, prevCPHash) // continue the checkpoint chain across restart
		log.Printf("backend %q: checkpoints resumed from checkpoint %d", b.Name, cpSeq)
	}
	return cp.
		WithErrorHandler(func(err error) {
			log.Printf("backend %q: AUDIT CHECKPOINT ERROR: %v", name, err)
		}), nil
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
func serveHTTP(client *embed.Client, b *Backend, ln net.Listener, enf *httpEnforcer) {
	checker := b.peerACL()
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
		// Per-tool policy for HTTP backends (F16): parse the JSON-RPC body,
		// authorize tools/call by identity, audit, and deny inline — the same
		// firewall the stdio path applies.
		if enf != nil {
			ok, status, denial := enf.decide(fqdn, pubKey, r)
			if !ok {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(status)
				_, _ = w.Write(denial)
				return
			}
		}
		// Identity headers are set by the gateway, never trusted from input.
		r.Header.Del("X-Meshmcp-Peer")
		r.Header.Del("X-Meshmcp-Peer-Key")
		r.Header.Set("X-Meshmcp-Peer", fqdn)
		r.Header.Set("X-Meshmcp-Peer-Key", pubKey)
		proxy.ServeHTTP(w, r)
	})

	// ReadHeaderTimeout bounds a slow/half-open header dribble (Slowloris)
	// without a Read/Write timeout that would sever legitimate long-lived SSE
	// streams or large uploads this reverse proxy must pass through.
	srv := &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second}
	if err := srv.Serve(ln); err != nil &&
		!errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
		log.Printf("backend %q: serve: %v", b.Name, err)
	}
}
