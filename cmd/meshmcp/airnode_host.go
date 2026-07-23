package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/netbirdio/netbird/client/embed"

	"github.com/xrey167/meshmcp/air"
	"github.com/xrey167/meshmcp/policy"
	"github.com/xrey167/meshmcp/session"
)

// mergeHostedService announces a hosted service on the node's card. The
// hosted service owns its kind's slot: a manually announced --service of the
// same kind would advertise a receiver this process does not run, so it is a
// conflict, not an override.
func mergeHostedService(ann air.Announcement, svc air.Service) (air.Announcement, error) {
	for _, existing := range ann.Services {
		if existing.Kind == svc.Kind {
			return air.Announcement{}, fmt.Errorf("--service %s conflicts with --%s-port; the hosted %s is announced automatically", svc.Kind, svc.Kind, svc.Kind)
		}
	}
	out := ann
	out.Services = append(append([]air.Service(nil), ann.Services...), svc)
	return out, nil
}

func mergeHostedInbox(ann air.Announcement, port int) (air.Announcement, error) {
	return mergeHostedService(ann, air.Service{
		Kind: air.ServiceInbox, Port: port,
		Capabilities: []string{air.InboxCompletionCapabilityV1},
	})
}

func mergeHostedRing(ann air.Announcement, port int) (air.Announcement, error) {
	return mergeHostedService(ann, air.Service{Kind: air.ServiceRing, Port: port})
}

// hostInboxService starts the drop/push inbox receiver on the node's own mesh
// identity: sender ACL, bounded transfers, and the drop.complete.v1 completion
// handshake resolved Send requires. The returned stop closes the listener.
func hostInboxService(client *embed.Client, port int, dir string, allow []string, auditPath string) (func(), error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create dir %s: %w", dir, err)
	}
	var audit *policy.AuditLog
	var auditClose func()
	if auditPath != "" {
		f, err := os.OpenFile(auditPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return nil, fmt.Errorf("open audit log %s: %w", auditPath, err)
		}
		auditClose = func() { f.Close() }
		audit = policy.NewAuditLog(f, func() string { return time.Now().UTC().Format(time.RFC3339) })
	}
	ln, err := client.ListenTCP(fmt.Sprintf(":%d", port))
	if err != nil {
		if auditClose != nil {
			auditClose()
		}
		return nil, fmt.Errorf("listen on mesh port %d: %w", port, err)
	}
	lim := (&DropConfig{}).limits()
	identity := func(addr net.Addr) (string, string) { return peerIdentity(client, addr) }
	factory := newDropFactory(dirPlacer(dir), lim, audit)
	go runAirAcceptLoop(ln, identity, newACL(allow), factory, "drop", log.Printf)
	return func() {
		ln.Close()
		if auditClose != nil {
			auditClose()
		}
	}, nil
}

// hostRingService starts the ring receiver on the node's own mesh identity:
// sender ACL, per-identity rate limit, escape-safe rendering to stdout, and
// optional audit — the receiving half of `air ring`, in-process.
func hostRingService(client *embed.Client, port int, allow []string, auditPath string, ratePerMin float64) (func(), error) {
	var audit *policy.AuditLog
	var auditClose func()
	if auditPath != "" {
		f, err := os.OpenFile(auditPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return nil, fmt.Errorf("open audit log %s: %w", auditPath, err)
		}
		auditClose = func() { f.Close() }
		audit = policy.NewAuditLog(f, func() string { return time.Now().UTC().Format(time.RFC3339) })
	}
	ln, err := client.ListenTCP(fmt.Sprintf(":%d", port))
	if err != nil {
		if auditClose != nil {
			auditClose()
		}
		return nil, fmt.Errorf("listen on mesh port %d: %w", port, err)
	}
	limiter := newRingLimiter(ratePerMin)
	handle := func(n air.Notice, meta session.Meta) {
		onRing(n, meta, limiter, audit, false, false, os.Stdout)
	}
	identity := func(addr net.Addr) (string, string) { return peerIdentity(client, addr) }
	go runAirAcceptLoop(ln, identity, newACL(allow), newListenFactory(handle), "ring", log.Printf)
	return func() {
		ln.Close()
		if auditClose != nil {
			auditClose()
		}
	}, nil
}

// runAirAcceptLoop is the shared receiver loop behind `drop --config`,
// `air listen`, and a hosting `air node`: gate each sender by the ACL, then
// hand the connection to a resumable session served by factory. verb names the
// service in log lines.
func runAirAcceptLoop(ln net.Listener, identity func(net.Addr) (string, string), checker acl, factory session.BackendFactory, verb string, logf func(string, ...any)) {
	srv := session.NewServer(factory, 2*time.Minute, logf)
	for {
		conn, err := ln.Accept()
		if err != nil {
			logf("%s receiver shutting down", verb)
			return
		}
		pubKey, fqdn := identity(conn.RemoteAddr())
		if !checker.allows(pubKey, fqdn) {
			logf("%s DENIED from %s (%s): not in allow list", verb, fqdn, shortKey(pubKey))
			conn.Close()
			continue
		}
		go srv.Handle(conn, session.Meta{PeerFQDN: fqdn, PeerAddr: conn.RemoteAddr().String(), PeerKey: pubKey})
	}
}
