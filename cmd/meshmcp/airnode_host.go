package main

import (
	"errors"
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

// mergeHostedInbox announces the hosted inbox on the node's card. The hosted
// service owns the inbox slot: a manually announced --service inbox would
// advertise a receiver this process does not run, so it is a conflict, not an
// override.
func mergeHostedInbox(ann air.Announcement, port int) (air.Announcement, error) {
	for _, svc := range ann.Services {
		if svc.Kind == air.ServiceInbox {
			return air.Announcement{}, errors.New("--service inbox conflicts with --inbox-port; the hosted inbox is announced automatically")
		}
	}
	out := ann
	out.Services = append(append([]air.Service(nil), ann.Services...), air.Service{
		Kind: air.ServiceInbox, Port: port,
		Capabilities: []string{air.InboxCompletionCapabilityV1},
	})
	return out, nil
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
	go runDropAcceptLoop(ln, identity, newACL(allow), dirPlacer(dir), lim, audit, log.Printf)
	return func() {
		ln.Close()
		if auditClose != nil {
			auditClose()
		}
	}, nil
}

// runDropAcceptLoop is the shared receiver loop behind `drop --config` and a
// hosting `air node`: gate each sender by the ACL, then hand the connection to
// a resumable drop session.
func runDropAcceptLoop(ln net.Listener, identity func(net.Addr) (string, string), checker acl, place placer, lim dropLimits, audit *policy.AuditLog, logf func(string, ...any)) {
	srv := session.NewServer(newDropFactory(place, lim, audit), 2*time.Minute, logf)
	for {
		conn, err := ln.Accept()
		if err != nil {
			logf("drop receiver shutting down")
			return
		}
		pubKey, fqdn := identity(conn.RemoteAddr())
		if !checker.allows(pubKey, fqdn) {
			logf("drop DENIED from %s (%s): not in allow list", fqdn, shortKey(pubKey))
			conn.Close()
			continue
		}
		go srv.Handle(conn, session.Meta{PeerFQDN: fqdn, PeerAddr: conn.RemoteAddr().String(), PeerKey: pubKey})
	}
}
