package main

import (
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xrey167/meshmcp/air"
)

func TestMergeHostedInbox(t *testing.T) {
	ann := air.Announcement{
		Name: "analyst", Kind: air.NodeAgent,
		Services: []air.Service{{Kind: air.ServiceSteer, Port: 9120}},
	}
	out, err := mergeHostedInbox(ann, 9110)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Services) != 2 {
		t.Fatalf("services = %v", out.Services)
	}
	inbox := out.Services[1]
	if inbox.Kind != air.ServiceInbox || inbox.Port != 9110 {
		t.Fatalf("hosted inbox service = %+v", inbox)
	}
	if len(inbox.Capabilities) != 1 || inbox.Capabilities[0] != air.InboxCompletionCapabilityV1 {
		t.Fatalf("hosted inbox must advertise %s, got %v", air.InboxCompletionCapabilityV1, inbox.Capabilities)
	}
	// The input announcement must not be mutated.
	if len(ann.Services) != 1 {
		t.Fatalf("input announcement mutated: %v", ann.Services)
	}

	// A manually announced inbox is a conflict, never an override.
	conflicted := air.Announcement{Services: []air.Service{{Kind: air.ServiceInbox, Port: 9000}}}
	if _, err := mergeHostedInbox(conflicted, 9110); err == nil || !strings.Contains(err.Error(), "conflicts") {
		t.Fatalf("expected conflict error, got %v", err)
	}
}

// TestDropAcceptLoopACLGate proves the shared receiver loop admits only
// ACL-listed identities: a denied peer's connection is closed before any
// session traffic; an allowed peer's connection stays open for the handshake.
func TestDropAcceptLoopACLGate(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	// The loop resolves the caller identity via this fake. Each dial below is
	// fully asserted before the next identity is installed, so the guarded
	// "current identity" is unambiguous per connection.
	var mu sync.Mutex
	current := struct{ key, fqdn string }{}
	identity := func(net.Addr) (string, string) {
		mu.Lock()
		defer mu.Unlock()
		return current.key, current.fqdn
	}
	go runDropAcceptLoop(ln, identity, newACL([]string{"allowed.mesh"}),
		dirPlacer(t.TempDir()), dropLimits{}, nil, func(string, ...any) {})

	dial := func(key, fqdn string) net.Conn {
		t.Helper()
		mu.Lock()
		current = struct{ key, fqdn string }{key, fqdn}
		mu.Unlock()
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		return c
	}

	denied := dial("KEY-D", "denied.mesh")
	defer denied.Close()
	denied.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := denied.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("denied peer: want closed connection (EOF), got %v", err)
	}

	allowed := dial("KEY-A", "allowed.mesh")
	defer allowed.Close()
	allowed.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	_, err = allowed.Read(make([]byte, 1))
	var ne net.Error
	if !errors.As(err, &ne) || !ne.Timeout() {
		t.Fatalf("allowed peer: want an open (idle) connection awaiting ATTACH, got %v", err)
	}
}
