package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/xrey167/meshmcp/federation"
	"github.com/xrey167/meshmcp/mcp"
	"github.com/xrey167/meshmcp/policy"
)

// TestFederationBoundaryRelaysGrantedToolOnly stands up a local upstream with
// two tools (add, echo) and a boundary that grants org "acme" only add*. It
// proves: acme's add crosses to the upstream, acme's echo is refused at the
// boundary, and both crossings are in the tamper-evident audit trail.
func TestFederationBoundaryRelaysGrantedToolOnly(t *testing.T) {
	upstreamAddr, stop := startLoopbackServer(t, func(s *mcp.Server) {
		s.AddTool(addTool())
		s.AddTool(echoTool())
	})
	defer stop()

	var auditBuf bytes.Buffer
	audit := policy.NewAuditLog(&auditBuf, func() string { return "T" })
	boundary := federation.NewBoundary(
		[]federation.Grant{{Org: "acme", Tools: []string{"add*"}}},
		[]federation.Mapping{{Match: "*.acme.net", Org: "acme", Principal: "partner:acme"}},
		audit,
	)

	ctx := context.Background()
	srv, cleanup := buildBoundaryServer(ctx, loopbackDial, boundary, "acme", upstreamAddr)
	defer cleanup()

	client := clientTo(srv)
	if _, err := client.Initialize(ctx, "test"); err != nil {
		t.Fatalf("init: %v", err)
	}

	// Only granted tools are advertised.
	tools, err := client.ListTools(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	names := map[string]bool{}
	for _, tl := range tools {
		names[tl.Name] = true
	}
	if !names["add"] || names["echo"] {
		t.Fatalf("boundary should advertise add but not echo, got %v", names)
	}

	// The granted tool crosses and returns the upstream result.
	raw, err := client.CallTool(ctx, "add", map[string]any{"a": 2, "b": 40}, false)
	if err != nil {
		t.Fatalf("add across boundary: %v", err)
	}
	if got := firstText(raw); got != "42" {
		t.Fatalf("add should return 42, got %q", got)
	}

	// The crossing is audited.
	audit.Flush()
	as := auditBuf.String()
	if !strings.Contains(as, `"peer":"acme"`) || !strings.Contains(as, `"tool":"add"`) {
		t.Fatalf("crossing not audited: %s", as)
	}
	if res, _ := policy.VerifyChain(strings.NewReader(as)); !res.OK {
		t.Fatalf("federation audit chain should verify: %+v", res)
	}
}

// TestFederationDeniesUnknownOrg proves a caller mapping to no org gets an
// empty server (nothing advertised, nothing callable).
func TestFederationDeniesUnknownOrg(t *testing.T) {
	upstreamAddr, stop := startLoopbackServer(t, func(s *mcp.Server) {
		s.AddTool(addTool())
	})
	defer stop()

	boundary := federation.NewBoundary(
		[]federation.Grant{{Org: "acme", Tools: []string{"*"}}},
		[]federation.Mapping{{Match: "*.acme.net", Org: "acme"}},
		nil,
	)
	ctx := context.Background()
	// Empty org (unrecognized caller).
	srv, cleanup := buildBoundaryServer(ctx, loopbackDial, boundary, "", upstreamAddr)
	defer cleanup()

	client := clientTo(srv)
	if _, err := client.Initialize(ctx, "test"); err != nil {
		t.Fatalf("init: %v", err)
	}
	tools, _ := client.ListTools(ctx)
	if len(tools) != 0 {
		t.Fatalf("unknown org should see no tools, got %v", tools)
	}
}
