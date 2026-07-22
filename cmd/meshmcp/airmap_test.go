package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/xrey167/meshmcp/air"
)

// TestRenderAirMap proves the topology renders you → gateway → sorted backends
// with aligned names and capability labels, and handles the empty case.
func TestRenderAirMap(t *testing.T) {
	old := colorOn
	colorOn = false
	defer func() { colorOn = old }()

	var buf bytes.Buffer
	me := air.PeerRow{IP: "100.64.0.9", FQDN: "reys-iphone.mesh", PubKey: "AbCd"}
	cat := air.Catalog{
		Gateway: "gateway.mesh",
		Endpoints: []air.CatalogEntry{
			{Name: "knowledge-graph", Address: "100.64.0.2:9103", Transport: "stdio", Resumable: true, Steerable: true},
			{Name: "fs", Address: "100.64.0.2:9101", Transport: "stdio", Steerable: true},
			{Name: "billing", Address: "100.64.0.2:9102", Transport: "http"},
		},
	}
	renderAirMap(&buf, me, "100.64.0.2:9600", cat)
	out := buf.String()
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")

	if !strings.Contains(lines[0], "reys-iphone.mesh") || !strings.Contains(lines[0], "100.64.0.9") {
		t.Fatalf("you line wrong: %q", lines[0])
	}
	if !strings.Contains(out, "gateway.mesh") || !strings.Contains(out, "100.64.0.2:9600") {
		t.Fatalf("gateway line missing: %q", out)
	}
	// Sorted: billing, fs, knowledge-graph (alphabetical).
	bi, fi, ki := strings.Index(out, "billing"), strings.Index(out, "fs "), strings.Index(out, "knowledge-graph")
	if !(bi < fi && fi < ki) {
		t.Fatalf("backends not sorted: %q", out)
	}
	// Last branch uses └──.
	if !strings.Contains(out, "└──") || !strings.Contains(out, "├──") {
		t.Fatalf("tree branches missing: %q", out)
	}
	// Capabilities rendered.
	if !strings.Contains(out, "resumable") || !strings.Contains(out, "steerable") {
		t.Fatalf("capabilities missing: %q", out)
	}

	// Empty catalog → a clear leaf, no panic.
	buf.Reset()
	renderAirMap(&buf, me, "c:1", air.Catalog{})
	if !strings.Contains(buf.String(), "no backends") {
		t.Fatalf("empty map should say so: %q", buf.String())
	}
}
