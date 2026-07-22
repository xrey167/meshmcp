package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/xrey167/meshmcp/air"
)

// homeFixture is a fully-populated board for the render tests.
func homeFixture() air.Home {
	h := air.Home{
		Generated: "2026-07-22T12:00:00Z",
		You:       air.PeerRow{Status: "connected", IP: "100.64.0.1", FQDN: "me.mesh", PubKey: "PUBKEYme"},
		Peers: []air.PeerRow{
			{Status: "connected", IP: "100.64.0.2", FQDN: "gw.mesh", PubKey: "PUBKEYgw"},
			{Status: "idle", IP: "100.64.0.3", FQDN: "laptop.mesh", PubKey: "PUBKEYlp"},
		},
		Nearby: []air.Presence{{
			Version: air.PresenceSchema, Name: "Research Agent", Kind: air.NodeAgent, Status: air.StatusAvailable,
			PublicKey: "PUBKEYagent", FQDN: "research.mesh", IP: "100.64.0.4",
			Services: []air.Service{{Kind: air.ServiceSteer, Port: 9120, Protocol: "tcp", Address: "100.64.0.4:9120"}},
			Activity: &air.Activity{Schema: air.ActivitySchema, ID: "research", Kind: air.ActivityTask, Title: "Customer research", State: air.ActivityRunning},
		}},
		Sessions:  []air.Session{{Backend: "fs", ID: "9f2a", Peer: "gw.mesh", AgeSec: 4}},
		Reachable: []air.CatalogEntry{{Name: "fs", Address: "100.64.0.2:9101", Transport: "stdio", Steerable: true}},
		Activity:  []air.Receipt{{Decision: "allow", Time: "2026-07-22T11:59:00Z", Peer: "gw.mesh", Method: "tools/call", Tool: "read"}},
		Pending:   1,
	}
	h.Summary = air.Summarize(h)
	return h
}

func TestRenderHomeGolden(t *testing.T) {
	var buf bytes.Buffer
	renderHome(&buf, homeFixture(), 5)
	out := buf.String()

	// The board paints, in order: YOU, hero counts, then each labelled section.
	wantOrder := []string{
		"me.mesh", "100.64.0.1", // YOU
		"● 1 nearby", "1 working", "1/2 mesh peers", "1 sessions", "1 reachable", "⏸ 1 waiting", // hero
		"NEARBY", "Research Agent", "Customer research",
		"MESH PEERS", "gw.mesh", "laptop.mesh",
		"LIVE SESSIONS", "fs", "9f2a",
		"REACHABLE", "100.64.0.2:9101", "steerable",
		"RECENT ACTIVITY", "allow", "tools/call",
	}
	last := -1
	for _, w := range wantOrder {
		i := strings.Index(out[last+1:], w)
		if i < 0 {
			t.Fatalf("board missing %q (or out of order) in:\n%s", w, out)
		}
		last = last + 1 + i
	}
}

func TestRenderHomeEmptyMesh(t *testing.T) {
	var buf bytes.Buffer
	h := air.Home{Generated: "2026-07-22T12:00:00Z", Pending: -1}
	h.Summary = air.Summarize(h)
	renderHome(&buf, h, 5)
	out := buf.String()

	for _, want := range []string{"no Air nodes nearby", "no peers reachable", "no live sessions", "no backends you may reach", "nothing recent", "— pending"} {
		if !strings.Contains(out, want) {
			t.Errorf("empty-mesh board missing calm state %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "0 waiting") {
		t.Errorf("unknown pending must read as a dash, not 0 waiting:\n%s", out)
	}
}

func TestRenderHomeSanitizesHostileFQDN(t *testing.T) {
	var buf bytes.Buffer
	h := air.Home{
		Generated: "2026-07-22T12:00:00Z",
		Peers:     []air.PeerRow{{Status: "connected", IP: "100.64.0.9", FQDN: "evil\x1b[31m.mesh", PubKey: "K"}},
		Activity:  []air.Receipt{{Decision: "deny", Time: "t", Peer: "evil\x1b[2J.mesh", Method: "m\x1b[H"}},
		Pending:   -1,
	}
	h.Summary = air.Summarize(h)
	renderHome(&buf, h, 5)
	if bytes.Contains(buf.Bytes(), []byte{0x1b}) {
		t.Fatalf("hostile ESC byte survived into rendered board: %q", buf.String())
	}
}

func TestWatchRedrawsOnlyOnChange(t *testing.T) {
	same := air.Home{Generated: "a", Peers: []air.PeerRow{{Status: "connected", FQDN: "x", PubKey: "K1"}}}
	same2 := air.Home{Generated: "b", Peers: []air.PeerRow{{Status: "connected", FQDN: "x", PubKey: "K1"}}} // same state, later
	changed := air.Home{Generated: "c", Peers: []air.PeerRow{
		{Status: "connected", FQDN: "x", PubKey: "K1"},
		{Status: "connected", FQDN: "y", PubKey: "K2"},
	}}
	homes := []air.Home{same, same2, changed}

	var i int
	poll := func() (air.Home, error) {
		h := homes[i]
		if i < len(homes)-1 {
			i++
		}
		return h, nil
	}

	// Two ticks then close: initial draw (same), tick→same2 (no draw), tick→changed (draw).
	ticks := make(chan time.Time, 2)
	ticks <- time.Now()
	ticks <- time.Now()
	close(ticks)

	var draws int
	render := func(w io.Writer, h air.Home) { draws++ }
	if err := watchHome(context.Background(), io.Discard, poll, ticks, render); err != nil {
		t.Fatal(err)
	}
	if draws != 2 {
		t.Fatalf("draws = %d, want 2 (initial + the one real change)", draws)
	}
}

func TestHomeJSONRoundTrip(t *testing.T) {
	h := air.Home{
		Generated: nowRFC3339(),
		You:       air.PeerRow{FQDN: "me.mesh"},
		Peers:     []air.PeerRow{{Status: "connected", FQDN: "gw.mesh"}},
		Sessions:  []air.Session{{Backend: "fs", ID: "9f2a", Peer: "gw.mesh", AgeSec: 3}},
		Pending:   -1,
	}
	h.Summary = air.Summarize(h)

	b, err := json.Marshal(h)
	if err != nil {
		t.Fatal(err)
	}
	var got air.Home
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("--json output did not round-trip into air.Home: %v", err)
	}
	if got.You.FQDN != "me.mesh" || len(got.Peers) != 1 || len(got.Sessions) != 1 {
		t.Fatalf("round-trip lost data: %+v", got)
	}
	if got.Sessions[0].Backend != "fs" || got.Pending != -1 {
		t.Fatalf("round-trip corrupted fields: %+v", got)
	}
}
