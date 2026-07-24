package gateway

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/xrey167/meshmcp/gateway/channels"
)

// TestGatewayConcurrentHandle drives many messages across several users
// concurrently under the race detector — the gateway's session map must stay
// race-free.
func TestGatewayConcurrentHandle(t *testing.T) {
	g, _, _ := newGateway(t, DMPairing{})
	var wg sync.WaitGroup
	for i := 0; i < 60; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			user := fmt.Sprintf("u%d", n%5)
			if n%3 == 0 {
				_, _ = g.Handle(context.Background(), channels.Inbound{Channel: "webchat", User: user, Text: "/status"})
			} else {
				_, _ = g.Handle(context.Background(), channels.Inbound{Channel: "webchat", User: user, Text: "do a thing"})
			}
		}(i)
	}
	wg.Wait()
}

// TestParseSlashEdges asserts the slash-command parser handles degenerate inputs
// without panicking and normalizes the command.
func TestParseSlashEdges(t *testing.T) {
	cases := []struct {
		in       string
		wantCmd  string
		wantRest string
		wantOK   bool
	}{
		{"/help", "help", "", true},
		{"/", "", "", true},
		{"  /think   high  ", "think", "high", true},
		{"/THINK High", "think", "High", true},
		{"hello world", "", "", false},
		{"", "", "", false},
		{"/usage", "usage", "", true},
	}
	for _, c := range cases {
		cmd, rest, ok := parseSlash(c.in)
		if ok != c.wantOK || cmd != c.wantCmd || rest != c.wantRest {
			t.Errorf("parseSlash(%q) = (%q,%q,%v), want (%q,%q,%v)", c.in, cmd, rest, ok, c.wantCmd, c.wantRest, c.wantOK)
		}
	}
}

// TestUnknownChannelErrors asserts a message to an unregistered channel is a
// clean error, not a panic.
func TestUnknownChannelErrors(t *testing.T) {
	g, _, _ := newGateway(t, DMPairing{})
	r, err := g.Handle(context.Background(), channels.Inbound{Channel: "does-not-exist", User: "u", Text: "hi"})
	if err == nil {
		t.Fatal("unknown channel should error")
	}
	if !contains(r.Text, "not registered") {
		t.Fatalf("expected a not-registered reply, got %q", r.Text)
	}
}

// TestUnknownSlashCommand asserts an unknown command is handled gracefully.
func TestUnknownSlashCommand(t *testing.T) {
	g, _, _ := newGateway(t, DMPairing{})
	r, _ := g.Handle(context.Background(), channels.Inbound{Channel: "webchat", User: "u", Text: "/frobnicate now"})
	if !contains(r.Text, "unknown command") {
		t.Fatalf("expected an unknown-command reply, got %q", r.Text)
	}
}
