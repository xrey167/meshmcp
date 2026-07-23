package gateway

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/xrey167/meshmcp/gateway/channels"
	"github.com/xrey167/meshmcp/harness"
	"github.com/xrey167/meshmcp/policy"
)

func newGateway(t *testing.T, pairing DMPairing) (*Gateway, *channels.WebChat, *bytes.Buffer) {
	t.Helper()
	var buf bytes.Buffer
	al := policy.NewAuditLog(&buf, func() string { return "2026-07-23T00:00:00Z" })
	eng := harness.NewEngine(harness.EngineOpts{Audit: al, Now: func() time.Time { return time.Unix(0, 0) }})
	g := New(eng, pairing)
	wc := channels.NewWebChat()
	g.Register(wc)
	return g, wc, &buf
}

// TestChannelMessageOpensGovernedRun asserts a plain message runs a governed
// harness run and the reply is delivered to the channel, with the audit chain
// intact.
func TestChannelMessageOpensGovernedRun(t *testing.T) {
	g, wc, buf := newGateway(t, DMPairing{})
	r, err := g.Handle(context.Background(), channels.Inbound{Channel: "webchat", User: "u1", Text: "add a health endpoint"})
	if err != nil {
		t.Fatalf("handle: %v", err)
	}
	if r.Text == "" || r.Meta["run_id"] == "" {
		t.Fatalf("expected a run summary reply, got %+v", r)
	}
	if last, ok := wc.Last("u1"); !ok || last.Text != r.Text {
		t.Fatalf("reply not delivered to the channel")
	}
	if res, _ := policy.VerifyChain(bytes.NewReader(buf.Bytes())); !res.OK {
		t.Fatalf("audit chain broke: %s", res.Reason)
	}
}

// TestDMPairingBlocksUnpaired asserts an unpaired session is refused until paired.
func TestDMPairingBlocksUnpaired(t *testing.T) {
	g, _, _ := newGateway(t, DMPairing{Required: true})
	r, _ := g.Handle(context.Background(), channels.Inbound{Channel: "webchat", User: "u2", Text: "do a thing"})
	if !contains(r.Text, "isn't paired") {
		t.Fatalf("unpaired session should be refused, got %q", r.Text)
	}
	// Pair via slash-command, then it runs.
	g.Handle(context.Background(), channels.Inbound{Channel: "webchat", User: "u2", Text: "/pair"})
	r, err := g.Handle(context.Background(), channels.Inbound{Channel: "webchat", User: "u2", Text: "do a thing"})
	if err != nil {
		t.Fatalf("after pairing: %v", err)
	}
	if r.Meta["run_id"] == "" {
		t.Fatalf("paired session should run, got %+v", r)
	}
}

// TestSlashCommands asserts session commands map to control ops without running
// the pipeline.
func TestSlashCommands(t *testing.T) {
	g, _, _ := newGateway(t, DMPairing{})
	cases := map[string]string{
		"/help":       "commands:",
		"/status":     "no run yet",
		"/think high": "effort set to high",
		"/usage":      "budget",
		"/reset":      "session reset",
	}
	for msg, want := range cases {
		r, _ := g.Handle(context.Background(), channels.Inbound{Channel: "webchat", User: "u3", Text: msg})
		if !contains(r.Text, want) {
			t.Errorf("%q → %q, want substring %q", msg, r.Text, want)
		}
	}
}

// TestUnauthorizedChannelRefused asserts a token channel with no token is refused.
func TestUnauthorizedChannelRefused(t *testing.T) {
	g, _, _ := newGateway(t, DMPairing{})
	g.Register(channels.NewTokenChannel("slack", "")) // no token
	r, _ := g.Handle(context.Background(), channels.Inbound{Channel: "slack", User: "u", Text: "hi"})
	if !contains(r.Text, "not provisioned") {
		t.Fatalf("unprovisioned channel should be refused, got %q", r.Text)
	}
}

func contains(s, sub string) bool { return bytes.Contains([]byte(s), []byte(sub)) }
