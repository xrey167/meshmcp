// Package gateway folds openclaw's multi-channel Gateway into meshmcp as an
// INGRESS ADAPTER to the same governed harness — a front door, not a parallel
// brain. An inbound message from any channel maps to a harness RunRequest driven
// by a per-channel-user mesh identity, so the same firewall, audit, secrets, and
// continuity apply to a Slack message as to a CLI run. Non-main channel sessions
// are sandboxed and restricted by default (openclaw's group/channel-safety),
// gated further by DM pairing.
//
// The gateway is optional: the harness is fully usable head-less over MCP + CLI.
package gateway

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/xrey167/meshmcp/gateway/channels"
	"github.com/xrey167/meshmcp/harness"
)

// DMPairing is the channel-safety policy. When Required, a channel:user session
// must be paired by an operator before the gateway serves it; unpaired sessions
// get a pairing prompt, never a run.
type DMPairing struct {
	Required       bool
	DefaultSandbox string // sandbox backend for non-main channel work (e.g. "docker")
}

// chSession is per channel:user state.
type chSession struct {
	lastRun harness.RunID
	think   string // effort level set via /think
	verbose bool
}

// Gateway routes channel messages to the harness.
type Gateway struct {
	eng      *harness.Engine
	pairing  DMPairing
	mu       sync.Mutex
	channels map[string]channels.Channel
	sessions map[string]*chSession
	paired   map[string]bool
}

// New builds a gateway over a harness engine.
func New(eng *harness.Engine, pairing DMPairing) *Gateway {
	return &Gateway{
		eng:      eng,
		pairing:  pairing,
		channels: map[string]channels.Channel{},
		sessions: map[string]*chSession{},
		paired:   map[string]bool{},
	}
}

// Register adds a channel adapter under its kind.
func (g *Gateway) Register(ch channels.Channel) {
	g.mu.Lock()
	g.channels[ch.Kind()] = ch
	g.mu.Unlock()
}

// Channels lists the registered channel kinds and whether each is authorized.
func (g *Gateway) Channels() map[string]bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := map[string]bool{}
	for k, ch := range g.channels {
		out[k] = ch.Authorized()
	}
	return out
}

// Pair marks a channel:user session as paired (an operator action).
func (g *Gateway) Pair(channel, user string) {
	g.mu.Lock()
	g.paired[sessKey(channel, user)] = true
	g.mu.Unlock()
}

// Handle processes one inbound message and returns the reply. Slash-commands are
// handled without running the pipeline; a normal message opens a governed run
// under a per-channel-user identity. The reply is also delivered to the channel
// adapter (Send).
func (g *Gateway) Handle(ctx context.Context, in channels.Inbound) (channels.Reply, error) {
	key := sessKey(in.Channel, in.User)

	if cmd, rest, ok := parseSlash(in.Text); ok {
		r := g.handleCommand(ctx, in, key, cmd, rest)
		g.deliver(in, r)
		return r, nil
	}

	g.mu.Lock()
	ch := g.channels[in.Channel]
	required := g.pairing.Required
	paired := g.paired[key]
	g.mu.Unlock()

	if ch == nil {
		return channels.Reply{Text: "channel not registered: " + in.Channel}, fmt.Errorf("unknown channel %q", in.Channel)
	}
	if !ch.Authorized() {
		r := channels.Reply{Text: "channel is not provisioned (no broker token); refused"}
		return r, nil
	}
	if required && !paired {
		return channels.Reply{Text: "This channel isn't paired yet. An operator must pair it before I can act. (/pair)"}, nil
	}

	// Per-channel-user identity: a distinct mesh identity so the session is
	// independently attributable and policy-scoped (openclaw isolation, governed).
	actor := harness.Identity{Key: "channel:" + key}
	st, err := g.eng.Run(ctx, harness.RunRequest{
		Goal:  in.Text,
		Mode:  harness.ModeQuick,
		Actor: actor,
	})
	if err != nil {
		r := channels.Reply{Text: "run failed: " + err.Error()}
		g.deliver(in, r)
		return r, err
	}

	g.mu.Lock()
	g.sessions[key] = &chSession{lastRun: st.ID}
	g.mu.Unlock()

	r := channels.Reply{Text: summarize(st), Meta: map[string]string{"run_id": string(st.ID)}}
	g.deliver(in, r)
	return r, nil
}

func (g *Gateway) deliver(in channels.Inbound, r channels.Reply) {
	g.mu.Lock()
	ch := g.channels[in.Channel]
	g.mu.Unlock()
	if ch != nil {
		_ = ch.Send(in.User, r)
	}
}

func sessKey(channel, user string) string { return channel + ":" + user }

func summarize(st harness.RunState) string {
	var b strings.Builder
	fmt.Fprintf(&b, "run %s: %s", st.ID, st.Status)
	if st.GoalMet {
		b.WriteString(" · goal met")
	}
	if len(st.Workers) > 0 {
		fmt.Fprintf(&b, " · %d worker(s)", len(st.Workers))
	}
	if st.Error != "" {
		fmt.Fprintf(&b, " · error: %s", st.Error)
	}
	return b.String()
}
