// Package channels holds the gateway's channel adapters — the front doors that
// turn an inbound message from a chat transport into a harness run and deliver
// the reply back. Each adapter authenticates via a broker-held token (never a
// token in config); a channel with no token reports Authorized()==false and is
// refused, so the gateway never serves a mis-provisioned transport.
package channels

import "sync"

// Inbound is a message received from a channel.
type Inbound struct {
	Channel string // adapter kind, e.g. "slack"
	User    string // channel-scoped user id
	Text    string
}

// Reply is the gateway's response to deliver back to the channel.
type Reply struct {
	Text string
	Meta map[string]string
}

// Channel is a messaging transport adapter. Kind is the transport name; the
// concrete send/receive plumbing (webhooks, long-poll, sockets) lives in the
// adapter. Authorized reports whether the adapter holds its broker-injected
// token and may serve.
type Channel interface {
	Kind() string
	Authorized() bool
	// Send delivers a reply to a channel user.
	Send(user string, r Reply) error
}

// WebChat is an in-process channel used for the built-in web chat surface and
// for tests: it has no external token (always authorized) and records the last
// reply per user so a caller can read it back. The gateway delivers from
// concurrent Handle goroutines, so access to the reply map is mutex-guarded.
type WebChat struct {
	mu   sync.Mutex
	last map[string]Reply
}

// NewWebChat builds an in-process web chat channel.
func NewWebChat() *WebChat { return &WebChat{last: map[string]Reply{}} }

func (w *WebChat) Kind() string     { return "webchat" }
func (w *WebChat) Authorized() bool { return true }

// Send records the reply for user (the built-in surface renders it).
func (w *WebChat) Send(user string, r Reply) error {
	w.mu.Lock()
	w.last[user] = r
	w.mu.Unlock()
	return nil
}

// Last returns the last reply delivered to user (test/inspection helper).
func (w *WebChat) Last(user string) (Reply, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	r, ok := w.last[user]
	return r, ok
}

// TokenChannel is a token-authenticated adapter (slack/telegram/discord/…). The
// token is resolved by name from the broker at construction; without it the
// channel is unauthorized and the gateway refuses to serve it — a mis-provisioned
// transport fails closed rather than serving anonymously.
type TokenChannel struct {
	kind  string
	token string // resolved from the broker by reference name; never logged
}

// NewTokenChannel builds a token channel. token is the value the broker resolved
// for this channel's reference; pass "" to model an un-provisioned channel.
func NewTokenChannel(kind, token string) *TokenChannel {
	return &TokenChannel{kind: kind, token: token}
}

func (t *TokenChannel) Kind() string     { return t.kind }
func (t *TokenChannel) Authorized() bool { return t.token != "" }

// Send delivers a reply. The live transport call (Slack/Telegram API over the
// mesh egress) is Phase-4 wiring; an unauthorized channel refuses.
func (t *TokenChannel) Send(user string, r Reply) error {
	if !t.Authorized() {
		return errUnauthorized(t.kind)
	}
	return nil
}

type unauthorizedError struct{ kind string }

func (e unauthorizedError) Error() string {
	return "channel " + e.kind + " has no broker token (fail-closed; provision it via the secrets broker)"
}

func errUnauthorized(kind string) error { return unauthorizedError{kind} }

// KnownChannels is the set of transport kinds the gateway recognizes (openclaw's
// 23+ transports). Adapters beyond webchat are token channels pending live wiring.
var KnownChannels = []string{
	"whatsapp", "telegram", "slack", "discord", "google-chat", "signal",
	"imessage", "irc", "teams", "matrix", "feishu", "line", "mattermost",
	"nextcloud-talk", "nostr", "synology-chat", "tlon", "twitch", "zalo",
	"wechat", "qq", "webchat",
}
