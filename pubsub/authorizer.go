package pubsub

import (
	"path"
	"strings"
)

// Action distinguishes the two authorized operations on the bus.
type Action int

const (
	// ActPublish authorizes emitting an event to a topic.
	ActPublish Action = iota
	// ActSubscribe authorizes opening a subscription to a topic.
	ActSubscribe
)

// PubDecision is the authorizer's verdict for a publish. Labels are the
// data-flow labels the bus stamps onto the allowed event (emit labels, e.g.
// a `web.*` topic that always yields "tainted" content) — these travel with
// the event and drive subscriber-side containment.
type PubDecision struct {
	Allow  bool
	Reason string
	Labels []string
	// Explicit is true when a rule matched (allow or deny), false for the
	// default. A signed capability may upgrade only a non-explicit (default)
	// deny to allow — never an explicit `allow: false`.
	Explicit bool
}

// SubDecision is the authorizer's verdict for a subscribe. Clear is the set of
// data-flow labels this subscription is cleared to receive; the broker delivers
// an event to the subscription only if every label the event carries is in
// Clear. An empty Clear therefore receives only unlabeled events — deny by
// default for taint, matching the gateway's taint_guard posture. ClearAll
// overrides Clear and receives events regardless of labels (an unrestricted,
// fully-trusted subscriber).
type SubDecision struct {
	Allow    bool
	Reason   string
	Clear    []string
	ClearAll bool
	// Explicit is true when a rule matched. A capability may upgrade only a
	// non-explicit (default) deny.
	Explicit bool
}

// Authorizer decides whether an identity may publish to or subscribe to a
// topic, and carries the label semantics for each. Implementations MUST be
// safe for concurrent use: the broker calls them under load from many peers.
type Authorizer interface {
	Publish(id Identity, topic string) PubDecision
	Subscribe(id Identity, topic string) SubDecision
}

// TopicRule authorizes (or denies) a set of identities on a set of topic
// globs, mirroring policy.Rule but for the event fabric. Peers are matched by
// FQDN glob ("laptop-*.netbird.cloud") or "pubkey:<key>"; an empty Peers
// matches any identity. Topics are matched by glob ("web.*", "*"); an empty
// Topics matches any topic. The first matching rule wins.
type TopicRule struct {
	Peers  []string `yaml:"peers,omitempty"`
	Topics []string `yaml:"topics,omitempty"`
	Allow  bool     `yaml:"allow"`

	// Emit are labels stamped onto publishes this rule allows (data-flow
	// taint at the source). `taint: true` is sugar for Emit: ["tainted"].
	Emit  []string `yaml:"emit_labels,omitempty"`
	Taint bool     `yaml:"taint,omitempty"`

	// Clear are the labels subscriptions this rule allows may receive. An
	// event carrying any label outside a subscriber's cleared set is dropped
	// for that subscriber. `clear_taint: true` is sugar for Clear: ["tainted"].
	// ClearAll clears every label (an unrestricted subscriber) and overrides
	// Clear/ClearTaint.
	Clear      []string `yaml:"clear_labels,omitempty"`
	ClearTaint bool     `yaml:"clear_taint,omitempty"`
	ClearAll   bool     `yaml:"clear_all,omitempty"`
}

func (r TopicRule) emitSet() []string {
	out := append([]string(nil), r.Emit...)
	if r.Taint {
		out = append(out, "tainted")
	}
	return out
}

func (r TopicRule) clearSet() []string {
	out := append([]string(nil), r.Clear...)
	if r.ClearTaint {
		out = append(out, "tainted")
	}
	return out
}

// RuleAuthorizer is an ordered list of TopicRules with a default decision.
// It is the concrete Authorizer used by the broker daemon, configured from
// YAML. Deny-by-default (DefaultAllow=false) is the safe posture.
type RuleAuthorizer struct {
	DefaultAllow bool        `yaml:"default_allow"`
	Rules        []TopicRule `yaml:"rules"`
}

// Publish implements Authorizer.
func (a *RuleAuthorizer) Publish(id Identity, topic string) PubDecision {
	if r := a.match(id, topic); r != nil {
		return PubDecision{Allow: r.Allow, Reason: reason(r.Allow, "rule"), Labels: r.emitSet(), Explicit: true}
	}
	return PubDecision{Allow: a.DefaultAllow, Reason: reason(a.DefaultAllow, "default")}
}

// Subscribe implements Authorizer.
func (a *RuleAuthorizer) Subscribe(id Identity, topic string) SubDecision {
	if r := a.match(id, topic); r != nil {
		return SubDecision{Allow: r.Allow, Reason: reason(r.Allow, "rule"), Clear: r.clearSet(), ClearAll: r.ClearAll, Explicit: true}
	}
	return SubDecision{Allow: a.DefaultAllow, Reason: reason(a.DefaultAllow, "default")}
}

func (a *RuleAuthorizer) match(id Identity, topic string) *TopicRule {
	for i := range a.Rules {
		r := &a.Rules[i]
		if matchPeer(r.Peers, id.Key, id.FQDN) && matchGlob(r.Topics, topic) {
			return r
		}
	}
	return nil
}

func reason(allow bool, src string) string {
	if allow {
		return "allowed by " + src
	}
	return "denied by " + src
}

// matchPeer reports whether key/fqdn matches any pattern. An empty pattern
// list matches any peer. Patterns are "pubkey:<key>" (exact key) or an FQDN
// glob.
func matchPeer(patterns []string, key, fqdn string) bool {
	if len(patterns) == 0 {
		return true
	}
	for _, p := range patterns {
		if k, ok := strings.CutPrefix(p, "pubkey:"); ok {
			if k == key {
				return true
			}
			continue
		}
		if p == "*" || p == fqdn {
			return true
		}
		if ok, _ := path.Match(p, fqdn); ok {
			return true
		}
	}
	return false
}

// matchGlob reports whether s matches any glob. An empty pattern list matches
// anything.
func matchGlob(patterns []string, s string) bool {
	if len(patterns) == 0 {
		return true
	}
	for _, p := range patterns {
		if p == "*" || p == s {
			return true
		}
		if ok, _ := path.Match(p, s); ok {
			return true
		}
	}
	return false
}

// AllowAll is an Authorizer that permits every publish and subscribe with no
// label restrictions. It exists for tests and for a deliberately open broker;
// production brokers use a RuleAuthorizer with DefaultAllow=false.
type AllowAll struct{}

func (AllowAll) Publish(Identity, string) PubDecision { return PubDecision{Allow: true} }
func (AllowAll) Subscribe(Identity, string) SubDecision {
	return SubDecision{Allow: true, ClearAll: true}
}
