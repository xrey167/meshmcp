// Package policy turns the meshmcp gateway into an MCP-aware policy
// enforcement point. It parses the JSON-RPC stream flowing from a mesh
// peer to a backend MCP server, authorizes individual tools/call requests
// against the caller's cryptographic mesh identity, denies disallowed
// calls inline with a JSON-RPC error, and records a structured audit
// trail of every tool invocation.
//
// This is a layer NetBird's network ACLs cannot express: network ACLs
// decide who may reach a backend at all; policy decides which *tools*
// each identity may call once connected.
package policy

import (
	"path"
	"strings"
)

// Outcome is a three-valued policy verdict. Beyond allow/deny, a call can be
// held pending a human co-sign.
type Outcome int

const (
	OutcomeDeny   Outcome = iota // blocked
	OutcomeAllow                 // permitted
	OutcomeCosign                // permitted only once a human identity co-signs
)

func (o Outcome) String() string {
	switch o {
	case OutcomeAllow:
		return "allow"
	case OutcomeCosign:
		return "cosign"
	default:
		return "deny"
	}
}

// Decision is the outcome of authorizing a tool call. Allow is kept as the
// boolean fast-path used by the simple Policy.Decide callers; Outcome carries
// the richer verdict (including co-sign) produced by the Engine.
type Decision struct {
	Allow     bool
	RuleID    int      // index of the matching rule, or -1 for the default
	Outcome   Outcome  // allow | deny | cosign
	Reason    string   // human-readable why (for audit + the denial message)
	AddLabels []string // data-flow labels this allowed call adds to the session
}

// Rule authorizes (or denies) a set of tools OR a set of JSON-RPC methods
// for a set of peers. Peers are matched by FQDN glob
// (e.g. "laptop-*.netbird.cloud") or "pubkey:<key>". Tools are matched by
// name glob (e.g. "read_*", "*"); Methods are matched by JSON-RPC method
// glob (e.g. "tasks/*", "notifications/*"). A rule governs tools when Tools
// is set (and Methods is empty), and governs methods when Methods is set.
// The first matching rule wins.
type Rule struct {
	Peers   []string `yaml:"peers"`
	Tools   []string `yaml:"tools"`
	Methods []string `yaml:"methods"`
	Allow   bool     `yaml:"allow"`

	// --- capability constraints (the "agent firewall") ---
	// These refine an allow rule; they are ignored on a deny rule. The Engine
	// (not the pure Policy) evaluates them, since they carry runtime state.

	// Rate caps how often this rule's identities may make matching calls.
	Rate *RateLimit `yaml:"rate"`
	// When restricts this rule to a set of days/hours; outside the window the
	// rule does not apply and evaluation falls through to the next rule.
	When *Window `yaml:"when"`
	// RequireCosign holds a matching call as OutcomeCosign until a human
	// identity on the mesh co-signs it (see CosignStore).
	RequireCosign bool `yaml:"require_cosign"`
	// TaintSource marks a matching call as producing untrusted data: once made,
	// the session is tainted (e.g. a tool that fetches arbitrary web content).
	// Sugar for emit_labels: ["tainted"].
	TaintSource bool `yaml:"taint_source"`
	// TaintGuard blocks a matching call whenever the session is tainted. This
	// is prompt-injection defense at the network layer: a privileged tool
	// simply will not be routed after untrusted data entered the session.
	// Sugar for block_labels: ["tainted"].
	TaintGuard bool `yaml:"taint_guard"`

	// EmitLabels are data-flow classification labels this call adds to the
	// session (e.g. ["pii"], ["secret"]). Labels model where sensitive data
	// has flowed, generalizing taint from one bit to a lattice.
	EmitLabels []string `yaml:"emit_labels"`
	// BlockLabels deny a matching call if the session already carries any of
	// these labels — e.g. an external-egress tool with block_labels: ["pii"]
	// enforces "no PII may leave the mesh", which no LLM guardrail or ordinary
	// firewall can express.
	BlockLabels []string `yaml:"block_labels"`
}

// emitSet is the effective set of labels this rule adds (including taint sugar).
func (r Rule) emitSet() []string {
	out := append([]string(nil), r.EmitLabels...)
	if r.TaintSource {
		out = append(out, "tainted")
	}
	return out
}

// blockSet is the effective set of labels that block this rule (incl. sugar).
func (r Rule) blockSet() []string {
	out := append([]string(nil), r.BlockLabels...)
	if r.TaintGuard {
		out = append(out, "tainted")
	}
	return out
}

// Policy is an ordered list of rules with a default decision.
type Policy struct {
	// DefaultAllow decides tool calls that match no rule. Default false
	// (deny) is the safe posture; set true for an allowlist-with-holes.
	DefaultAllow bool   `yaml:"default_allow"`
	Rules        []Rule `yaml:"rules"`
}

// Decide authorizes a tools/call by the given caller for the given tool.
// Method-governance rules (those with Methods set) are skipped here.
func (p *Policy) Decide(peerFQDN, peerKey, tool string) Decision {
	for i, r := range p.Rules {
		if len(r.Methods) > 0 {
			continue
		}
		if r.matchesPeer(peerFQDN, peerKey) && r.matchesTool(tool) {
			return Decision{Allow: r.Allow, RuleID: i, Outcome: outcomeOf(r.Allow)}
		}
	}
	return Decision{Allow: p.DefaultAllow, RuleID: -1, Outcome: outcomeOf(p.DefaultAllow)}
}

func outcomeOf(allow bool) Outcome {
	if allow {
		return OutcomeAllow
	}
	return OutcomeDeny
}

// DecideMethod authorizes a non-tool JSON-RPC method (e.g. tasks/cancel, or
// a client notification) by the given caller. Method governance is opt-in:
// a method is only restricted when a Methods rule matches it. With no
// matching rule the method is allowed (RuleID -1), so ungoverned methods
// like initialize and tools/list always pass. This intentionally does not
// use DefaultAllow, which is the deny-by-default posture for *tools*.
func (p *Policy) DecideMethod(peerFQDN, peerKey, method string) Decision {
	for i, r := range p.Rules {
		if len(r.Methods) == 0 {
			continue
		}
		if r.matchesPeer(peerFQDN, peerKey) && r.matchesMethod(method) {
			return Decision{Allow: r.Allow, RuleID: i, Outcome: outcomeOf(r.Allow)}
		}
	}
	return Decision{Allow: true, RuleID: -1, Outcome: OutcomeAllow}
}

func (r Rule) matchesPeer(fqdn, key string) bool {
	if len(r.Peers) == 0 {
		return true
	}
	for _, p := range r.Peers {
		if k, ok := strings.CutPrefix(p, "pubkey:"); ok {
			if k == key {
				return true
			}
			continue
		}
		if p == "*" || fqdn == p {
			return true
		}
		if ok, _ := path.Match(p, fqdn); ok {
			return true
		}
	}
	return false
}

func (r Rule) matchesTool(tool string) bool {
	if len(r.Tools) == 0 {
		return true
	}
	for _, t := range r.Tools {
		if t == "*" || t == tool {
			return true
		}
		if ok, _ := path.Match(t, tool); ok {
			return true
		}
	}
	return false
}

func (r Rule) matchesMethod(method string) bool {
	for _, m := range r.Methods {
		if m == "*" || m == method {
			return true
		}
		if ok, _ := path.Match(m, method); ok {
			return true
		}
	}
	return false
}
