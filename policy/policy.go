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

// Decision is the outcome of authorizing a tool call.
type Decision struct {
	Allow  bool
	RuleID int // index of the matching rule, or -1 for the default
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
			return Decision{Allow: r.Allow, RuleID: i}
		}
	}
	return Decision{Allow: p.DefaultAllow, RuleID: -1}
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
			return Decision{Allow: r.Allow, RuleID: i}
		}
	}
	return Decision{Allow: true, RuleID: -1}
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
