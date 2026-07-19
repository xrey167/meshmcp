package policy

import (
	"path"
	"strings"
)

// GroupResolver reports whether a caller identity belongs to a named group, so
// a policy rule can authorize by role/group instead of an individual key (F17).
// The static resolver below works from config today; a NetBird management-API
// resolver is a drop-in that implements the same interface.
type GroupResolver interface {
	InGroup(peerKey, peerFQDN, group string) bool
}

// StaticGroups maps a group name to a list of member patterns — each a
// "pubkey:<key>" or an FQDN glob, the same forms a rule's peers accept. It is
// the config-driven GroupResolver ("groups:" in the gateway config).
type StaticGroups map[string][]string

func (g StaticGroups) InGroup(peerKey, peerFQDN, group string) bool {
	for _, pat := range g[group] {
		if k, ok := strings.CutPrefix(pat, "pubkey:"); ok {
			if k == peerKey {
				return true
			}
			continue
		}
		if pat == "*" || peerFQDN == pat {
			return true
		}
		if ok, _ := path.Match(pat, peerFQDN); ok {
			return true
		}
	}
	return false
}
