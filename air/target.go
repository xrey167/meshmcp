package air

import (
	"fmt"
	"strings"
)

// TargetKind is the kind of live work a steer addresses. The Air · Steer
// vocabulary (AIR-STEER §1) addresses an agent by name, a session by id, a task
// by id, or a group by name — one "<kind>:<value>" grammar across all of them.
type TargetKind string

const (
	TargetAgent   TargetKind = "agent"
	TargetSession TargetKind = "session"
	TargetTask    TargetKind = "task"
	TargetGroup   TargetKind = "group"
)

// Target is the parsed sub-work address a steer acts on: "task:9f2a" →
// {Task, "9f2a"}. The zero Target (empty Kind) means "no sub-work addressed" —
// the steer applies to the agent itself.
type Target struct {
	Kind  TargetKind
	Value string
}

// ParseTarget parses a "<kind>:<value>" address. An empty string is the zero
// Target (no error) — a steer with no target. A present-but-malformed target,
// or one naming an unknown kind, is an error rather than being silently
// applied to the wrong work.
func ParseTarget(s string) (Target, error) {
	if s == "" {
		return Target{}, nil
	}
	kind, value, found := strings.Cut(s, ":")
	if !found || value == "" {
		return Target{}, fmt.Errorf("bad target %q (want <kind>:<value>, e.g. task:9f2a)", s)
	}
	switch k := TargetKind(kind); k {
	case TargetAgent, TargetSession, TargetTask, TargetGroup:
		return Target{Kind: k, Value: value}, nil
	default:
		return Target{}, fmt.Errorf("unknown target kind %q (want agent, session, task, or group)", kind)
	}
}

// Empty reports whether no sub-work is addressed (the steer applies to the
// agent itself).
func (t Target) Empty() bool { return t.Kind == "" }

// String renders the target back to its "<kind>:<value>" form ("" when empty).
func (t Target) String() string {
	if t.Empty() {
		return ""
	}
	return string(t.Kind) + ":" + t.Value
}

// ParsedTarget parses the envelope's Target field, so a receiver can route a
// steer to the sub-work it addresses.
func (e SteerEnvelope) ParsedTarget() (Target, error) { return ParseTarget(e.Target) }
