// Package hooks is the harness's lifecycle hook engine — a middleware chain
// evaluated at defined points in a run (pre-plan, pre-tool, post-tool,
// pre-spawn, post-run, on-error, on-notify). It merges the source harnesses'
// 54–61 hooks into one governed model: each hook is a pure decision
// (Event) → Effect where Effect is one of {continue, mutate, block, retry,
// inject}. Every non-continue effect is audited by the caller.
//
// Two governance properties are enforced here: a hook may be individually
// toggled, but a hook marked Safety cannot be disabled, and a user hook that
// declares it weakens a safety label is refused at load. This is the concrete
// "a user hook that would weaken a safety label is rejected by policy at load
// time" from the spec.
package hooks

import "strings"

// Phase is a lifecycle point at which the chain is evaluated.
type Phase string

const (
	PrePlan  Phase = "pre-plan"
	PreTool  Phase = "pre-tool"
	PostTool Phase = "post-tool"
	PreSpawn Phase = "pre-spawn"
	PostRun  Phase = "post-run"
	OnError  Phase = "on-error"
	OnNotify Phase = "on-notify"
)

// Event is the immutable input to a hook.
type Event struct {
	Phase  Phase
	Tool   string            // pre/post-tool: the tool name
	Role   string            // pre-spawn: the role being spawned
	Labels []string          // data-flow labels in play
	Text   string            // prompt/output/notify text
	ErrMsg string            // on-error: the error
	Meta   map[string]string // arbitrary context (e.g. "stopped":"true")
}

// EffectKind is the class of a hook's decision.
type EffectKind int

const (
	Continue EffectKind = iota // no change; the next hook runs
	Mutate                     // replace Text and/or Meta and continue
	Block                      // deny the action (terminal)
	Retry                      // ask the caller to retry (terminal)
	Inject                     // add Text to the context (terminal for this event)
)

func (k EffectKind) String() string {
	switch k {
	case Mutate:
		return "mutate"
	case Block:
		return "block"
	case Retry:
		return "retry"
	case Inject:
		return "inject"
	default:
		return "continue"
	}
}

// Effect is a hook's decision.
type Effect struct {
	Kind   EffectKind
	Reason string
	Text   string            // Mutate/Inject: the new/added text
	Meta   map[string]string // Mutate: fields to set
}

// Cont is the no-op effect.
var Cont = Effect{Kind: Continue}

// Hook is one lifecycle decision.
type Hook interface {
	Name() string
	Phases() []Phase
	Handle(e Event) Effect
}

// Safety marks a hook that must not be disabled (a load-time guarantee). A hook
// implementing Safety with IsSafety()==true is retained even if Disable names it.
type Safety interface {
	IsSafety() bool
}

// WeakensSafety is implemented by an untrusted (user) hook to self-declare that
// it would relax a safety label. Add refuses such a hook when strict loading is
// on, so a user hook can never silently weaken the firewall.
type WeakensSafety interface {
	WeakensSafety() bool
}

// AuditFunc records a non-continue effect. The chain calls it for every fired
// hook whose effect is not Continue, so hook decisions land on the audit trail.
type AuditFunc func(hook string, e Event, eff Effect)

// Chain is an ordered set of hooks with per-name disabling and audit.
type Chain struct {
	hooks    []Hook
	disabled map[string]bool
	strict   bool
	audit    AuditFunc
}

// NewChain builds a chain. strict rejects WeakensSafety hooks at Add. audit may
// be nil.
func NewChain(strict bool, audit AuditFunc) *Chain {
	return &Chain{disabled: map[string]bool{}, strict: strict, audit: audit}
}

// Add registers a hook. It returns false (and does not add) when strict loading
// is on and the hook declares it weakens a safety label.
func (c *Chain) Add(h Hook) bool {
	if c.strict {
		if w, ok := h.(WeakensSafety); ok && w.WeakensSafety() {
			return false
		}
	}
	c.hooks = append(c.hooks, h)
	return true
}

// Disable turns off named hooks. A hook implementing Safety with IsSafety()==true
// cannot be disabled; naming it is a no-op.
func (c *Chain) Disable(names ...string) {
	safe := map[string]bool{}
	for _, h := range c.hooks {
		if s, ok := h.(Safety); ok && s.IsSafety() {
			safe[h.Name()] = true
		}
	}
	for _, n := range names {
		if !safe[n] {
			c.disabled[n] = true
		}
	}
}

// Names returns the enabled hooks that fire at phase, in order.
func (c *Chain) Names(phase Phase) []string {
	var out []string
	for _, h := range c.hooks {
		if c.disabled[h.Name()] || !hasPhase(h, phase) {
			continue
		}
		out = append(out, h.Name())
	}
	return out
}

// Run evaluates the chain for e. It applies Mutate effects in place (threading
// the mutated event to later hooks) and returns the FIRST terminal effect
// (Block/Retry/Inject), or the final mutated Continue. The names of every hook
// that produced a non-continue effect are returned for the caller's trace, and
// each such effect is audited.
func (c *Chain) Run(e Event) (Effect, []string) {
	var fired []string
	final := Cont
	for _, h := range c.hooks {
		if c.disabled[h.Name()] || !hasPhase(h, e.Phase) {
			continue
		}
		eff := h.Handle(e)
		if eff.Kind == Continue {
			continue
		}
		if c.audit != nil {
			c.audit(h.Name(), e, eff)
		}
		fired = append(fired, h.Name())
		switch eff.Kind {
		case Mutate:
			if eff.Text != "" {
				e.Text = eff.Text
			}
			if len(eff.Meta) > 0 {
				e.Meta = mergeMeta(e.Meta, eff.Meta)
			}
			final = eff
		default: // Block, Retry, Inject are terminal
			return eff, fired
		}
	}
	return final, fired
}

func hasPhase(h Hook, p Phase) bool {
	for _, ph := range h.Phases() {
		if ph == p {
			return true
		}
	}
	return false
}

func mergeMeta(a, b map[string]string) map[string]string {
	out := make(map[string]string, len(a)+len(b))
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		out[k] = v
	}
	return out
}

func hasLabel(labels []string, want string) bool {
	for _, l := range labels {
		if l == want {
			return true
		}
	}
	return false
}

func containsAny(s string, subs ...string) bool {
	s = strings.ToLower(s)
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
