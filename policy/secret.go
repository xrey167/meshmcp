package policy

// SecretResolver injects credentials into an authorized outbound tools/call.
// It is implemented by the secrets broker and attached to a Filter with
// SetSecretResolver. The Filter calls it only AFTER a call is authorized and
// traced, so the raw secret value reaches the backend alone — never the trace
// or the audit log.
type SecretResolver interface {
	// Resolve substitutes secret references in an outbound tools/call line.
	// It returns ok=false with a reason when a referenced secret is not
	// granted, is blocked by the session's labels, or is unavailable; the
	// Filter then denies the call inline. A line with no references returns
	// unchanged with ok=true.
	//
	// injected is the set of secret byte-values substituted into this call, so
	// the Filter can scrub them from later responses (response-side redaction).
	// It must contain no value that was not actually injected, and the caller
	// must never trace, audit, log, or otherwise surface these bytes.
	Resolve(caller Caller, tool string, line []byte, labels map[string]bool) (out []byte, injected [][]byte, ok bool, reason string)
}

// SetSecretRedactor attaches a redactor the filter uses to scrub injected secret
// values out of backend responses. A redactor is created automatically the
// first time a secret is injected, so this is only needed to share one.
func (f *Filter) SetSecretRedactor(r *Redactor) { f.redactor = r }

// SetSecretResolver attaches a credential broker to the filter.
func (f *Filter) SetSecretResolver(r SecretResolver) { f.secrets = r }

// SetPendingStore attaches a held-request registry so a co-sign outcome is
// recorded for a human approver (e.g. a phone on the mesh) to act on.
func (f *Filter) SetPendingStore(p PendingStore) { f.pending = p }

// AddDecisionHook appends a plugin decision hook. Hooks run after the rule
// engine and any capability upgrade, in registration order, and may only
// tighten the outcome (deny / co-sign) or add data-flow labels — never widen a
// deny into an allow (enforced by applyDecisionHooks).
func (f *Filter) AddDecisionHook(h DecisionHook) {
	if h != nil {
		f.hooks = append(f.hooks, h)
	}
}
