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
	Resolve(caller Caller, tool string, line []byte, labels map[string]bool) (out []byte, ok bool, reason string)
}

// SetSecretResolver attaches a credential broker to the filter.
func (f *Filter) SetSecretResolver(r SecretResolver) { f.secrets = r }

// SetPendingStore attaches a held-request registry so a co-sign outcome is
// recorded for a human approver (e.g. a phone on the mesh) to act on.
func (f *Filter) SetPendingStore(p PendingStore) { f.pending = p }
