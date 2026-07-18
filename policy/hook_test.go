package policy

import (
	"encoding/json"
	"strings"
	"testing"
)

// staticHook returns a fixed decision regardless of input.
type staticHook struct{ out Decision }

func (h staticHook) DecideTool(ToolCallInfo, Decision) Decision { return h.out }

// TestDecisionHookCannotWidenDeny proves a hook returning allow can never turn
// a base deny into an allow (tighten-only invariant / F13).
func TestDecisionHookCannotWidenDeny(t *testing.T) {
	base := Decision{Outcome: OutcomeDeny, RuleID: 3, Reason: "denied by rule"}
	hooks := []DecisionHook{staticHook{out: Decision{Outcome: OutcomeAllow, Allow: true}}}
	got := applyDecisionHooks(hooks, ToolCallInfo{Tool: "x"}, base)
	if got.Outcome != OutcomeDeny || got.Allow {
		t.Fatalf("hook widened a deny into %v (allow=%v)", got.Outcome, got.Allow)
	}
}

// TestDecisionHookCanTightenAllow proves a hook can escalate an allow to a deny
// (and to co-sign), and that its reason and labels take effect.
func TestDecisionHookCanTightenAllow(t *testing.T) {
	base := Decision{Outcome: OutcomeAllow, Allow: true, RuleID: 1}
	deny := applyDecisionHooks([]DecisionHook{staticHook{out: Decision{Outcome: OutcomeDeny, Reason: "DLP: pii detected"}}},
		ToolCallInfo{Tool: "x"}, base)
	if deny.Outcome != OutcomeDeny || deny.Allow || deny.Reason != "DLP: pii detected" {
		t.Fatalf("hook failed to tighten allow->deny: %+v", deny)
	}

	cosign := applyDecisionHooks([]DecisionHook{staticHook{out: Decision{Outcome: OutcomeCosign, Reason: "needs review"}}},
		ToolCallInfo{Tool: "x"}, base)
	if cosign.Outcome != OutcomeCosign {
		t.Fatalf("hook failed to escalate allow->cosign: %+v", cosign)
	}
}

// labelHook adds a label and otherwise passes the base decision through.
type labelHook struct{ label string }

func (h labelHook) DecideTool(_ ToolCallInfo, base Decision) Decision {
	base.AddLabels = append(base.AddLabels, h.label)
	return base
}

// TestDecisionHookEndToEndDeniesCall wires a denying hook into a real Filter and
// asserts the call is denied inline and never reaches the backend.
func TestDecisionHookEndToEndDeniesCall(t *testing.T) {
	backend := newRecordRWC()
	pol := &Policy{DefaultAllow: true} // rules allow; the hook must still deny
	f := NewFilter(backend, Caller{Peer: "alice", PeerKey: "k", Backend: "b"}, pol, nil, nil)
	f.AddDecisionHook(staticHook{out: Decision{Outcome: OutcomeDeny, Reason: "blocked by plugin"}})

	call := `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"do_it","arguments":{}}}` + "\n"
	go func() { _, _ = f.Write([]byte(call)) }()
	buf := make([]byte, 4096)
	n, _ := f.Read(buf)
	if got := string(buf[:n]); !strings.Contains(got, "blocked by plugin") {
		t.Fatalf("expected plugin denial, got: %s", got)
	}
	if backend.written.Len() != 0 {
		t.Fatalf("denied call reached backend: %q", backend.written.String())
	}
}

// TestDecisionHookSeesArguments proves the hook receives the call's raw
// arguments (the content a DLP/semantic hook inspects).
func TestDecisionHookSeesArguments(t *testing.T) {
	var seen json.RawMessage
	inspect := hookFunc(func(info ToolCallInfo, base Decision) Decision {
		seen = info.Arguments
		return base
	})
	backend := newRecordRWC()
	go func() {
		b := make([]byte, 4096)
		for {
			if _, err := backend.r.Read(b); err != nil {
				return
			}
		}
	}()
	f := NewFilter(backend, Caller{Peer: "a", PeerKey: "k", Backend: "b"}, &Policy{DefaultAllow: true}, nil, nil)
	f.AddDecisionHook(inspect)
	call := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"t","arguments":{"path":"secret.txt"}}}` + "\n"
	if _, err := f.Write([]byte(call)); err != nil {
		t.Fatalf("write: %v", err)
	}
	if !strings.Contains(string(seen), "secret.txt") {
		t.Fatalf("hook did not see arguments, got: %s", string(seen))
	}
}

type hookFunc func(ToolCallInfo, Decision) Decision

func (h hookFunc) DecideTool(i ToolCallInfo, d Decision) Decision { return h(i, d) }
