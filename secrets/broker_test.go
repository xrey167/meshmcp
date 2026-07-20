package secrets

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/xrey167/meshmcp/policy"
)

const secretVal = `sk_live_"weird"\value` // contains quotes + backslash on purpose

func testBroker(audit *policy.AuditLog) *Broker {
	return New(
		MapStore{"stripe_key": secretVal, "openai": "sk-abc"},
		[]Grant{
			{Peers: []string{"pubkey:AGENT"}, Secrets: []string{"stripe_*"}, Tools: []string{"charge"}, BlockLabels: []string{"tainted"}},
			{Peers: []string{"*"}, Secrets: []string{"openai"}},
		},
		audit,
	)
}

func caller() policy.Caller {
	return policy.Caller{Backend: "pay", Peer: "agent.mesh", PeerKey: "AGENT"}
}

func TestBrokerInjectsGrantedSecret(t *testing.T) {
	var buf bytes.Buffer
	b := testBroker(policy.NewAuditLog(&buf, func() string { return "T" }))

	line := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"charge","arguments":{"auth":"Bearer {{secret:stripe_key}}"}}}`)
	out, ok, reason := b.Resolve(caller(), "charge", line, nil)
	if !ok {
		t.Fatalf("granted secret should resolve, got reason %q", reason)
	}
	// The output must be valid JSON with the real value spliced in.
	var msg map[string]any
	if err := json.Unmarshal(out, &msg); err != nil {
		t.Fatalf("substituted line is not valid JSON: %v\n%s", err, out)
	}
	auth := msg["params"].(map[string]any)["arguments"].(map[string]any)["auth"].(string)
	if auth != "Bearer "+secretVal {
		t.Fatalf("value not substituted correctly: %q", auth)
	}
	// The audit records the NAME, never the VALUE.
	as := buf.String()
	if !strings.Contains(as, "stripe_key") || !strings.Contains(as, `"method":"secrets/inject"`) {
		t.Fatalf("secret use not audited: %s", as)
	}
	if strings.Contains(as, "sk_live") {
		t.Fatalf("SECRET VALUE LEAKED INTO AUDIT: %s", as)
	}
}

func TestBrokerDeniesUngranted(t *testing.T) {
	b := testBroker(nil)
	// stranger has no grant for stripe_key.
	stranger := policy.Caller{Backend: "pay", Peer: "stranger.mesh", PeerKey: "ZZ"}
	line := []byte(`{"params":{"name":"charge","arguments":{"k":"{{secret:stripe_key}}"}}}`)
	out, ok, reason := b.Resolve(stranger, "charge", line, nil)
	if ok {
		t.Fatalf("ungranted caller must be denied")
	}
	if out != nil {
		t.Fatalf("denied resolve must not return a substituted line")
	}
	if !strings.Contains(reason, "not granted") {
		t.Fatalf("reason should say not granted, got %q", reason)
	}
}

func TestBrokerToolRestriction(t *testing.T) {
	b := testBroker(nil)
	// AGENT may use stripe_key only for `charge`, not `refund`.
	line := []byte(`{"params":{"name":"refund","arguments":{"k":"{{secret:stripe_key}}"}}}`)
	if _, ok, _ := b.Resolve(caller(), "refund", line, nil); ok {
		t.Fatalf("stripe_key must not inject into a non-granted tool")
	}
}

func TestBrokerTaintBlocksInjection(t *testing.T) {
	b := testBroker(nil)
	line := []byte(`{"params":{"name":"charge","arguments":{"k":"{{secret:stripe_key}}"}}}`)
	// Session tainted → the grant's block_labels refuses injection.
	_, ok, reason := b.Resolve(caller(), "charge", line, map[string]bool{"tainted": true})
	if ok {
		t.Fatalf("tainted session must not receive a secret")
	}
	if !strings.Contains(reason, "tainted") {
		t.Fatalf("reason should mention taint, got %q", reason)
	}
}

func TestBrokerNoRefsPassthrough(t *testing.T) {
	b := testBroker(nil)
	line := []byte(`{"params":{"name":"charge","arguments":{"amount":100}}}`)
	out, ok, _ := b.Resolve(caller(), "charge", line, nil)
	if !ok || !bytes.Equal(out, line) {
		t.Fatalf("a line with no references must pass through unchanged")
	}
}

func TestBrokerUnavailableSecret(t *testing.T) {
	b := New(MapStore{}, []Grant{{Peers: []string{"*"}, Secrets: []string{"*"}}}, nil)
	line := []byte(`{"params":{"name":"x","arguments":{"k":"{{secret:missing}}"}}}`)
	if _, ok, reason := b.Resolve(caller(), "x", line, nil); ok || !strings.Contains(reason, "not available") {
		t.Fatalf("missing secret must be denied, got ok=%v reason=%q", ok, reason)
	}
}
