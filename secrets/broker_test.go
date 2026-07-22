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
	out, _, ok, reason := b.Resolve(caller(), "charge", line, nil)
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
	out, _, ok, reason := b.Resolve(stranger, "charge", line, nil)
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
	if _, _, ok, _ := b.Resolve(caller(), "refund", line, nil); ok {
		t.Fatalf("stripe_key must not inject into a non-granted tool")
	}
}

func TestBrokerTaintBlocksInjection(t *testing.T) {
	b := testBroker(nil)
	line := []byte(`{"params":{"name":"charge","arguments":{"k":"{{secret:stripe_key}}"}}}`)
	// Session tainted → the grant's block_labels refuses injection.
	_, _, ok, reason := b.Resolve(caller(), "charge", line, map[string]bool{"tainted": true})
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
	out, _, ok, _ := b.Resolve(caller(), "charge", line, nil)
	if !ok || !bytes.Equal(out, line) {
		t.Fatalf("a line with no references must pass through unchanged")
	}
}

func TestBrokerUnavailableSecret(t *testing.T) {
	b := New(MapStore{}, []Grant{{Peers: []string{"*"}, Secrets: []string{"*"}}}, nil)
	line := []byte(`{"params":{"name":"x","arguments":{"k":"{{secret:missing}}"}}}`)
	if _, _, ok, reason := b.Resolve(caller(), "x", line, nil); ok || !strings.Contains(reason, "not available") {
		t.Fatalf("missing secret must be denied, got ok=%v reason=%q", ok, reason)
	}
}

// TestBrokerOnlyInjectsIntoArguments: a secret marker OUTSIDE params.arguments
// (e.g. in params.name) is left literal and never resolved — injection is
// confined to declared argument locations, not the whole message.
func TestBrokerOnlyInjectsIntoArguments(t *testing.T) {
	b := testBroker(nil)
	// Marker in params.name (not an argument) plus a real one in arguments.
	line := []byte(`{"method":"tools/call","params":{"name":"charge {{secret:openai}}","arguments":{"k":"{{secret:openai}}"}}}`)
	out, _, ok, reason := b.Resolve(caller(), "charge", line, nil)
	if !ok {
		t.Fatalf("resolve should succeed: %s", reason)
	}
	var msg map[string]any
	if err := json.Unmarshal(out, &msg); err != nil {
		t.Fatal(err)
	}
	params := msg["params"].(map[string]any)
	// The name still contains the literal marker (not injected).
	if !strings.Contains(params["name"].(string), "{{secret:openai}}") {
		t.Fatalf("marker outside arguments must be left literal, got name=%q", params["name"])
	}
	// The argument value IS injected.
	if params["arguments"].(map[string]any)["k"].(string) != "sk-abc" {
		t.Fatalf("argument marker should be injected, got %v", params["arguments"])
	}
}

// TestBrokerLocationBinding: a grant bound to an argument location injects only
// there; a reference at another location is denied.
func TestBrokerLocationBinding(t *testing.T) {
	b := New(
		MapStore{"tok": "SEKRET"},
		[]Grant{{Peers: []string{"*"}, Secrets: []string{"tok"}, Locations: []string{"headers.*"}}},
		nil,
	)
	c := policy.Caller{Backend: "b", Peer: "p", PeerKey: "K"}

	// Allowed location.
	ok1 := []byte(`{"params":{"name":"call","arguments":{"headers":{"Authorization":"Bearer {{secret:tok}}"}}}}`)
	out, _, ok, reason := b.Resolve(c, "call", ok1, nil)
	if !ok {
		t.Fatalf("headers.Authorization should be allowed: %s", reason)
	}
	if !strings.Contains(string(out), "Bearer SEKRET") {
		t.Fatalf("value not injected at allowed location: %s", out)
	}

	// Disallowed location.
	bad := []byte(`{"params":{"name":"call","arguments":{"body":{"token":"{{secret:tok}}"}}}}`)
	_, _, ok, reason = b.Resolve(c, "call", bad, nil)
	if ok {
		t.Fatal("a secret reference outside the granted location must be denied")
	}
	if !strings.Contains(reason, "location") {
		t.Fatalf("reason should mention location, got %q", reason)
	}
}

// TestBrokerNestedAndMultiple: multiple secrets across nested arguments and
// arrays, incl. Unicode, are all injected correctly.
func TestBrokerNestedAndMultiple(t *testing.T) {
	b := New(
		MapStore{"a": "AAA", "b": "BBB-üñïçödé"},
		[]Grant{{Peers: []string{"*"}, Secrets: []string{"a", "b"}}},
		nil,
	)
	c := policy.Caller{Backend: "x", Peer: "p", PeerKey: "K"}
	line := []byte(`{"params":{"name":"t","arguments":{"list":["{{secret:a}}","x"],"obj":{"deep":{"v":"pre-{{secret:b}}-post"}}}}}`)
	out, injected, ok, reason := b.Resolve(c, "t", line, nil)
	if !ok {
		t.Fatalf("resolve: %s", reason)
	}
	s := string(out)
	if !strings.Contains(s, `"AAA"`) || !strings.Contains(s, "pre-BBB-üñïçödé-post") {
		t.Fatalf("nested/multiple/unicode injection wrong: %s", s)
	}
	if len(injected) < 2 {
		t.Fatalf("expected injected values reported for redaction, got %d", len(injected))
	}
}
