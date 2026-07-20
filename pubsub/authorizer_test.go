package pubsub

import (
	"bytes"
	"strings"
	"testing"

	"github.com/xrey167/meshmcp/policy"
)

func TestRuleAuthorizerMatching(t *testing.T) {
	auth := &RuleAuthorizer{
		Rules: []TopicRule{
			{Peers: []string{"pubkey:svc"}, Topics: []string{"metrics.*"}, Allow: true, ClearAll: true},
			{Peers: []string{"*.corp.netbird.cloud"}, Topics: []string{"chat.*"}, Allow: true, Clear: []string{"pii"}},
			{Topics: []string{"web.*"}, Allow: true, Taint: true},
		},
	}

	cases := []struct {
		name          string
		id            Identity
		topic         string
		wantPubAllow  bool
		wantEmit      []string
		wantSubAllow  bool
		wantClearAll  bool
		wantClearList []string
	}{
		{"svc metrics", Identity{Key: "svc"}, "metrics.cpu", true, nil, true, true, nil},
		{"svc wrong topic", Identity{Key: "svc"}, "chat.x", false, nil, false, false, nil},
		{"corp fqdn chat", Identity{FQDN: "a.corp.netbird.cloud"}, "chat.room", true, nil, true, false, []string{"pii"}},
		{"web taint", Identity{Key: "anyone"}, "web.fetch", true, []string{"tainted"}, true, false, nil},
		{"unmatched default deny", Identity{Key: "x"}, "other", false, nil, false, false, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			pd := auth.Publish(c.id, c.topic)
			if pd.Allow != c.wantPubAllow {
				t.Fatalf("publish allow=%v want %v", pd.Allow, c.wantPubAllow)
			}
			if strings.Join(pd.Labels, ",") != strings.Join(c.wantEmit, ",") {
				t.Fatalf("emit labels=%v want %v", pd.Labels, c.wantEmit)
			}
			sd := auth.Subscribe(c.id, c.topic)
			if sd.Allow != c.wantSubAllow {
				t.Fatalf("subscribe allow=%v want %v", sd.Allow, c.wantSubAllow)
			}
			if sd.ClearAll != c.wantClearAll {
				t.Fatalf("clearAll=%v want %v", sd.ClearAll, c.wantClearAll)
			}
			if strings.Join(sd.Clear, ",") != strings.Join(c.wantClearList, ",") {
				t.Fatalf("clear=%v want %v", sd.Clear, c.wantClearList)
			}
		})
	}
}

func TestDefaultAllowPosture(t *testing.T) {
	auth := &RuleAuthorizer{DefaultAllow: true}
	if !auth.Publish(Identity{Key: "x"}, "anything").Allow {
		t.Fatal("default_allow=true should permit unmatched publish")
	}
	// Even with default allow, an explicit deny rule wins when placed first.
	auth.Rules = []TopicRule{{Topics: []string{"admin.*"}, Allow: false}}
	if auth.Publish(Identity{Key: "x"}, "admin.reset").Allow {
		t.Fatal("explicit deny rule should override default_allow")
	}
}

// TestMultiTopicClearanceIntersection verifies a subscription spanning topics
// with different clearance gets the least (fail-closed) clearance.
func TestMultiTopicClearanceIntersection(t *testing.T) {
	auth := &RuleAuthorizer{
		Rules: []TopicRule{
			{Topics: []string{"a"}, Allow: true, Clear: []string{"pii", "tainted"}},
			{Topics: []string{"b"}, Allow: true, Clear: []string{"pii"}},
		},
	}
	b := New(Options{Authorizer: auth})
	sub, err := b.Subscribe(Identity{Key: "u"}, SubOptions{Topics: []string{"a", "b"}})
	if err != nil {
		t.Fatal(err)
	}
	defer sub.Close()
	// Effective clearance is {pii} (intersection). A "tainted" event on topic
	// "a" must NOT be delivered.
	if sub.accepts(&Event{Topic: "a", Labels: []string{"tainted"}}) {
		t.Fatal("intersection clearance should exclude tainted")
	}
	if !sub.accepts(&Event{Topic: "a", Labels: []string{"pii"}}) {
		t.Fatal("pii is in the intersection and should be accepted")
	}
	if sub.accepts(&Event{Topic: "a", Labels: []string{"pii", "tainted"}}) {
		t.Fatal("an event needs ALL its labels cleared")
	}
}

// TestAuditIntegration checks every decision lands in the hash-chained ledger.
func TestAuditIntegration(t *testing.T) {
	var buf bytes.Buffer
	log := policy.NewAuditLog(&buf, func() string { return "t" })
	auth := &RuleAuthorizer{Rules: []TopicRule{{Peers: []string{"pubkey:ok"}, Topics: []string{"t"}, Allow: true, ClearAll: true}}}
	b := New(Options{Authorizer: auth, Audit: log})

	_, _ = b.Publish(id("ok"), "t", nil, nil)     // allow
	_, _ = b.Publish(id("no"), "t", nil, nil)     // deny
	_, _ = b.Subscribe(id("no"), SubOptions{Topics: []string{"t"}}) // deny

	out := buf.String()
	for _, want := range []string{`"backend":"pubsub"`, `"method":"pubsub/publish"`, `"decision":"allow"`, `"decision":"deny"`, `"method":"pubsub/subscribe"`} {
		if !strings.Contains(out, want) {
			t.Fatalf("audit missing %q in:\n%s", want, out)
		}
	}
	if strings.Count(out, "\n") < 3 {
		t.Fatalf("expected >=3 audit records, got:\n%s", out)
	}
}
