package pubsub

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"meshmcp/policy"
)

// TestRetainedMessages verifies a retained publish becomes the topic's
// last-value, delivered to a subscriber that connects afterward.
func TestRetainedMessages(t *testing.T) {
	b := New(Options{Authorizer: AllowAll{}})
	defer b.Close()

	b.PublishOpts(id("p"), "state.temp", json.RawMessage(`21`), PublishOptions{Retain: true})
	b.Publish(id("p"), "state.temp", json.RawMessage(`22`), nil) // not retained: doesn't update last-value
	b.PublishOpts(id("p"), "state.temp", json.RawMessage(`23`), PublishOptions{Retain: true})

	sub, err := b.Subscribe(id("s"), SubOptions{Topics: []string{"state.*"}})
	if err != nil {
		t.Fatal(err)
	}
	defer sub.Close()
	if ev := recv(t, sub); string(ev.Payload) != "23" {
		t.Fatalf("retained value = %s, want 23 (latest retained)", ev.Payload)
	}
}

// TestEmitFederated verifies a mirrored event preserves the original publisher,
// carries the source broker in Origin (the loop guard), and is delivered — and
// that a normal publish has no Origin (so it *would* be mirrored).
func TestEmitFederated(t *testing.T) {
	b := New(Options{Authorizer: AllowAll{}})
	defer b.Close()
	sub, _ := b.Subscribe(id("s"), SubOptions{Topics: []string{"t"}})
	defer sub.Close()

	if ev, _ := b.Publish(id("orig"), "t", json.RawMessage(`1`), nil); ev.Origin != "" {
		t.Fatalf("a normal publish must have empty Origin, got %q", ev.Origin)
	}
	recv(t, sub) // drain the normal publish

	ev, err := b.EmitFederated("t", json.RawMessage(`2`), nil, "orig-key", "broker-A")
	if err != nil {
		t.Fatal(err)
	}
	if ev.Origin != "broker-A" || ev.Publisher != "orig-key" {
		t.Fatalf("federated event: %+v", ev)
	}
	got := recv(t, sub)
	if got.Origin != "broker-A" || got.Publisher != "orig-key" {
		t.Fatalf("delivered federated event: %+v", got)
	}
	// The non-empty Origin is exactly what the federation runner checks to avoid
	// re-mirroring (loop prevention across a bidirectional federation).
}

// TestBinaryPayload verifies a base64-encoded binary payload round-trips with
// its encoding hint.
func TestBinaryPayload(t *testing.T) {
	b := New(Options{Authorizer: AllowAll{}})
	defer b.Close()
	sub, _ := b.Subscribe(id("s"), SubOptions{Topics: []string{"blob"}})
	defer sub.Close()

	raw := []byte{0x00, 0x01, 0x02, 0xff, 0xfe}
	b64, _ := json.Marshal(base64.StdEncoding.EncodeToString(raw))
	if _, err := b.PublishOpts(id("p"), "blob", b64, PublishOptions{Encoding: "base64"}); err != nil {
		t.Fatal(err)
	}
	got := recv(t, sub)
	if got.Enc != "base64" {
		t.Fatalf("encoding hint = %q, want base64", got.Enc)
	}
	var s string
	json.Unmarshal(got.Payload, &s)
	dec, _ := base64.StdEncoding.DecodeString(s)
	if !bytes.Equal(dec, raw) {
		t.Fatal("binary payload did not round-trip")
	}
}

// fakeClock is a settable clock for deterministic time-dependent tests.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *fakeClock { return &fakeClock{t: time.Unix(1_700_000_000, 0).UTC()} }
func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}
func (c *fakeClock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func id(key string) Identity { return Identity{Key: key, FQDN: key + ".netbird.cloud"} }

func mustPub(t *testing.T, b *Broker, who, topic string, body any, labels ...string) *Event {
	t.Helper()
	raw, _ := json.Marshal(body)
	ev, err := b.Publish(id(who), topic, raw, labels)
	if err != nil {
		t.Fatalf("publish %q by %s: %v", topic, who, err)
	}
	return ev
}

// recv reads one event or fails after a timeout (so a wrongly-empty stream
// fails fast instead of hanging the suite).
func recv(t *testing.T, s *Subscription) *Event {
	t.Helper()
	select {
	case ev, ok := <-s.C():
		if !ok {
			t.Fatal("subscription closed unexpectedly")
		}
		return ev
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for event")
		return nil
	}
}

// expectNone asserts no event arrives within a short window.
func expectNone(t *testing.T, s *Subscription) {
	t.Helper()
	select {
	case ev, ok := <-s.C():
		if ok {
			t.Fatalf("expected no event, got %q seq %d labels %v", ev.Topic, ev.Seq, ev.Labels)
		}
	case <-time.After(150 * time.Millisecond):
	}
}

func TestPublishSubscribeBasic(t *testing.T) {
	b := New(Options{Authorizer: AllowAll{}})
	sub, err := b.Subscribe(id("alice"), SubOptions{Topics: []string{"news.*"}})
	if err != nil {
		t.Fatal(err)
	}
	defer sub.Close()

	mustPub(t, b, "bob", "news.tech", map[string]string{"h": "hi"})
	ev := recv(t, sub)
	if ev.Topic != "news.tech" || ev.Publisher != "bob" || ev.Seq != 1 {
		t.Fatalf("unexpected event: %+v", ev)
	}
	var got map[string]string
	if err := json.Unmarshal(ev.Payload, &got); err != nil || got["h"] != "hi" {
		t.Fatalf("payload: %v / %v", got, err)
	}
	// A publish on a non-matching topic is not delivered.
	mustPub(t, b, "bob", "sports.nba", nil)
	expectNone(t, sub)
}

func TestDenyByDefault(t *testing.T) {
	auth := &RuleAuthorizer{ // DefaultAllow false
		Rules: []TopicRule{{Peers: []string{"pubkey:alice"}, Topics: []string{"news.*"}, Allow: true, ClearAll: true}},
	}
	b := New(Options{Authorizer: auth})

	if _, err := b.Publish(id("mallory"), "news.tech", nil, nil); err == nil {
		t.Fatal("expected publish denial for unauthorized peer")
	} else if !strings.Contains(err.Error(), "denied") {
		t.Fatalf("want deny error, got %v", err)
	}
	if _, err := b.Subscribe(id("mallory"), SubOptions{Topics: []string{"news.tech"}}); err == nil {
		t.Fatal("expected subscribe denial for unauthorized peer")
	}
	// Authorized peer, wrong topic → still denied (deny by default).
	if _, err := b.Publish(id("alice"), "secret.leak", nil, nil); err == nil {
		t.Fatal("expected deny on ungranted topic")
	}
	// Authorized peer and topic → allowed.
	if _, err := b.Publish(id("alice"), "news.tech", nil, nil); err != nil {
		t.Fatalf("authorized publish should pass: %v", err)
	}
}

func TestOrderingAndHashChain(t *testing.T) {
	b := New(Options{Authorizer: AllowAll{}})
	sub, _ := b.Subscribe(id("a"), SubOptions{Topics: []string{"t"}})
	defer sub.Close()

	const n = 50
	for i := 0; i < n; i++ {
		mustPub(t, b, "p", "t", i)
	}
	for i := 0; i < n; i++ {
		ev := recv(t, sub)
		if ev.Seq != uint64(i+1) {
			t.Fatalf("out of order: got seq %d want %d", ev.Seq, i+1)
		}
	}
	// The retained window is a valid, tamper-evident chain.
	events := b.Retained()
	if len(events) != n {
		t.Fatalf("retained %d want %d", len(events), n)
	}
	if err := VerifyChain(events); err != nil {
		t.Fatalf("chain should verify: %v", err)
	}
	// Tampering breaks it.
	events[10].Payload = json.RawMessage(`"tampered"`)
	if err := VerifyChain(events); err == nil {
		t.Fatal("tampered chain should fail verification")
	}
	// Reordering breaks it.
	events = b.Retained()
	events[3], events[4] = events[4], events[3]
	if err := VerifyChain(events); err == nil {
		t.Fatal("reordered chain should fail verification")
	}
}

func TestBackpressureDropOldest(t *testing.T) {
	b := New(Options{Authorizer: AllowAll{}, Limits: Limits{SubQueue: 4}})
	sub, _ := b.Subscribe(id("a"), SubOptions{Topics: []string{"t"}, Backpressure: DropOldest})
	defer sub.Close()

	// Publish well past the queue depth without reading.
	const n = 20
	for i := 0; i < n; i++ {
		mustPub(t, b, "p", "t", i)
	}
	if d := sub.Dropped(); d != n-4 {
		t.Fatalf("dropped %d want %d", d, n-4)
	}
	// The buffer holds the most recent SubQueue events, in order.
	var seqs []uint64
	for {
		select {
		case ev := <-sub.C():
			seqs = append(seqs, ev.Seq)
			continue
		default:
		}
		break
	}
	if len(seqs) != 4 {
		t.Fatalf("buffered %d want 4", len(seqs))
	}
	if seqs[0] != uint64(n-3) || seqs[3] != uint64(n) {
		t.Fatalf("buffer window wrong: %v", seqs)
	}
}

func TestBackpressureDisconnect(t *testing.T) {
	b := New(Options{Authorizer: AllowAll{}, Limits: Limits{SubQueue: 4}})
	sub, _ := b.Subscribe(id("a"), SubOptions{Topics: []string{"t"}, Backpressure: Disconnect})

	for i := 0; i < 20; i++ {
		if _, err := b.Publish(id("p"), "t", nil, nil); err != nil {
			t.Fatalf("publish should still succeed even as a subscriber disconnects: %v", err)
		}
	}
	// The overflowing subscription must be closed.
	select {
	case <-sub.Done():
	case <-time.After(time.Second):
		t.Fatal("disconnect-policy subscription should have closed")
	}
	if b.SubCount() != 0 {
		t.Fatalf("broker still has %d subs after disconnect", b.SubCount())
	}
}

func TestRateLimit(t *testing.T) {
	clk := newClock()
	b := New(Options{Authorizer: AllowAll{}, Now: clk.now, Limits: Limits{PublishRate: 10, PublishBurst: 3}})

	// Burst of 3 allowed.
	for i := 0; i < 3; i++ {
		if _, err := b.Publish(id("p"), "t", nil, nil); err != nil {
			t.Fatalf("burst publish %d should pass: %v", i, err)
		}
	}
	// 4th is rate limited (bucket empty, no time advanced).
	if _, err := b.Publish(id("p"), "t", nil, nil); err == nil {
		t.Fatal("expected rate limit after burst")
	}
	// Advance 200ms → 10 tok/s refills ~2 tokens.
	clk.add(200 * time.Millisecond)
	for i := 0; i < 2; i++ {
		if _, err := b.Publish(id("p"), "t", nil, nil); err != nil {
			t.Fatalf("refilled publish %d should pass: %v", i, err)
		}
	}
	if _, err := b.Publish(id("p"), "t", nil, nil); err == nil {
		t.Fatal("expected rate limit again after refill spent")
	}
	// A different publisher has its own bucket.
	if _, err := b.Publish(id("other"), "t", nil, nil); err != nil {
		t.Fatalf("independent publisher bucket should allow: %v", err)
	}
}

// TestRateLimitBeforeAuth verifies the limiter is charged ahead of
// authorization and audit, so a connected-but-unauthorized peer flooding
// rejected publishes cannot amplify audit writes: once the bucket empties,
// further attempts return ErrRateLimited and produce no new ledger records.
func TestRateLimitBeforeAuth(t *testing.T) {
	clk := newClock()
	var buf bytes.Buffer
	audit := policy.NewAuditLog(&buf, func() string { return "t" })
	auth := &RuleAuthorizer{} // deny by default: this peer is unauthorized
	b := New(Options{Authorizer: auth, Audit: audit, Now: clk.now, Limits: Limits{PublishRate: 5, PublishBurst: 3}})

	var denied, limited int
	for i := 0; i < 100; i++ {
		_, err := b.Publish(id("flood"), "t", nil, nil)
		switch {
		case errors.Is(err, ErrRateLimited):
			limited++
		case errors.Is(err, ErrDenied):
			denied++
		default:
			t.Fatalf("unexpected err: %v", err)
		}
	}
	// Only the burst (3) reaches authorization and is audited as a denial; the
	// rest are rate-limited and NOT audited.
	if denied != 3 {
		t.Fatalf("audited denials = %d, want 3 (burst)", denied)
	}
	if limited != 97 {
		t.Fatalf("rate-limited = %d, want 97", limited)
	}
	if n := strings.Count(buf.String(), "\n"); n != 3 {
		t.Fatalf("audit records = %d, want 3 (flood must not amplify audit)", n)
	}
}

// TestEmptyIdentityDenied verifies an unproven caller (empty WireGuard key) is
// refused even by an otherwise-permissive authorizer — identity is never claimed.
func TestEmptyIdentityDenied(t *testing.T) {
	b := New(Options{Authorizer: AllowAll{}}) // would allow anything with an identity
	if _, err := b.Publish(Identity{Key: ""}, "t", nil, nil); !errors.Is(err, ErrDenied) {
		t.Fatalf("empty-identity publish: got %v want ErrDenied", err)
	}
	if _, err := b.Subscribe(Identity{Key: ""}, SubOptions{Topics: []string{"t"}}); !errors.Is(err, ErrDenied) {
		t.Fatalf("empty-identity subscribe: got %v want ErrDenied", err)
	}
	// A real identity still works.
	if _, err := b.Publish(id("real"), "t", nil, nil); err != nil {
		t.Fatalf("proven identity should pass: %v", err)
	}
}

// TestSubscribeAuditSingleRecord verifies a wide subscribe writes exactly one
// audit record, not one per topic (no ledger amplification).
func TestSubscribeAuditSingleRecord(t *testing.T) {
	var buf bytes.Buffer
	audit := policy.NewAuditLog(&buf, func() string { return "t" })
	b := New(Options{Authorizer: AllowAll{}, Audit: audit})
	sub, err := b.Subscribe(id("a"), SubOptions{Topics: []string{"a.*", "b.*", "c.*", "d.*"}})
	if err != nil {
		t.Fatal(err)
	}
	defer sub.Close()
	if n := strings.Count(buf.String(), `"method":"pubsub/subscribe"`); n != 1 {
		t.Fatalf("subscribe audit records = %d, want 1", n)
	}
}

// TestSubscribeRateLimited verifies subscribe is rate-limited before auth/audit
// like publish, so a peer flooding denied subscribes cannot flood the ledger.
func TestSubscribeRateLimited(t *testing.T) {
	var buf bytes.Buffer
	audit := policy.NewAuditLog(&buf, func() string { return "t" })
	auth := &RuleAuthorizer{} // deny by default
	b := New(Options{Authorizer: auth, Audit: audit, Limits: Limits{PublishRate: 5, PublishBurst: 3}})

	var limited, denied int
	for i := 0; i < 50; i++ {
		_, err := b.Subscribe(id("flood"), SubOptions{Topics: []string{"t"}})
		switch {
		case errors.Is(err, ErrRateLimited):
			limited++
		case errors.Is(err, ErrDenied):
			denied++
		default:
			t.Fatalf("unexpected err: %v", err)
		}
	}
	if denied != 3 || limited != 47 {
		t.Fatalf("denied=%d limited=%d, want 3/47", denied, limited)
	}
	if n := strings.Count(buf.String(), "\n"); n != 3 {
		t.Fatalf("audit records=%d want 3 (subscribe flood must not amplify audit)", n)
	}
}

// TestMaxSubsPerPeer verifies one identity cannot pin every global slot.
func TestMaxSubsPerPeer(t *testing.T) {
	b := New(Options{Authorizer: AllowAll{}, Limits: Limits{MaxSubsPerPeer: 2, PublishRate: -1}})
	s1, _ := b.Subscribe(id("a"), SubOptions{Topics: []string{"x"}})
	s2, _ := b.Subscribe(id("a"), SubOptions{Topics: []string{"y"}})
	if _, err := b.Subscribe(id("a"), SubOptions{Topics: []string{"z"}}); !errors.Is(err, ErrTooMany) {
		t.Fatalf("per-peer cap: got %v want ErrTooMany", err)
	}
	// A different identity is unaffected.
	if _, err := b.Subscribe(id("b"), SubOptions{Topics: []string{"z"}}); err != nil {
		t.Fatalf("other peer should subscribe: %v", err)
	}
	// Freeing a slot lets the first peer subscribe again.
	s1.Close()
	s3, err := b.Subscribe(id("a"), SubOptions{Topics: []string{"z"}})
	if err != nil {
		t.Fatalf("after close should subscribe: %v", err)
	}
	s2.Close()
	s3.Close()
}

func TestLabelCap(t *testing.T) {
	b := New(Options{Authorizer: AllowAll{}, Limits: Limits{MaxLabels: 3, MaxTopicLen: 8}})
	if _, err := b.Publish(id("p"), "t", nil, []string{"a", "b", "c"}); err != nil {
		t.Fatalf("within label cap should pass: %v", err)
	}
	if _, err := b.Publish(id("p"), "t", nil, []string{"a", "b", "c", "d"}); !errors.Is(err, ErrBadTopic) {
		t.Fatalf("over label count: got %v want ErrBadTopic", err)
	}
	if _, err := b.Publish(id("p"), "t", nil, []string{"waytoolonglabel"}); !errors.Is(err, ErrBadTopic) {
		t.Fatalf("over-long label: got %v want ErrBadTopic", err)
	}
}

// TestEmitInternal verifies gateway-side internal emission bypasses per-topic
// publish authorization (and rate limiting) while normal publishes stay
// governed, and that internal events are sealed into the same hash chain and
// delivered to cleared subscribers.
func TestEmitInternal(t *testing.T) {
	// Only "sub" may subscribe to gateway.*; nobody has a publish grant.
	auth := &RuleAuthorizer{Rules: []TopicRule{
		{Peers: []string{"pubkey:sub"}, Topics: []string{"gateway.*"}, Allow: true, ClearAll: true},
	}}
	b := New(Options{Authorizer: auth})
	defer b.Close()

	sub, err := b.Subscribe(Identity{Key: "sub"}, SubOptions{Topics: []string{"gateway.*"}})
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	defer sub.Close()

	// A normal publish by an ungranted peer is denied...
	if _, err := b.Publish(Identity{Key: "other"}, "gateway.deny", nil, nil); !errors.Is(err, ErrDenied) {
		t.Fatalf("normal publish should be denied: %v", err)
	}
	// ...but internal emission from the gateway operator succeeds.
	ev, err := b.EmitInternal("gateway", "gateway.deny", json.RawMessage(`{"tool":"x"}`), nil)
	if err != nil {
		t.Fatalf("EmitInternal: %v", err)
	}
	if ev.Publisher != "gateway" || ev.Topic != "gateway.deny" {
		t.Fatalf("unexpected internal event: %+v", ev)
	}
	got := recv(t, sub)
	if got.Seq != ev.Seq || got.Publisher != "gateway" {
		t.Fatalf("subscriber got wrong event: %+v", got)
	}
	if err := VerifyChain(b.Retained()); err != nil {
		t.Fatalf("chain must verify after internal emit: %v", err)
	}
}

// TestCapabilityGrants verifies a signed capability upgrades a default-deny to
// allow for the right subject/audience/topic, and never for the wrong ones or
// over an explicit deny.
func TestCapabilityGrants(t *testing.T) {
	signer, err := policy.GenerateSigner()
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := policy.NewCapabilityVerifier([]string{signer.PubKeyHex()}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	// Deny by default, with one explicit deny on secret.*.
	auth := &RuleAuthorizer{Rules: []TopicRule{{Topics: []string{"secret.*"}, Allow: false}}}
	b := New(Options{Authorizer: auth, Name: "bus1", Capabilities: verifier})
	defer b.Close()

	mint := func(subject, audience string, topics []string) string {
		tok, err := signer.IssueCapability(policy.CapabilityClaims{
			Subject: subject, Audience: audience, Tools: topics,
			ExpiresAt: time.Now().Add(time.Hour).Unix(),
		}, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}

	// No capability → denied.
	if _, err := b.Subscribe(id("alice"), SubOptions{Topics: []string{"legal.contracts"}}); !errors.Is(err, ErrDenied) {
		t.Fatalf("no-capability subscribe: got %v want ErrDenied", err)
	}

	// A valid grant lets alice subscribe and publish legal.*.
	tok := mint("alice", "bus1", []string{"legal.*"})
	sub, err := b.Subscribe(id("alice"), SubOptions{Topics: []string{"legal.contracts"}, Capability: tok})
	if err != nil {
		t.Fatalf("capability subscribe should pass: %v", err)
	}
	defer sub.Close()
	if _, err := b.PublishCap(id("alice"), "legal.contracts", nil, nil, tok); err != nil {
		t.Fatalf("capability publish should pass: %v", err)
	}
	if ev := recv(t, sub); ev.Topic != "legal.contracts" {
		t.Fatalf("delivered event: %+v", ev)
	}

	// Wrong subject, wrong topic, wrong audience — all refused.
	if _, err := b.Subscribe(id("alice"), SubOptions{Topics: []string{"legal.x"}, Capability: mint("mallory", "bus1", []string{"legal.*"})}); !errors.Is(err, ErrDenied) {
		t.Fatal("capability bound to another subject must not authorize alice")
	}
	if _, err := b.Subscribe(id("alice"), SubOptions{Topics: []string{"legal.x"}, Capability: mint("alice", "bus1", []string{"finance.*"})}); !errors.Is(err, ErrDenied) {
		t.Fatal("capability for a different topic must not authorize legal.x")
	}
	if _, err := b.Subscribe(id("alice"), SubOptions{Topics: []string{"legal.x"}, Capability: mint("alice", "other-bus", []string{"legal.*"})}); !errors.Is(err, ErrDenied) {
		t.Fatal("capability for a different audience must not authorize here")
	}
	// A capability cannot override an explicit deny (secret.*).
	if _, err := b.Subscribe(id("alice"), SubOptions{Topics: []string{"secret.keys"}, Capability: mint("alice", "bus1", []string{"secret.*"})}); !errors.Is(err, ErrDenied) {
		t.Fatal("capability must not override an explicit allow:false")
	}
}

func TestResourceCaps(t *testing.T) {
	b := New(Options{Authorizer: AllowAll{}, Limits: Limits{MaxTopicsPerSub: 2, MaxSubs: 2, MaxTopicLen: 8}})

	if _, err := b.Subscribe(id("a"), SubOptions{Topics: []string{"a", "b", "c"}}); err == nil {
		t.Fatal("expected too-many-topics error")
	}
	if _, err := b.Subscribe(id("a"), SubOptions{Topics: []string{"toolongtopicname"}}); err == nil {
		t.Fatal("expected topic-too-long error")
	}
	if _, err := b.Subscribe(id("a"), SubOptions{Topics: nil}); err == nil {
		t.Fatal("expected empty-topics error")
	}
	if _, err := b.Publish(id("p"), "with\nnewline", nil, nil); err == nil {
		t.Fatal("expected control-char topic rejection")
	}
	// MaxSubs.
	s1, _ := b.Subscribe(id("a"), SubOptions{Topics: []string{"x"}})
	s2, _ := b.Subscribe(id("a"), SubOptions{Topics: []string{"y"}})
	if _, err := b.Subscribe(id("a"), SubOptions{Topics: []string{"z"}}); err == nil {
		t.Fatal("expected max-subs error")
	}
	s1.Close()
	if _, err := b.Subscribe(id("a"), SubOptions{Topics: []string{"z"}}); err != nil {
		t.Fatalf("subscribe should succeed after a slot frees: %v", err)
	}
	s2.Close()
}

func TestMaxPayloadBytes(t *testing.T) {
	b := New(Options{Authorizer: AllowAll{}, Limits: Limits{MaxPayloadBytes: 16}})
	if _, err := b.Publish(id("p"), "t", json.RawMessage(`"0123456789"`), nil); err != nil {
		t.Fatalf("payload within cap should pass: %v", err)
	}
	big := json.RawMessage(`"` + strings.Repeat("x", 64) + `"`)
	_, err := b.Publish(id("p"), "t", big, nil)
	if err == nil || !errors.Is(err, ErrPayloadTooLarge) {
		t.Fatalf("oversized payload: got %v want ErrPayloadTooLarge", err)
	}
	// The rejected publish must not advance the sequence or retention.
	if b.Seq() != 1 {
		t.Fatalf("rejected publish advanced seq to %d", b.Seq())
	}
}

func TestLabelContainment(t *testing.T) {
	auth := &RuleAuthorizer{
		Rules: []TopicRule{
			{Peers: []string{"pubkey:trusted"}, Topics: []string{"*"}, Allow: true, ClearAll: true},
			{Topics: []string{"web.*"}, Allow: true, Taint: true}, // publishes tainted; subs cleared for nothing
			{Topics: []string{"*"}, Allow: true, ClearAll: true},
		},
	}
	b := New(Options{Authorizer: auth})

	trusted, _ := b.Subscribe(id("trusted"), SubOptions{Topics: []string{"web.*"}})
	defer trusted.Close()
	untrusted, _ := b.Subscribe(id("untrusted"), SubOptions{Topics: []string{"web.*"}})
	defer untrusted.Close()

	ev := mustPub(t, b, "crawler", "web.fetch", "untrusted content")
	found := false
	for _, l := range ev.Labels {
		if l == "tainted" {
			found = true
		}
	}
	if !found {
		t.Fatalf("event should be tainted at emit: %v", ev.Labels)
	}
	// The cleared subscriber receives it; the uncleared one does not.
	got := recv(t, trusted)
	if got.Seq != ev.Seq {
		t.Fatalf("trusted got wrong event: %+v", got)
	}
	expectNone(t, untrusted)
}

func TestPublisherDeclaredLabelsAddContainment(t *testing.T) {
	b := New(Options{Authorizer: AllowAll{}}) // AllowAll clears everything
	// A subscriber restricted to only unlabeled events.
	auth := &RuleAuthorizer{Rules: []TopicRule{{Topics: []string{"*"}, Allow: true}}} // clear nothing
	restricted := New(Options{Authorizer: auth})

	// On the open broker, an event with a publisher-declared label still
	// reaches the fully-cleared subscriber.
	open, _ := b.Subscribe(id("a"), SubOptions{Topics: []string{"t"}})
	defer open.Close()
	mustPub(t, b, "p", "t", nil, "pii")
	if got := recv(t, open); len(got.Labels) != 1 || got.Labels[0] != "pii" {
		t.Fatalf("declared label lost: %v", got.Labels)
	}

	// On the restricted broker, the same labeled event is contained away.
	sub, _ := restricted.Subscribe(id("a"), SubOptions{Topics: []string{"t"}})
	defer sub.Close()
	mustPub(t, restricted, "p", "t", nil, "pii")
	expectNone(t, sub)
}

func TestReplaySince(t *testing.T) {
	b := New(Options{Authorizer: AllowAll{}, Limits: Limits{Retain: 5}})
	for i := 0; i < 8; i++ {
		mustPub(t, b, "p", "t", i)
	}
	// Retention holds only the last 5 (seq 4..8). Ask for events after seq 6.
	sub, _ := b.Subscribe(id("a"), SubOptions{Topics: []string{"t"}, Since: 6})
	defer sub.Close()
	for _, want := range []uint64{7, 8} {
		if ev := recv(t, sub); ev.Seq != want {
			t.Fatalf("replay seq %d want %d", ev.Seq, want)
		}
	}
	if sub.Truncated() {
		t.Fatal("replay after seq 6 should not be truncated (retention covers it)")
	}

	// Asking from before the retained window is truncated (surfaced, not silent).
	sub2, _ := b.Subscribe(id("a"), SubOptions{Topics: []string{"t"}, Since: 1})
	defer sub2.Close()
	if !sub2.Truncated() {
		t.Fatal("replay from seq 1 should be truncated: seq 1..3 aged out")
	}
	// It still delivers what it has (seq 4..8), then live events continue.
	if ev := recv(t, sub2); ev.Seq != 4 {
		t.Fatalf("oldest retained replay seq %d want 4", ev.Seq)
	}
}

// TestFanoutIsolation asserts a stalled subscriber never blocks the fan-out
// loop or a concurrently-draining subscriber. Under DropOldest the draining
// reader may see gaps, but delivery stays strictly monotonic and it still
// reaches the final event; the stalled subscriber absorbs the pressure as
// drops rather than backpressuring the publisher.
func TestFanoutIsolation(t *testing.T) {
	b := New(Options{Authorizer: AllowAll{}, Limits: Limits{SubQueue: 4}})
	reader, _ := b.Subscribe(id("reader"), SubOptions{Topics: []string{"t"}, Backpressure: DropOldest})
	defer reader.Close()
	stalled, _ := b.Subscribe(id("stalled"), SubOptions{Topics: []string{"t"}, Backpressure: DropOldest})
	defer stalled.Close()

	const n = 200
	sawFinal := make(chan struct{})
	go func() {
		var last uint64
		for ev := range reader.C() {
			if ev.Seq <= last {
				t.Errorf("delivery not monotonic: seq %d after %d", ev.Seq, last)
				return
			}
			last = ev.Seq
			if ev.Seq == n {
				close(sawFinal)
				return
			}
		}
	}()

	// The publish loop must complete promptly despite `stalled` never draining.
	done := make(chan struct{})
	go func() {
		for i := 0; i < n; i++ {
			mustPub(t, b, "p", "t", i)
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("publish loop stalled — a slow subscriber blocked fan-out")
	}

	select {
	case <-sawFinal:
	case <-time.After(2 * time.Second):
		t.Fatal("draining reader never reached the final event")
	}
	if stalled.Dropped() == 0 {
		t.Fatal("stalled subscriber should have dropped events")
	}
}

func TestCloseBroker(t *testing.T) {
	b := New(Options{Authorizer: AllowAll{}})
	sub, _ := b.Subscribe(id("a"), SubOptions{Topics: []string{"t"}})
	b.Close()
	select {
	case <-sub.Done():
	case <-time.After(time.Second):
		t.Fatal("Close should close open subscriptions")
	}
	if _, err := b.Publish(id("p"), "t", nil, nil); err != ErrClosed {
		t.Fatalf("publish after close: got %v want ErrClosed", err)
	}
	if _, err := b.Subscribe(id("a"), SubOptions{Topics: []string{"t"}}); err != ErrClosed {
		t.Fatalf("subscribe after close: got %v want ErrClosed", err)
	}
	// Unsubscribe after close is a no-op (no panic).
	sub.Close()
}

func TestUnsubscribeIdempotent(t *testing.T) {
	b := New(Options{Authorizer: AllowAll{}})
	sub, _ := b.Subscribe(id("a"), SubOptions{Topics: []string{"t"}})
	sub.Close()
	sub.Close() // must not panic or double-close
	mustPub(t, b, "p", "t", nil)
	if b.SubCount() != 0 {
		t.Fatalf("sub count %d want 0", b.SubCount())
	}
}

// TestConcurrentFuzz drives the broker from many goroutines to shake out data
// races (run with -race). It asserts the sequence is exactly the number of
// successful publishes and the retained chain verifies.
func TestConcurrentFuzz(t *testing.T) {
	// PublishRate: -1 opts out of rate limiting — this test exercises raw
	// throughput and ordering, not the limiter.
	b := New(Options{Authorizer: AllowAll{}, Limits: Limits{SubQueue: 8, Retain: 4096, PublishRate: -1}})
	const (
		publishers = 8
		perPub     = 500
		readers    = 6
	)
	// Readers that continuously subscribe, drain briefly, and unsubscribe.
	var rwg sync.WaitGroup
	stop := make(chan struct{})
	for r := 0; r < readers; r++ {
		rwg.Add(1)
		go func(r int) {
			defer rwg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				sub, err := b.Subscribe(id(fmt.Sprintf("r%d", r)), SubOptions{Topics: []string{"*"}, Backpressure: DropOldest})
				if err != nil {
					return
				}
				for j := 0; j < 20; j++ {
					select {
					case <-sub.C():
					case <-time.After(time.Millisecond):
					}
				}
				sub.Close()
			}
		}(r)
	}

	var pwg sync.WaitGroup
	for p := 0; p < publishers; p++ {
		pwg.Add(1)
		go func(p int) {
			defer pwg.Done()
			for j := 0; j < perPub; j++ {
				body, _ := json.Marshal(j)
				if _, err := b.Publish(id(fmt.Sprintf("p%d", p)), "topic", body, nil); err != nil {
					t.Errorf("publish: %v", err)
					return
				}
			}
		}(p)
	}
	pwg.Wait()
	close(stop)
	rwg.Wait()

	if got := b.Seq(); got != publishers*perPub {
		t.Fatalf("seq %d want %d", got, publishers*perPub)
	}
	if err := VerifyChain(b.Retained()); err != nil {
		t.Fatalf("retained chain must verify after concurrent load: %v", err)
	}
	b.Close()
}
