package pubsub

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

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
	b := New(Options{Authorizer: AllowAll{}, Limits: Limits{SubQueue: 8, Retain: 4096}})
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
