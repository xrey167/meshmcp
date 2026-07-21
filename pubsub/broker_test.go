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

	ev, err := b.EmitFederated("t", json.RawMessage(`2`), nil, "orig-key", "broker-A", false, false, "")
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

// TestRetainedMapBounded verifies the retained last-value map cannot grow
// without bound: once MaxRetainedTopics distinct topics are retained, a new
// topic is not added (but an existing topic still updates). Prevents a publisher
// from exhausting memory by retaining across an unbounded topic space.
func TestRetainedMapBounded(t *testing.T) {
	b := New(Options{Authorizer: AllowAll{}, Limits: Limits{MaxRetainedTopics: 3}})
	defer b.Close()

	for i := 0; i < 10; i++ {
		b.PublishOpts(id("p"), fmt.Sprintf("topic.%d", i), json.RawMessage(`1`), PublishOptions{Retain: true})
	}
	b.mu.Lock()
	n := len(b.retained)
	b.mu.Unlock()
	if n != 3 {
		t.Fatalf("retained map holds %d topics, want it capped at 3", n)
	}

	// An already-retained topic still updates in place (does not count as new).
	b.PublishOpts(id("p"), "topic.0", json.RawMessage(`99`), PublishOptions{Retain: true})
	b.mu.Lock()
	ev, ok := b.retained["topic.0"]
	n = len(b.retained)
	b.mu.Unlock()
	if !ok || string(ev.Payload) != "99" || n != 3 {
		t.Fatalf("existing retained topic must update in place; map=%d ev=%v", n, ev)
	}
}

// TestRetainedDeliveredInSeqOrder verifies retained last-values are delivered to
// a fresh subscriber in ascending sequence order (not the map's random order),
// so a consumer that reconstructs state sees a deterministic ordering.
func TestRetainedDeliveredInSeqOrder(t *testing.T) {
	b := New(Options{Authorizer: AllowAll{}})
	defer b.Close()
	// Retain several topics; their sequences increase in publish order.
	for i := 0; i < 8; i++ {
		b.PublishOpts(id("p"), fmt.Sprintf("s.%d", i), json.RawMessage(`1`), PublishOptions{Retain: true})
	}
	sub, err := b.Subscribe(id("s"), SubOptions{Topics: []string{"s.*"}})
	if err != nil {
		t.Fatal(err)
	}
	defer sub.Close()
	var last uint64
	for i := 0; i < 8; i++ {
		ev := recv(t, sub)
		if ev.Seq <= last {
			t.Fatalf("retained delivered out of order: seq %d after %d", ev.Seq, last)
		}
		last = ev.Seq
	}
}

// TestEncodingHintBounded verifies the per-event encoding hint is length-capped
// like a label — it is retained and hashed, so an unbounded hint would bypass
// the payload×retain memory bound.
func TestEncodingHintBounded(t *testing.T) {
	b := New(Options{Authorizer: AllowAll{}})
	defer b.Close()
	long := strings.Repeat("x", maxEncodingLen+1)
	if _, err := b.PublishOpts(id("p"), "t", json.RawMessage(`1`), PublishOptions{Encoding: long}); !errors.Is(err, ErrBadTopic) {
		t.Fatalf("over-long encoding hint: got %v, want ErrBadTopic", err)
	}
	// A normal-length hint is accepted.
	if _, err := b.PublishOpts(id("p"), "t", json.RawMessage(`1`), PublishOptions{Encoding: "base64"}); err != nil {
		t.Fatalf("valid encoding hint rejected: %v", err)
	}
}

// TestFederationRespectsLocalPolicy verifies a mirrored event is re-authorized
// against THIS broker's policy: an explicit local deny drops the mirror (an
// untrustworthy upstream cannot smuggle past a local deny), and the local emit
// labels are unioned in (an upstream cannot launder taint by omitting a label).
func TestFederationRespectsLocalPolicy(t *testing.T) {
	auth := &RuleAuthorizer{Rules: []TopicRule{
		{Topics: []string{"secret.*"}, Allow: false},                          // explicit local deny
		{Topics: []string{"web.*"}, Allow: true, Taint: true, ClearAll: true}, // local taint on web.*, subscriber cleared
	}}
	b := New(Options{Authorizer: auth})
	defer b.Close()

	// A federated event on an explicitly-denied topic is refused.
	if _, err := b.EmitFederated("secret.keys", json.RawMessage(`1`), nil, "up-key", "broker-B", false, false, ""); !errors.Is(err, ErrDenied) {
		t.Fatalf("federated event on locally-denied topic: got %v, want ErrDenied", err)
	}

	// A federated event on web.* is accepted and carries the LOCAL taint label,
	// even though the upstream asserted none.
	sub, _ := b.Subscribe(id("s"), SubOptions{Topics: []string{"web.*"}})
	defer sub.Close()
	ev, err := b.EmitFederated("web.page", json.RawMessage(`1`), nil, "up-key", "broker-B", false, false, "")
	if err != nil {
		t.Fatalf("federated web.* event should pass: %v", err)
	}
	if !hasLabel(ev.Labels, "tainted") {
		t.Fatalf("local taint not applied to federated event: labels=%v", ev.Labels)
	}
	got := recv(t, sub)
	if got.Origin != "broker-B" {
		t.Fatalf("federated event Origin = %q, want broker-B", got.Origin)
	}
}

// hasLabel reports whether labels contains want.
func hasLabel(labels []string, want string) bool {
	for _, l := range labels {
		if l == want {
			return true
		}
	}
	return false
}

// TestConsumerGroupLoadBalance verifies a named consumer group is a competing-
// consumer set: each live event is delivered to exactly one member, the members
// share the load (round-robin), and together they see every event with no
// duplicates.
func TestConsumerGroupLoadBalance(t *testing.T) {
	b := New(Options{Authorizer: AllowAll{}, Limits: Limits{SubQueue: 64}})
	defer b.Close()

	a, err := b.Subscribe(id("a"), SubOptions{Topics: []string{"work"}, Group: "g"})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	c, err := b.Subscribe(id("c"), SubOptions{Topics: []string{"work"}, Group: "g"})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	const n = 20
	for i := 0; i < n; i++ {
		if _, err := b.Publish(id("p"), "work", json.RawMessage(fmt.Sprintf("%d", i)), nil); err != nil {
			t.Fatal(err)
		}
	}

	seen := map[string]int{}
	drain := func(s *Subscription) int {
		got := 0
		for {
			select {
			case ev := <-s.C():
				seen[string(ev.Payload)]++
				got++
			default:
				return got
			}
		}
	}
	ga, gc := drain(a), drain(c)
	if ga+gc != n {
		t.Fatalf("group saw %d events (a=%d c=%d), want %d total", ga+gc, ga, gc, n)
	}
	if ga == 0 || gc == 0 {
		t.Fatalf("load not shared: a=%d c=%d", ga, gc)
	}
	for i := 0; i < n; i++ {
		k := fmt.Sprintf("%d", i)
		if seen[k] != 1 {
			t.Fatalf("event %s delivered %d times, want exactly once", k, seen[k])
		}
	}
}

// TestConsumerGroupCapacityAware verifies group delivery prefers a member with
// buffer room: a member whose buffer is already full is skipped in favor of an
// idle member instead of dropping the event on the busy one.
func TestConsumerGroupCapacityAware(t *testing.T) {
	const q = 4
	b := New(Options{Authorizer: AllowAll{}, Limits: Limits{SubQueue: q}})
	defer b.Close()

	busy, _ := b.Subscribe(id("busy"), SubOptions{Topics: []string{"t"}, Group: "g"})
	defer busy.Close()
	idle, _ := b.Subscribe(id("idle"), SubOptions{Topics: []string{"t"}, Group: "g"})
	defer idle.Close()

	// Saturate "busy" by filling its buffer directly (it never drains).
	b.mu.Lock()
	for i := 0; i < cap(busy.ch); i++ {
		busy.ch <- &Event{Topic: "t"}
	}
	b.mu.Unlock()

	// Publish exactly idle's capacity worth of events. With "busy" full, every
	// one must land on "idle" without a drop — rather than being dropped on the
	// saturated member as blind round-robin would.
	for i := 0; i < q; i++ {
		if _, err := b.Publish(id("p"), "t", json.RawMessage(`1`), nil); err != nil {
			t.Fatal(err)
		}
	}
	got := 0
	for {
		select {
		case <-idle.C():
			got++
			continue
		default:
		}
		break
	}
	if got != q {
		t.Fatalf("idle member received %d of %d; capacity-aware routing should send all to the idle member", got, q)
	}
	if d := busy.Dropped(); d != 0 {
		t.Fatalf("busy member dropped %d events; it should have been skipped, not dropped on", d)
	}
}

// TestConsumerGroupWithStandalone verifies grouped and ungrouped subscribers
// coexist: an ungrouped subscriber receives every event, while a group splits
// the same events across its members (each event: one group copy + one standalone
// copy).
func TestConsumerGroupWithStandalone(t *testing.T) {
	b := New(Options{Authorizer: AllowAll{}, Limits: Limits{SubQueue: 64}})
	defer b.Close()

	solo, _ := b.Subscribe(id("solo"), SubOptions{Topics: []string{"t"}})
	defer solo.Close()
	g1, _ := b.Subscribe(id("g1"), SubOptions{Topics: []string{"t"}, Group: "grp"})
	defer g1.Close()
	g2, _ := b.Subscribe(id("g2"), SubOptions{Topics: []string{"t"}, Group: "grp"})
	defer g2.Close()

	const n = 10
	for i := 0; i < n; i++ {
		b.Publish(id("p"), "t", json.RawMessage(fmt.Sprintf("%d", i)), nil)
	}
	count := func(s *Subscription) int {
		got := 0
		for {
			select {
			case <-s.C():
				got++
			default:
				return got
			}
		}
	}
	if c := count(solo); c != n {
		t.Fatalf("standalone subscriber saw %d, want all %d", c, n)
	}
	if c := count(g1) + count(g2); c != n {
		t.Fatalf("group saw %d total, want %d (one copy per event)", c, n)
	}
}

// TestConsumerGroupTaintContainment verifies group delivery still honors label
// clearance: a tainted event is only ever routed to a group member cleared for
// it, never to an uncleared member (containment is applied before group
// selection).
func TestConsumerGroupTaintContainment(t *testing.T) {
	// web.* is tainted; "cleared" is cleared for it, "blind" is not. Both join
	// the same group.
	auth := &RuleAuthorizer{Rules: []TopicRule{
		{Peers: []string{"pubkey:pub"}, Topics: []string{"web.*"}, Allow: true, Taint: true},
		{Peers: []string{"pubkey:cleared"}, Topics: []string{"web.*"}, Allow: true, ClearTaint: true},
		{Peers: []string{"pubkey:blind"}, Topics: []string{"web.*"}, Allow: true}, // not cleared
	}}
	b := New(Options{Authorizer: auth})
	defer b.Close()

	cleared, err := b.Subscribe(Identity{Key: "cleared", FQDN: "cleared.x"}, SubOptions{Topics: []string{"web.*"}, Group: "g"})
	if err != nil {
		t.Fatal(err)
	}
	defer cleared.Close()
	blind, err := b.Subscribe(Identity{Key: "blind", FQDN: "blind.x"}, SubOptions{Topics: []string{"web.*"}, Group: "g"})
	if err != nil {
		t.Fatal(err)
	}
	defer blind.Close()

	const n = 8
	for i := 0; i < n; i++ {
		b.Publish(Identity{Key: "pub", FQDN: "pub.x"}, "web.page", json.RawMessage(`1`), nil)
	}
	// Every tainted event must land on the cleared member; the blind member,
	// though in the group, is never a valid target for a tainted event.
	got := 0
	for {
		select {
		case <-cleared.C():
			got++
			continue
		default:
		}
		break
	}
	if got != n {
		t.Fatalf("cleared member saw %d tainted events, want all %d routed to it", got, n)
	}
	select {
	case ev := <-blind.C():
		t.Fatalf("uncleared group member received a tainted event: %+v", ev)
	default:
	}
}

// TestConsumerGroupMemberLeave verifies that after a member leaves, all events
// route to the remaining member (and the group's cursor state is reclaimed once
// empty).
func TestConsumerGroupMemberLeave(t *testing.T) {
	b := New(Options{Authorizer: AllowAll{}, Limits: Limits{SubQueue: 32}})
	defer b.Close()

	a, _ := b.Subscribe(id("a"), SubOptions{Topics: []string{"t"}, Group: "g"})
	c, _ := b.Subscribe(id("c"), SubOptions{Topics: []string{"t"}, Group: "g"})
	a.Close()

	const n = 6
	for i := 0; i < n; i++ {
		b.Publish(id("p"), "t", json.RawMessage(`1`), nil)
	}
	got := 0
	for {
		select {
		case <-c.C():
			got++
			continue
		default:
		}
		break
	}
	if got != n {
		t.Fatalf("remaining member saw %d, want all %d after peer left", got, n)
	}
	c.Close()
	// After all members leave, the group's cursor/count are reclaimed.
	b.mu.Lock()
	_, hasRR := b.groupRR["g"]
	_, hasN := b.groupN["g"]
	b.mu.Unlock()
	if hasRR || hasN {
		t.Fatal("group state not reclaimed after last member left")
	}
}

// TestAckGroupRedeliversOnLoss is the core at-least-once guarantee: an event
// delivered to a member that disconnects WITHOUT acking is redelivered to
// another group member, so a crashed/rolling worker loses no work.
func TestAckGroupRedeliversOnLoss(t *testing.T) {
	b := New(Options{Authorizer: AllowAll{}, Limits: Limits{SubQueue: 16}})
	defer b.Close()

	w1, err := b.Subscribe(id("w1"), SubOptions{Topics: []string{"jobs"}, Group: "g", Ack: true})
	if err != nil {
		t.Fatal(err)
	}
	w2, err := b.Subscribe(id("w2"), SubOptions{Topics: []string{"jobs"}, Group: "g", Ack: true})
	if err != nil {
		t.Fatal(err)
	}
	defer w2.Close()

	// Publish one job; the round-robin cursor starts at 0, so w1 (members[0])
	// receives it.
	ev, _ := b.Publish(id("p"), "jobs", json.RawMessage(`"job1"`), nil)
	if g := recv(t, w1); g.Seq != ev.Seq {
		t.Fatalf("w1 got seq %d, want %d", g.Seq, ev.Seq)
	}

	// w1 dies WITHOUT acking → the un-acked job is redelivered to w2.
	w1.Close()
	if r := recvWithin(w2, 2*time.Second); r == nil || r.Seq != ev.Seq {
		t.Fatal("un-acked event was not redelivered to the surviving member")
	}
}

// TestAckGroupAckReleasesInflight verifies that once a member acks an event, the
// event is NOT redelivered when that member later leaves (the work was done).
func TestAckGroupAckReleasesInflight(t *testing.T) {
	b := New(Options{Authorizer: AllowAll{}, Limits: Limits{SubQueue: 16}})
	defer b.Close()

	w1, _ := b.Subscribe(id("w1"), SubOptions{Topics: []string{"jobs"}, Group: "g", Ack: true})
	w2, _ := b.Subscribe(id("w2"), SubOptions{Topics: []string{"jobs"}, Group: "g", Ack: true})
	defer w2.Close()

	ev, _ := b.Publish(id("p"), "jobs", json.RawMessage(`1`), nil)
	// Whichever worker got it acks it, then leaves.
	recvd, other := w1, w2
	g := recvWithin(w1, 200*time.Millisecond)
	if g == nil {
		g = recv(t, w2)
		recvd, other = w2, w1
	}
	b.Ack(recvd, g.Seq)
	recvd.Close()

	// The acked event must NOT be redelivered.
	if r := recvWithin(other, 300*time.Millisecond); r != nil {
		t.Fatalf("acked event should not be redelivered, got seq %d", r.Seq)
	}
	_ = ev
}

// TestAckGroupBacklogDrainsOnAck verifies the bounded backlog: when the only
// member is at its in-flight cap, further events are held (not dropped) and
// delivered as the member acks and frees capacity.
func TestAckGroupBacklogDrainsOnAck(t *testing.T) {
	// SubQueue=2 → in-flight cap 2. Publish 4 with one member; 2 delivered, 2 held.
	b := New(Options{Authorizer: AllowAll{}, Limits: Limits{SubQueue: 2}})
	defer b.Close()

	w, _ := b.Subscribe(id("w"), SubOptions{Topics: []string{"jobs"}, Group: "g", Ack: true})
	defer w.Close()

	var seqs []uint64
	for i := 0; i < 4; i++ {
		ev, _ := b.Publish(id("p"), "jobs", json.RawMessage(fmt.Sprintf("%d", i)), nil)
		seqs = append(seqs, ev.Seq)
	}
	// Drain the two the worker can hold.
	e0 := recv(t, w)
	e1 := recv(t, w)
	// No third yet — backlog is held pending an ack.
	if r := recvWithin(w, 150*time.Millisecond); r != nil {
		t.Fatalf("third event should be held until an ack, got seq %d", r.Seq)
	}
	// Ack one → backlog advances by one.
	b.Ack(w, e0.Seq)
	if r := recvWithin(w, time.Second); r == nil {
		t.Fatal("backlog did not advance after an ack")
	}
	b.Ack(w, e1.Seq)
	if r := recvWithin(w, time.Second); r == nil {
		t.Fatal("backlog did not advance after the second ack")
	}
	_ = seqs
}

// TestAckRequiresGroup verifies at-least-once without a group is refused (no
// peer to redeliver to).
func TestAckRequiresGroup(t *testing.T) {
	b := New(Options{Authorizer: AllowAll{}})
	defer b.Close()
	if _, err := b.Subscribe(id("w"), SubOptions{Topics: []string{"jobs"}, Ack: true}); !errors.Is(err, ErrBadTopic) {
		t.Fatalf("ack without group: got %v, want ErrBadTopic", err)
	}
}

// memGroupStore is an in-memory GroupStore for tests (stands in for the file
// store) — it also survives a simulated "restart" (a new broker built with the
// same store instance).
type memGroupStore struct {
	mu sync.Mutex
	m  map[string]uint64
}

func newMemGroupStore() *memGroupStore { return &memGroupStore{m: map[string]uint64{}} }
func (s *memGroupStore) Load(g string) (uint64, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, ok := s.m[g]
	return n, ok
}
func (s *memGroupStore) Save(g string, c uint64) error {
	s.mu.Lock()
	s.m[g] = c
	s.mu.Unlock()
	return nil
}

// TestDurableGroupSurvivesRestart is the cross-restart guarantee: an
// at-least-once group with a committed-offset store replays its un-acked events
// to a member that joins after a broker restart, so no work is lost across the
// gap.
func TestDurableGroupSurvivesRestart(t *testing.T) {
	store := newMemGroupStore()
	var buf bytes.Buffer

	// Run 1: a durable group processes one job and acks it, then a second job is
	// published and delivered but NOT acked before the broker "crashes".
	b1 := New(Options{Authorizer: AllowAll{}, Events: NewEventLog(&buf), GroupStore: store, Limits: Limits{Retain: 100}})
	w1, err := b1.Subscribe(id("w1"), SubOptions{Topics: []string{"jobs"}, Group: "g", Ack: true})
	if err != nil {
		t.Fatal(err)
	}
	j1, _ := b1.Publish(id("p"), "jobs", json.RawMessage(`"j1"`), nil)
	if e := recv(t, w1); e.Seq != j1.Seq {
		t.Fatalf("w1 got %d, want %d", e.Seq, j1.Seq)
	}
	b1.Ack(w1, j1.Seq) // j1 done → committed advances past it
	j2, _ := b1.Publish(id("p"), "jobs", json.RawMessage(`"j2"`), nil)
	recv(t, w1) // j2 delivered but NOT acked
	b1.Close()  // "crash" with j2 un-acked

	// Run 2: a fresh broker seeded from the same log + same store. A worker joins
	// the group and must be redelivered j2 (un-acked) but NOT j1 (acked).
	seed, err := LoadEvents(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	b2 := New(Options{Authorizer: AllowAll{}, Events: NewEventLog(&buf), Seed: seed, GroupStore: store, Limits: Limits{Retain: 100}})
	defer b2.Close()

	w2, err := b2.Subscribe(id("w2"), SubOptions{Topics: []string{"jobs"}, Group: "g", Ack: true})
	if err != nil {
		t.Fatal(err)
	}
	defer w2.Close()

	ev := recv(t, w2)
	if ev.Seq != j2.Seq {
		t.Fatalf("after restart, replayed seq %d, want the un-acked j2 (%d)", ev.Seq, j2.Seq)
	}
	// No further replay (j1 was acked before the crash).
	if r := recvWithin(w2, 200*time.Millisecond); r != nil {
		t.Fatalf("acked j1 should not be replayed, got seq %d", r.Seq)
	}
}

// TestDurableGroupBrandNewStartsFromNow verifies a brand-new durable group does
// NOT replay history — it starts from the current sequence, like a fresh
// subscriber.
func TestDurableGroupBrandNewStartsFromNow(t *testing.T) {
	store := newMemGroupStore()
	b := New(Options{Authorizer: AllowAll{}, GroupStore: store, Limits: Limits{Retain: 100}})
	defer b.Close()

	// Pre-existing history before the group ever existed.
	for i := 0; i < 5; i++ {
		b.Publish(id("p"), "jobs", json.RawMessage(`1`), nil)
	}
	w, _ := b.Subscribe(id("w"), SubOptions{Topics: []string{"jobs"}, Group: "g", Ack: true})
	defer w.Close()

	// The brand-new group must not receive the 5 historical events.
	if r := recvWithin(w, 200*time.Millisecond); r != nil {
		t.Fatalf("brand-new durable group replayed history (seq %d); it should start from now", r.Seq)
	}
	// A new publish is delivered normally.
	nv, _ := b.Publish(id("p"), "jobs", json.RawMessage(`1`), nil)
	if e := recv(t, w); e.Seq != nv.Seq {
		t.Fatalf("new event seq %d, want %d", e.Seq, nv.Seq)
	}
}

// TestDurableGroupResumesAfterTotalOutage verifies same-process recovery: after
// the group's last member leaves with un-acked work, a new member joining
// replays it (via the committed offset), no restart required.
func TestDurableGroupResumesAfterTotalOutage(t *testing.T) {
	store := newMemGroupStore()
	b := New(Options{Authorizer: AllowAll{}, GroupStore: store, Limits: Limits{Retain: 100}})
	defer b.Close()

	w1, _ := b.Subscribe(id("w1"), SubOptions{Topics: []string{"jobs"}, Group: "g", Ack: true})
	job, _ := b.Publish(id("p"), "jobs", json.RawMessage(`"x"`), nil)
	recv(t, w1) // delivered, not acked
	w1.Close()  // total outage: last member leaves with the job un-acked

	// A replacement worker joins → the un-acked job replays.
	w2, _ := b.Subscribe(id("w2"), SubOptions{Topics: []string{"jobs"}, Group: "g", Ack: true})
	defer w2.Close()
	if r := recvWithin(w2, time.Second); r == nil || r.Seq != job.Seq {
		t.Fatal("un-acked job was not replayed to the replacement worker after a total outage")
	}
}

// TestConsumerGroupRejectsSince verifies --since replay is refused with a group
// (a group is live-only; replaying a window to every competing consumer would
// duplicate it).
func TestConsumerGroupRejectsSince(t *testing.T) {
	b := New(Options{Authorizer: AllowAll{}})
	defer b.Close()
	if _, err := b.Subscribe(id("a"), SubOptions{Topics: []string{"t"}, Group: "g", Since: 1}); !errors.Is(err, ErrBadTopic) {
		t.Fatalf("group + since: got %v, want ErrBadTopic", err)
	}
}

// TestRequestReplyFields verifies the request/reply correlation fields are
// stamped onto the sealed event, delivered intact, and covered by the hash
// chain (they are part of the event, so a tamper would be detected).
func TestRequestReplyFields(t *testing.T) {
	b := New(Options{Authorizer: AllowAll{}})
	defer b.Close()
	sub, _ := b.Subscribe(id("s"), SubOptions{Topics: []string{"rpc.add"}})
	defer sub.Close()

	ev, err := b.PublishOpts(id("client"), "rpc.add", json.RawMessage(`[1,2]`),
		PublishOptions{ReplyTo: "_rpc.reply.abc", Corr: "abc"})
	if err != nil {
		t.Fatal(err)
	}
	if ev.ReplyTo != "_rpc.reply.abc" || ev.Corr != "abc" {
		t.Fatalf("published event missing correlation: %+v", ev)
	}
	got := recv(t, sub)
	if got.ReplyTo != "_rpc.reply.abc" || got.Corr != "abc" {
		t.Fatalf("delivered event missing correlation: %+v", got)
	}
	if err := VerifyChain(b.Retained()); err != nil {
		t.Fatalf("chain with correlation fields must verify: %v", err)
	}
}

// TestRequestReplyRoundTrip exercises the whole RPC pattern on the core: a
// responder subscribed to the request topic replies to the event's ReplyTo with
// the same Corr, and the requester (subscribed to the reply topic) matches it.
// Everything is ordinary per-topic publish/subscribe — RPC needs no special path.
func TestRequestReplyRoundTrip(t *testing.T) {
	b := New(Options{Authorizer: AllowAll{}})
	defer b.Close()

	// Requester listens on its private reply topic; responder listens on the
	// request topic.
	reply, err := b.Subscribe(id("client"), SubOptions{Topics: []string{"_rpc.reply.xyz"}})
	if err != nil {
		t.Fatal(err)
	}
	defer reply.Close()
	requests, err := b.Subscribe(id("server"), SubOptions{Topics: []string{"rpc.echo"}})
	if err != nil {
		t.Fatal(err)
	}
	defer requests.Close()

	// Requester publishes the request.
	if _, err := b.PublishOpts(id("client"), "rpc.echo", json.RawMessage(`"ping"`),
		PublishOptions{ReplyTo: "_rpc.reply.xyz", Corr: "xyz"}); err != nil {
		t.Fatal(err)
	}

	// Responder receives it and replies to ReplyTo with the same Corr.
	req := recv(t, requests)
	if req.ReplyTo == "" || req.Corr == "" {
		t.Fatalf("responder got a request without correlation: %+v", req)
	}
	if _, err := b.PublishOpts(id("server"), req.ReplyTo, json.RawMessage(`"pong"`),
		PublishOptions{Corr: req.Corr}); err != nil {
		t.Fatal(err)
	}

	// Requester matches the reply by Corr.
	resp := recv(t, reply)
	if resp.Corr != "xyz" || string(resp.Payload) != `"pong"` {
		t.Fatalf("requester got wrong reply: %+v", resp)
	}
}

// TestRequestReplyValidation verifies the correlation fields are bounded like a
// topic/label (they are retained and hashed): an over-long reply_to or corr is
// refused.
func TestRequestReplyValidation(t *testing.T) {
	b := New(Options{Authorizer: AllowAll{}, Limits: Limits{MaxTopicLen: 16}})
	defer b.Close()
	long := strings.Repeat("x", 17)
	if _, err := b.PublishOpts(id("c"), "t", json.RawMessage(`1`), PublishOptions{ReplyTo: long}); err == nil {
		t.Fatal("over-long reply_to should be rejected")
	}
	if _, err := b.PublishOpts(id("c"), "t", json.RawMessage(`1`), PublishOptions{Corr: long}); !errors.Is(err, ErrBadTopic) {
		t.Fatalf("over-long corr: got %v, want ErrBadTopic", err)
	}
}

// TestRetainedTTL verifies a retained last-value with a TTL is delivered before
// it expires and withheld (and evicted) after, using an injected clock.
func TestRetainedTTL(t *testing.T) {
	clk := newClock()
	b := New(Options{Authorizer: AllowAll{}, Now: clk.now})
	defer b.Close()

	b.PublishOpts(id("p"), "state.presence", json.RawMessage(`"online"`),
		PublishOptions{Retain: true, RetainTTL: time.Minute})

	// Before expiry: a new subscriber receives it.
	early, _ := b.Subscribe(id("s1"), SubOptions{Topics: []string{"state.*"}})
	if ev := recv(t, early); string(ev.Payload) != `"online"` {
		t.Fatalf("pre-expiry retained = %s, want online", ev.Payload)
	}
	early.Close()

	// After expiry: a new subscriber receives nothing, and the entry is evicted.
	clk.add(2 * time.Minute)
	late, _ := b.Subscribe(id("s2"), SubOptions{Topics: []string{"state.*"}})
	defer late.Close()
	expectNone(t, late)
	b.mu.Lock()
	_, stillThere := b.retained["state.presence"]
	b.mu.Unlock()
	if stillThere {
		t.Fatal("expired retained value was not evicted")
	}
}

// TestRetainedTombstone verifies an unretain (RetainDelete) clears the topic's
// retained last-value: the clear event still fans out live, but a later
// subscriber gets no retained value.
func TestRetainedTombstone(t *testing.T) {
	b := New(Options{Authorizer: AllowAll{}})
	defer b.Close()

	b.PublishOpts(id("p"), "state.k", json.RawMessage(`1`), PublishOptions{Retain: true})

	// A live subscriber sees the tombstone event.
	live, _ := b.Subscribe(id("live"), SubOptions{Topics: []string{"state.k"}})
	recv(t, live) // the retained value on connect
	if _, err := b.PublishOpts(id("p"), "state.k", json.RawMessage(`null`), PublishOptions{RetainDelete: true}); err != nil {
		t.Fatal(err)
	}
	if ev := recv(t, live); string(ev.Payload) != `null` {
		t.Fatalf("live subscriber should see the clear event, got %s", ev.Payload)
	}
	live.Close()

	// A later subscriber gets no retained value for the cleared topic.
	later, _ := b.Subscribe(id("later"), SubOptions{Topics: []string{"state.k"}})
	defer later.Close()
	expectNone(t, later)
}

// TestRetainedTTLRefreshedOnUpdate verifies re-retaining a topic without a TTL
// clears a previously set expiry (the value becomes permanent again).
func TestRetainedTTLRefreshedOnUpdate(t *testing.T) {
	clk := newClock()
	b := New(Options{Authorizer: AllowAll{}, Now: clk.now})
	defer b.Close()

	b.PublishOpts(id("p"), "t", json.RawMessage(`1`), PublishOptions{Retain: true, RetainTTL: time.Minute})
	b.PublishOpts(id("p"), "t", json.RawMessage(`2`), PublishOptions{Retain: true}) // no TTL: clears expiry
	clk.add(2 * time.Minute)
	sub, _ := b.Subscribe(id("s"), SubOptions{Topics: []string{"t"}})
	defer sub.Close()
	if ev := recv(t, sub); string(ev.Payload) != `2` {
		t.Fatalf("retained (no-TTL update) = %s, want 2 (should not have expired)", ev.Payload)
	}
}

// TestRetainedFederates verifies a retained last-value carries across a
// federation hop: mirroring the retained event into a second broker makes it
// that broker's retained value too (a late local subscriber gets it).
func TestRetainedFederates(t *testing.T) {
	up := New(Options{Authorizer: AllowAll{}})
	defer up.Close()
	down := New(Options{Authorizer: AllowAll{}})
	defer down.Close()

	// Publish a retained value on the upstream broker.
	rev, err := up.PublishOpts(id("p"), "state.k", json.RawMessage(`"v1"`), PublishOptions{Retain: true})
	if err != nil {
		t.Fatal(err)
	}
	if !rev.Retain {
		t.Fatal("published retained event should carry Retain=true on the event")
	}

	// The federation runner mirrors it: carry the retain intent from the event.
	if _, err := down.EmitFederated(rev.Topic, rev.Payload, rev.Labels, rev.Publisher, "up", rev.Retain, rev.RetainDel, rev.ExpiresAt); err != nil {
		t.Fatal(err)
	}

	// A subscriber that connects to the DOWNSTREAM broker afterward receives the
	// federated retained value.
	sub, _ := down.Subscribe(id("s"), SubOptions{Topics: []string{"state.*"}})
	defer sub.Close()
	if ev := recv(t, sub); string(ev.Payload) != `"v1"` {
		t.Fatalf("downstream retained = %s, want v1 (federated)", ev.Payload)
	}
}

// TestRetainedSurvivesRestart verifies retained state is rebuilt from the
// persisted event log on restart (retain intent rides the event), including a
// tombstone that must stay cleared.
func TestRetainedSurvivesRestart(t *testing.T) {
	var buf bytes.Buffer
	b1 := New(Options{Authorizer: AllowAll{}, Events: NewEventLog(&buf), Limits: Limits{Retain: 100}})
	b1.PublishOpts(id("p"), "state.keep", json.RawMessage(`"live"`), PublishOptions{Retain: true})
	b1.PublishOpts(id("p"), "state.gone", json.RawMessage(`"x"`), PublishOptions{Retain: true})
	b1.PublishOpts(id("p"), "state.gone", json.RawMessage(`null`), PublishOptions{RetainDelete: true}) // tombstone
	b1.Close()

	// "Restart": reload the log and seed a fresh broker.
	seed, err := LoadEvents(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	b2 := New(Options{Authorizer: AllowAll{}, Seed: seed, Limits: Limits{Retain: 100}})
	defer b2.Close()

	sub, _ := b2.Subscribe(id("s"), SubOptions{Topics: []string{"state.*"}})
	defer sub.Close()
	// state.keep is restored; state.gone was tombstoned and must not come back.
	ev := recv(t, sub)
	if ev.Topic != "state.keep" || string(ev.Payload) != `"live"` {
		t.Fatalf("restored retained = %+v, want state.keep=live", ev)
	}
	expectNone(t, sub) // no second retained value (the tombstoned one stays gone)
}

// TestRetainedExpirySweptAtCap verifies an expired retained value is actively
// swept to make room when a new topic would otherwise hit the retained cap.
func TestRetainedExpirySweptAtCap(t *testing.T) {
	clk := newClock()
	b := New(Options{Authorizer: AllowAll{}, Now: clk.now, Limits: Limits{MaxRetainedTopics: 1}})
	defer b.Close()

	b.PublishOpts(id("p"), "a", json.RawMessage(`1`), PublishOptions{Retain: true, RetainTTL: time.Minute})
	clk.add(2 * time.Minute) // "a" lapses

	// Retaining a new topic at the cap sweeps the lapsed "a" to make room.
	b.PublishOpts(id("p"), "b", json.RawMessage(`2`), PublishOptions{Retain: true})
	b.mu.Lock()
	_, hasA := b.retained["a"]
	_, hasB := b.retained["b"]
	b.mu.Unlock()
	if hasA {
		t.Fatal("expired retained value should have been swept at cap pressure")
	}
	if !hasB {
		t.Fatal("new retained value should have taken the freed slot")
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

// recvWithin returns one event or nil if none arrives within d (for tests that
// assert timing/absence without failing).
func recvWithin(s *Subscription, d time.Duration) *Event {
	select {
	case ev, ok := <-s.C():
		if !ok {
			return nil
		}
		return ev
	case <-time.After(d):
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
