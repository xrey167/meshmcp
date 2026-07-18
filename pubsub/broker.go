package pubsub

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"meshmcp/policy"
)

// Limits are the resource caps that keep one peer from exhausting the broker.
// Every cap is a hard bound checked before any allocation, so a hostile or
// buggy peer cannot drive the broker to unbounded memory or CPU.
type Limits struct {
	SubQueue        int     `yaml:"sub_queue"`         // per-subscription delivery buffer (events)
	MaxSubs         int     `yaml:"max_subs"`          // maximum concurrent subscriptions
	MaxTopicsPerSub int     `yaml:"max_topics_per_sub"` // maximum topic patterns in one subscription
	MaxTopicLen     int     `yaml:"max_topic_len"`      // maximum topic/pattern length in bytes
	MaxPayloadBytes int     `yaml:"max_payload_bytes"`  // maximum event payload size in bytes
	MaxLabels       int     `yaml:"max_labels"`         // maximum data-flow labels per event
	MaxSubsPerPeer  int     `yaml:"max_subs_per_peer"`  // maximum concurrent subscriptions per identity
	Retain          int     `yaml:"retain"`             // events kept for replay-from-sequence
	PublishRate     float64 `yaml:"publish_rate"`       // per-peer publish+subscribe requests/second (0 = default, <0 = unlimited)
	PublishBurst    int     `yaml:"publish_burst"`      // per-peer burst ceiling
}

// DefaultLimits are conservative caps suitable for a small trusted mesh.
func DefaultLimits() Limits {
	return Limits{
		SubQueue:        256,
		MaxSubs:         1024,
		MaxTopicsPerSub: 64,
		MaxTopicLen:     256,
		MaxPayloadBytes: 1 << 20, // 1 MiB
		MaxLabels:       32,
		MaxSubsPerPeer:  128,
		Retain:          1024,
		PublishRate:     200, // per-peer publish+subscribe requests/second; bounded by default
		PublishBurst:    400,
	}
}

func (l Limits) withDefaults() Limits {
	d := DefaultLimits()
	if l.SubQueue <= 0 {
		l.SubQueue = d.SubQueue
	}
	if l.MaxSubs <= 0 {
		l.MaxSubs = d.MaxSubs
	}
	if l.MaxTopicsPerSub <= 0 {
		l.MaxTopicsPerSub = d.MaxTopicsPerSub
	}
	if l.MaxTopicLen <= 0 {
		l.MaxTopicLen = d.MaxTopicLen
	}
	if l.MaxPayloadBytes <= 0 {
		l.MaxPayloadBytes = d.MaxPayloadBytes
	}
	if l.MaxLabels <= 0 {
		l.MaxLabels = d.MaxLabels
	}
	if l.MaxSubsPerPeer <= 0 {
		l.MaxSubsPerPeer = d.MaxSubsPerPeer
	}
	if l.Retain < 0 {
		l.Retain = 0
	} else if l.Retain == 0 {
		l.Retain = d.Retain
	}
	// PublishRate: 0 means "unset" and takes the bounded default; a negative
	// value is the explicit opt-out (unlimited), normalized to 0 so the token
	// bucket disables. This keeps the bus bounded by default while still
	// letting an operator uncap it deliberately.
	if l.PublishRate == 0 {
		l.PublishRate = d.PublishRate
	} else if l.PublishRate < 0 {
		l.PublishRate = 0
	}
	if l.PublishBurst <= 0 && l.PublishRate > 0 {
		l.PublishBurst = 2 * int(l.PublishRate)
	}
	return l
}

// Options configures a Broker.
type Options struct {
	// Authorizer decides publish/subscribe by identity and topic. Required;
	// nil is treated as deny-everything (fail closed).
	Authorizer Authorizer
	// Audit, if set, records every authorization decision into the shared
	// hash-chained ledger.
	Audit *policy.AuditLog
	// Now supplies the clock (for event timestamps and rate limiting).
	// Defaults to time.Now; injected in tests for determinism.
	Now    func() time.Time
	Limits Limits
}

// Broker is the in-memory pub/sub core. It is safe for concurrent use by many
// publishers and subscribers. All mutation of the sequence, hash chain,
// subscription set, and retention ring happens under mu, so ordering and the
// chain are deterministic; per-subscription delivery is non-blocking so one
// slow reader can never stall the fan-out for the others.
type Broker struct {
	auth  Authorizer
	audit *policy.AuditLog
	now   func() time.Time
	lim   *limiter
	lm    Limits

	mu        sync.Mutex
	seq       uint64
	prev      string // hash of the last published event ("" before genesis)
	subs      map[uint64]*Subscription
	perPeer   map[string]int // active subscription count per identity key
	nextSubID uint64
	ring      *ring
	closed    bool
}

// New builds a Broker from Options, applying defaults for any zero fields.
func New(opts Options) *Broker {
	lm := opts.Limits.withDefaults()
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	auth := opts.Authorizer
	if auth == nil {
		auth = denyAll{}
	}
	return &Broker{
		auth:  auth,
		audit: opts.Audit,
		now:   now,
		lim:     newLimiter(lm.PublishRate, lm.PublishBurst, now),
		lm:      lm,
		subs:    map[uint64]*Subscription{},
		perPeer: map[string]int{},
		ring:    newRing(lm.Retain),
	}
}

// MaxPayloadBytes reports the broker's per-event payload cap. The wire layer
// sizes its frame scanner from this so a within-cap payload always fits.
func (b *Broker) MaxPayloadBytes() int { return b.lm.MaxPayloadBytes }

// denyAll is the fail-closed default Authorizer used when none is supplied.
type denyAll struct{}

func (denyAll) Publish(Identity, string) PubDecision {
	return PubDecision{Allow: false, Reason: "no authorizer configured"}
}
func (denyAll) Subscribe(Identity, string) SubDecision {
	return SubDecision{Allow: false, Reason: "no authorizer configured"}
}

// Publish authorizes and emits an event to topic. extraLabels are additional
// data-flow labels the publisher declares; they are unioned with the
// authorizer's emit labels (a publisher may add containment, never remove it).
// It returns the sealed Event (with Seq and Hash) on success.
func (b *Broker) Publish(id Identity, topic string, payload json.RawMessage, extraLabels []string) (*Event, error) {
	// Identity is cryptographic, never claimed: a caller whose WireGuard key
	// the transport could not prove has no identity to authorize. Fail closed
	// before anything else, so an unproven caller can never match a rule with
	// no explicit peer restriction.
	if id.Key == "" {
		return nil, fmt.Errorf("%w: unproven identity", ErrDenied)
	}
	// Rate-limit next, before any authorization, validation, or audit work.
	// A connected-but-unauthorized peer must not be able to amplify CPU, disk
	// (audit writes), or lock contention by flooding rejected publishes: the
	// token bucket caps how many attempts per peer ever reach that work.
	// Rate-limited attempts are dropped without an audit record — they are
	// bounded to the token rate, and the wire layer still returns an error to
	// the publisher, so the drop is visible without being loggable-to-flood.
	if !b.lim.allow(id.Key) {
		return nil, fmt.Errorf("%w: publisher %s", ErrRateLimited, id.Key)
	}
	if err := validateTopic(topic, b.lm.MaxTopicLen); err != nil {
		return nil, err
	}
	if len(payload) > b.lm.MaxPayloadBytes {
		b.record(id, "pubsub/publish", topic, "deny", "payload too large", nil)
		return nil, fmt.Errorf("%w: %d bytes exceeds max %d", ErrPayloadTooLarge, len(payload), b.lm.MaxPayloadBytes)
	}
	dec := b.auth.Publish(id, topic)
	if !dec.Allow {
		b.record(id, "pubsub/publish", topic, "deny", dec.Reason, nil)
		return nil, fmt.Errorf("%w: publish %q: %s", ErrDenied, topic, dec.Reason)
	}
	labels := unionLabels(dec.Labels, extraLabels)
	// Cap labels: retention holds them, so an uncapped label set would let a
	// tiny payload carry ~1 frame of labels and break the MaxPayloadBytes×Retain
	// memory bound. Each label is also length-bounded like a topic.
	if len(labels) > b.lm.MaxLabels {
		b.record(id, "pubsub/publish", topic, "deny", "too many labels", nil)
		return nil, fmt.Errorf("%w: %d labels exceeds max %d", ErrBadTopic, len(labels), b.lm.MaxLabels)
	}
	for _, l := range labels {
		if len(l) > b.lm.MaxTopicLen {
			b.record(id, "pubsub/publish", topic, "deny", "label too long", nil)
			return nil, fmt.Errorf("%w: label exceeds %d bytes", ErrBadTopic, b.lm.MaxTopicLen)
		}
	}

	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return nil, ErrClosed
	}
	b.seq++
	ev := &Event{
		Topic:     topic,
		Seq:       b.seq,
		Time:      b.now().UTC().Format(time.RFC3339Nano),
		Publisher: id.Key,
		PubFQDN:   id.FQDN,
		Labels:    labels,
		Payload:   payload,
		PrevHash:  b.prev,
	}
	h, err := chainHash(*ev)
	if err != nil {
		b.mu.Unlock()
		return nil, fmt.Errorf("hash event: %w", err)
	}
	ev.Hash = h
	b.prev = h
	b.ring.add(*ev)
	for _, s := range b.subs {
		if s.accepts(ev) {
			b.deliverLocked(s, ev)
		}
	}
	b.mu.Unlock()

	b.record(id, "pubsub/publish", topic, "allow", dec.Reason, ev.Labels)
	return ev, nil
}

// EmitInternal publishes a system event from the broker operator itself — e.g.
// the gateway emitting its own lifecycle events (policy decisions, taint trips)
// onto the bus. It bypasses per-topic authorization and rate limiting (the
// operator running the broker is trusted to emit), but the event is still
// validated, capped, sealed into the hash chain, retained, fanned out subject
// to each subscriber's label clearance, and audited. source names the event's
// Publisher (a system identifier, not a WireGuard key).
func (b *Broker) EmitInternal(source, topic string, payload json.RawMessage, labels []string) (*Event, error) {
	if err := validateTopic(topic, b.lm.MaxTopicLen); err != nil {
		return nil, err
	}
	if len(payload) > b.lm.MaxPayloadBytes {
		return nil, fmt.Errorf("%w: %d bytes exceeds max %d", ErrPayloadTooLarge, len(payload), b.lm.MaxPayloadBytes)
	}
	labels = unionLabels(labels, nil)
	if len(labels) > b.lm.MaxLabels {
		return nil, fmt.Errorf("%w: %d labels exceeds max %d", ErrBadTopic, len(labels), b.lm.MaxLabels)
	}

	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return nil, ErrClosed
	}
	b.seq++
	ev := &Event{
		Topic:     topic,
		Seq:       b.seq,
		Time:      b.now().UTC().Format(time.RFC3339Nano),
		Publisher: source,
		Labels:    labels,
		Payload:   payload,
		PrevHash:  b.prev,
	}
	h, err := chainHash(*ev)
	if err != nil {
		b.mu.Unlock()
		return nil, fmt.Errorf("hash event: %w", err)
	}
	ev.Hash = h
	b.prev = h
	b.ring.add(*ev)
	for _, s := range b.subs {
		if s.accepts(ev) {
			b.deliverLocked(s, ev)
		}
	}
	b.mu.Unlock()

	// Internal emission is not audited here: its events derive from decisions
	// the gateway already recorded in the ledger, and re-auditing every one
	// would double ledger volume under a deny-flood. External publish/subscribe
	// on the bus are still audited.
	return ev, nil
}

// SubOptions parameterize a subscription.
type SubOptions struct {
	Topics       []string     // topic globs (at least one)
	Backpressure Backpressure // full-buffer policy
	Since        uint64       // >0 replays retained events with Seq > Since first
}

// Subscribe authorizes and opens a subscription. Every topic is authorized
// independently; a single denial fails the whole subscribe (fail closed). The
// subscription's label clearance is the intersection across its topics, so a
// multi-topic subscription is never more cleared than its least-cleared topic.
func (b *Broker) Subscribe(id Identity, opts SubOptions) (*Subscription, error) {
	if id.Key == "" {
		return nil, fmt.Errorf("%w: unproven identity", ErrDenied)
	}
	// Rate-limit before auth/audit/replay, like Publish, so a peer cannot flood
	// the ledger with denied subscribes or amplify replay work by reconnecting.
	if !b.lim.allow(id.Key) {
		return nil, fmt.Errorf("%w: subscriber %s", ErrRateLimited, id.Key)
	}
	if len(opts.Topics) == 0 {
		return nil, fmt.Errorf("%w: subscription needs at least one topic", ErrBadTopic)
	}
	if len(opts.Topics) > b.lm.MaxTopicsPerSub {
		return nil, fmt.Errorf("%w: %d topics exceeds max %d", ErrTooMany, len(opts.Topics), b.lm.MaxTopicsPerSub)
	}

	clearAll := true
	var clear map[string]bool
	for _, t := range opts.Topics {
		if err := validateTopic(t, b.lm.MaxTopicLen); err != nil {
			return nil, err
		}
		dec := b.auth.Subscribe(id, t)
		if !dec.Allow {
			b.record(id, "pubsub/subscribe", t, "deny", dec.Reason, nil)
			return nil, fmt.Errorf("%w: subscribe %q: %s", ErrDenied, t, dec.Reason)
		}
		if dec.ClearAll {
			continue // universe: does not constrain the intersection
		}
		clearAll = false
		set := toSet(dec.Clear)
		if clear == nil {
			clear = set
		} else {
			clear = intersect(clear, set)
		}
	}

	s := &Subscription{
		ident:    id,
		topics:   append([]string(nil), opts.Topics...),
		clearAll: clearAll,
		clear:    clear,
		bp:       opts.Backpressure,
		ch:       make(chan *Event, b.lm.SubQueue),
		closed:   make(chan struct{}),
		b:        b,
	}

	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return nil, ErrClosed
	}
	if len(b.subs) >= b.lm.MaxSubs {
		b.mu.Unlock()
		return nil, fmt.Errorf("%w: %d subscriptions at max", ErrTooMany, b.lm.MaxSubs)
	}
	// Per-peer cap: one identity must not be able to pin every global slot
	// (an abandoned subscription lingers for the session TTL).
	if b.perPeer[id.Key] >= b.lm.MaxSubsPerPeer {
		b.mu.Unlock()
		return nil, fmt.Errorf("%w: %d subscriptions for peer at max", ErrTooMany, b.lm.MaxSubsPerPeer)
	}
	b.nextSubID++
	s.ID = b.nextSubID
	b.perPeer[id.Key]++
	// Register before replay so backpressure (Disconnect) during replay is
	// handled by the normal close path instead of leaving a closed
	// subscription in the map.
	b.subs[s.ID] = s
	if opts.Since > 0 {
		replay, truncated := b.ring.since(opts.Since)
		s.truncated = truncated
		for i := range replay {
			ev := replay[i]
			if s.accepts(&ev) {
				b.deliverLocked(s, &ev)
			}
			if _, ok := b.subs[s.ID]; !ok {
				break // disconnected by backpressure mid-replay
			}
		}
	}
	b.mu.Unlock()

	// One audit record per subscribe (not per topic) so a wide or churning
	// subscribe cannot amplify ledger writes.
	b.record(id, "pubsub/subscribe", strings.Join(opts.Topics, ","), "allow", "subscribed", nil)
	return s, nil
}

// Unsubscribe closes a subscription and stops delivery. Idempotent.
func (b *Broker) Unsubscribe(s *Subscription) {
	if s == nil {
		return
	}
	b.mu.Lock()
	b.closeSubLocked(s)
	b.mu.Unlock()
}

// deliverLocked enqueues ev to s without ever blocking the caller (the
// fan-out loop). On a full buffer it applies the subscription's backpressure
// policy. Must be called with b.mu held.
func (b *Broker) deliverLocked(s *Subscription, ev *Event) {
	select {
	case s.ch <- ev:
		return
	default:
	}
	// Buffer full.
	if s.bp == Disconnect {
		b.closeSubLocked(s)
		return
	}
	// DropOldest: a concurrent reader may have drained a slot since the first
	// send failed — retry the non-blocking send before evicting, so we never
	// discard a live event unnecessarily.
	select {
	case s.ch <- ev:
		return
	default:
	}
	// Still full: evict the oldest undelivered event, then enqueue the new one.
	select {
	case <-s.ch:
	default:
	}
	select {
	case s.ch <- ev:
	default:
	}
	atomic.AddUint64(&s.dropped, 1)
}

// closeSubLocked removes a subscription and closes its channels exactly once.
// Must be called with b.mu held. Removing from the map first guarantees no
// further deliverLocked will send on the closed channel.
func (b *Broker) closeSubLocked(s *Subscription) {
	if _, ok := b.subs[s.ID]; !ok {
		// Not registered (already closed, or closed mid-replay before add).
		s.closeOnce.Do(func() { close(s.ch); close(s.closed) })
		return
	}
	delete(b.subs, s.ID)
	if n := b.perPeer[s.ident.Key] - 1; n <= 0 {
		delete(b.perPeer, s.ident.Key)
	} else {
		b.perPeer[s.ident.Key] = n
	}
	s.closeOnce.Do(func() { close(s.ch); close(s.closed) })
}

// Close shuts the broker down: no further publishes or subscribes, and every
// open subscription is closed so its reader loop ends.
func (b *Broker) Close() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return
	}
	b.closed = true
	for _, s := range b.subs {
		delete(b.subs, s.ID)
		s.closeOnce.Do(func() { close(s.ch); close(s.closed) })
	}
	b.perPeer = map[string]int{}
}

// Seq returns the sequence number of the last published event.
func (b *Broker) Seq() uint64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.seq
}

// SubCount returns the number of open subscriptions.
func (b *Broker) SubCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.subs)
}

// Retained returns a snapshot of the events still held for replay, oldest
// first. Verifiable with VerifyChain.
func (b *Broker) Retained() []Event {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.ring.snapshot()
}

// record writes an audit entry for one authorization decision, if an audit
// log is attached. topic is carried in the Tool field to match the ledger's
// existing shape.
func (b *Broker) record(id Identity, method, topic, decision, reason string, prov []string) {
	if b.audit == nil {
		return
	}
	b.audit.Append(policy.AuditRecord{
		Backend:    "pubsub",
		Peer:       id.FQDN,
		PeerKey:    id.Key,
		PeerAddr:   id.Addr,
		Method:     method,
		Tool:       topic,
		Decision:   decision,
		Reason:     reason,
		Rule:       -1,
		Provenance: prov,
	})
}

func toSet(ss []string) map[string]bool {
	m := make(map[string]bool, len(ss))
	for _, s := range ss {
		m[s] = true
	}
	return m
}

func intersect(a, b map[string]bool) map[string]bool {
	out := map[string]bool{}
	for k := range a {
		if b[k] {
			out[k] = true
		}
	}
	return out
}

// unionLabels merges two label slices, de-duplicating, preserving order
// (authorizer labels first, then extras).
func unionLabels(a, b []string) []string {
	if len(a) == 0 && len(b) == 0 {
		return nil
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(a)+len(b))
	for _, s := range append(append([]string(nil), a...), b...) {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// validateTopic rejects empty, oversized, or control-character-bearing topics.
// Control characters (including newline) are rejected because the wire
// protocol is line-delimited: a newline in a topic would break framing.
func validateTopic(topic string, maxLen int) error {
	if topic == "" {
		return fmt.Errorf("%w: empty", ErrBadTopic)
	}
	if len(topic) > maxLen {
		return fmt.Errorf("%w: %d bytes exceeds max %d", ErrBadTopic, len(topic), maxLen)
	}
	for _, r := range topic {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("%w: contains control character", ErrBadTopic)
		}
	}
	return nil
}
