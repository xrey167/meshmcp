package pubsub

import (
	"encoding/json"
	"fmt"
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
	MaxTopicLen     int     `yaml:"max_topic_len"`     // maximum topic/pattern length in bytes
	MaxPayloadBytes int     `yaml:"max_payload_bytes"` // maximum event payload size in bytes
	Retain          int     `yaml:"retain"`            // events kept for replay-from-sequence
	PublishRate     float64 `yaml:"publish_rate"`      // per-publisher publishes/second (0 = unlimited)
	PublishBurst    int     `yaml:"publish_burst"`     // per-publisher burst ceiling
}

// DefaultLimits are conservative caps suitable for a small trusted mesh.
func DefaultLimits() Limits {
	return Limits{
		SubQueue:        256,
		MaxSubs:         1024,
		MaxTopicsPerSub: 64,
		MaxTopicLen:     256,
		MaxPayloadBytes: 1 << 20, // 1 MiB, aligned with the wire frame cap
		Retain:          1024,
		PublishRate:     0,
		PublishBurst:    0,
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
	if l.Retain < 0 {
		l.Retain = 0
	} else if l.Retain == 0 {
		l.Retain = d.Retain
	}
	if l.PublishBurst <= 0 && l.PublishRate > 0 {
		l.PublishBurst = int(l.PublishRate) + 1
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
		lim:   newLimiter(lm.PublishRate, lm.PublishBurst, now),
		lm:    lm,
		subs:  map[uint64]*Subscription{},
		ring:  newRing(lm.Retain),
	}
}

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
	if !b.lim.allow(id.Key) {
		b.record(id, "pubsub/publish", topic, "deny", "rate limit exceeded", nil)
		return nil, fmt.Errorf("%w: publisher %s on %q", ErrRateLimited, id.Key, topic)
	}
	labels := unionLabels(dec.Labels, extraLabels)

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
	b.nextSubID++
	s.ID = b.nextSubID
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

	for _, t := range opts.Topics {
		b.record(id, "pubsub/subscribe", t, "allow", "subscribed", nil)
	}
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
	// DropOldest: evict one undelivered event, then enqueue the new one.
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
