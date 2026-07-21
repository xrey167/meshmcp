package pubsub

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"meshmcp/policy"
)

// maxEncodingLen bounds the per-event encoding hint (e.g. "base64"). It is a
// small enum-like tag, retained and hashed, so it is capped like a label rather
// than trusting the wire length.
const maxEncodingLen = 32

// Limits are the resource caps that keep one peer from exhausting the broker.
// Every cap is a hard bound checked before any allocation, so a hostile or
// buggy peer cannot drive the broker to unbounded memory or CPU.
type Limits struct {
	SubQueue          int     `yaml:"sub_queue"`           // per-subscription delivery buffer (events)
	MaxSubs           int     `yaml:"max_subs"`            // maximum concurrent subscriptions
	MaxTopicsPerSub   int     `yaml:"max_topics_per_sub"`  // maximum topic patterns in one subscription
	MaxTopicLen       int     `yaml:"max_topic_len"`       // maximum topic/pattern length in bytes
	MaxPayloadBytes   int     `yaml:"max_payload_bytes"`   // maximum event payload size in bytes
	MaxLabels         int     `yaml:"max_labels"`          // maximum data-flow labels per event
	MaxSubsPerPeer    int     `yaml:"max_subs_per_peer"`   // maximum concurrent subscriptions per identity
	MaxRetainedTopics int     `yaml:"max_retained_topics"` // maximum distinct topics holding a retained last-value
	MaxGroupPending   int     `yaml:"max_group_pending"`   // maximum backlog of undelivered events per at-least-once consumer group
	Retain            int     `yaml:"retain"`              // events kept for replay-from-sequence
	PublishRate       float64 `yaml:"publish_rate"`        // per-peer publish+subscribe requests/second (0 = default, <0 = unlimited)
	PublishBurst      int     `yaml:"publish_burst"`       // per-peer burst ceiling
}

// DefaultLimits are conservative caps suitable for a small trusted mesh.
func DefaultLimits() Limits {
	return Limits{
		SubQueue:          256,
		MaxSubs:           1024,
		MaxTopicsPerSub:   64,
		MaxTopicLen:       256,
		MaxPayloadBytes:   1 << 20, // 1 MiB
		MaxLabels:         32,
		MaxSubsPerPeer:    128,
		MaxRetainedTopics: 4096,
		MaxGroupPending:   1024,
		Retain:            1024,
		PublishRate:       200, // per-peer publish+subscribe requests/second; bounded by default
		PublishBurst:      400,
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
	if l.MaxRetainedTopics <= 0 {
		l.MaxRetainedTopics = d.MaxRetainedTopics
	}
	if l.MaxGroupPending <= 0 {
		l.MaxGroupPending = d.MaxGroupPending
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
	// Events, if set, is a durable append sink for the sealed event stream, so
	// the bus survives a restart and its chain is externally verifiable.
	Events *EventLog
	// Seed is a previously persisted event stream (from LoadEvents) used to
	// resume after a restart: the sequence and hash chain continue from its
	// last event, and its tail preloads the replay ring. Nil for a fresh bus.
	Seed []Event
	// Name is the broker's audience name — what a signed capability's `aud`
	// must equal for it to grant a topic here. Required only if Capabilities
	// is set.
	Name string
	// Capabilities, if set, lets a caller presenting a valid signed capability
	// (subject-bound to its WireGuard key, audience == Name, topic in the
	// grant, unexpired) upgrade a DEFAULT-deny to allow — never an explicit
	// `allow: false`. Mirrors the tool-capability semantics.
	Capabilities *policy.CapabilityVerifier
	// Now supplies the clock (for event timestamps and rate limiting).
	// Defaults to time.Now; injected in tests for determinism.
	Now func() time.Time
	// GroupStore, if set, persists per-consumer-group committed offsets so an
	// at-least-once group survives a broker restart: on resume, events after the
	// committed offset are replayed to the group. Nil disables group durability
	// (a group's un-acked work is then only recoverable while it keeps a member).
	// Keeping the core IO-agnostic, the actual file/db lives behind this interface.
	GroupStore GroupStore
	Limits     Limits
}

// GroupStore persists a consumer group's committed offset (the sequence up to
// which the group has fully processed its events). It makes at-least-once groups
// durable across a broker restart. Implementations must be safe for concurrent
// use; the broker calls Save under its own lock, so Save should be cheap (e.g. an
// atomic file write) or buffered.
type GroupStore interface {
	// Load returns the persisted committed offset for a group, or ok=false if the
	// group has no stored offset (a brand-new group, which starts from "now").
	Load(group string) (committed uint64, ok bool)
	// Save records a group's committed offset. The broker calls it only when the
	// offset advances.
	Save(group string, committed uint64) error
}

// Broker is the in-memory pub/sub core. It is safe for concurrent use by many
// publishers and subscribers. All mutation of the sequence, hash chain,
// subscription set, and retention ring happens under mu, so ordering and the
// chain are deterministic; per-subscription delivery is non-blocking so one
// slow reader can never stall the fan-out for the others.
type Broker struct {
	auth   Authorizer
	audit  *policy.AuditLog
	events *EventLog
	name   string
	caps   *policy.CapabilityVerifier
	now    func() time.Time
	lim    *limiter
	lm     Limits

	mu         sync.Mutex
	seq        uint64
	prev       string // hash of the last published event ("" before genesis)
	subs       map[uint64]*Subscription
	perPeer    map[string]int       // active subscription count per identity key
	retained   map[string]*Event    // last-value per topic (retained messages)
	retainExp  map[string]time.Time // optional expiry per retained topic (TTL); absent = never expires
	groupRR    map[string]uint64    // round-robin cursor per consumer group
	groupN     map[string]int       // live member count per consumer group (for cursor GC)
	groupPend  map[string][]*Event  // per-group backlog of events no member could take yet (at-least-once)
	groupCmt   map[string]uint64    // durable groups: committed offset (all group events ≤ this are acked)
	groupMax   map[string]uint64    // durable groups: highest seq delivered to the group
	groupStore GroupStore           // optional: persists groupCmt across restarts
	nextSubID  uint64
	ring       *ring
	dropped    uint64 // aggregate events dropped by backpressure across all subs
	closed     bool
}

// Stats is a point-in-time snapshot of a broker's activity, for introspection.
type Stats struct {
	Subscriptions int    `json:"subscriptions"` // open subscriptions now
	Groups        int    `json:"groups"`        // active consumer groups now
	Sequence      uint64 `json:"sequence"`      // last published event's sequence
	Retained      int    `json:"retained"`      // events held for replay
	Dropped       uint64 `json:"dropped"`       // events dropped by backpressure (lifetime)
}

// Stats returns a snapshot of broker activity.
func (b *Broker) Stats() Stats {
	b.mu.Lock()
	defer b.mu.Unlock()
	return Stats{
		Subscriptions: len(b.subs),
		Groups:        len(b.groupN),
		Sequence:      b.seq,
		Retained:      b.ring.n,
		Dropped:       b.dropped,
	}
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
	b := &Broker{
		auth:       auth,
		audit:      opts.Audit,
		events:     opts.Events,
		name:       opts.Name,
		caps:       opts.Capabilities,
		now:        now,
		lim:        newLimiter(lm.PublishRate, lm.PublishBurst, now),
		lm:         lm,
		subs:       map[uint64]*Subscription{},
		perPeer:    map[string]int{},
		retained:   map[string]*Event{},
		retainExp:  map[string]time.Time{},
		groupRR:    map[string]uint64{},
		groupN:     map[string]int{},
		groupPend:  map[string][]*Event{},
		groupCmt:   map[string]uint64{},
		groupMax:   map[string]uint64{},
		groupStore: opts.GroupStore,
		ring:       newRing(lm.Retain),
	}
	// Resume from a persisted stream: continue the sequence and hash chain from
	// its last event, and preload the retention ring's tail so --since replay
	// works across the restart.
	if n := len(opts.Seed); n > 0 {
		last := opts.Seed[n-1]
		b.seq = last.Seq
		b.prev = last.Hash
		start := 0
		if n > lm.Retain {
			start = n - lm.Retain
		}
		for _, ev := range opts.Seed[start:] {
			b.ring.add(ev)
		}
		// Rebuild the retained last-value store from the persisted stream, so
		// retained state (and its TTLs/tombstones) survives a restart. Applied in
		// sequence order over the whole seed — a retained value can predate the
		// ring window — then lapsed TTLs are pruned against the current clock.
		for i := range opts.Seed {
			if ev := &opts.Seed[i]; ev.Retain || ev.RetainDel {
				b.applyRetainedLocked(ev)
			}
		}
		b.sweepExpiredRetainedLocked()
	}
	return b
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

// capAllows reports whether a presented signed capability grants topic to id
// on this broker (subject-bound, audience == Name, unexpired). Used to upgrade
// a default-deny; the caller must have already checked the deny was not explicit.
func (b *Broker) capAllows(id Identity, topic, token string) bool {
	if b.caps == nil || token == "" {
		return false
	}
	_, err := b.caps.Verify(token, id.Key, b.name, topic)
	return err == nil
}

// PublishOptions carries the optional facets of a publish beyond the payload.
type PublishOptions struct {
	// Labels are additional data-flow labels the publisher declares; unioned
	// with the authorizer's emit labels (a publisher may add containment).
	Labels []string
	// Capability is a signed token that can upgrade a default-deny to allow.
	Capability string
	// Retain stores this event as the topic's last-value, delivered to future
	// subscribers of the topic (MQTT-style retained message).
	Retain bool
	// RetainTTL, if >0, expires the retained last-value after this duration: a
	// subscriber connecting later does not receive an expired value (stale state
	// like presence or a reading valid for a bounded window). Only meaningful
	// with Retain. Retained TTL is tracked in memory.
	RetainTTL time.Duration
	// RetainDelete clears the topic's retained last-value (an MQTT-style
	// tombstone: a retained publish with no value deletes the retained message).
	// The event is still published live so current subscribers see the clear;
	// future subscribers get no retained value for the topic. Overrides Retain.
	RetainDelete bool
	// Encoding is an opaque payload-encoding hint stamped onto the event
	// (e.g. "base64" for a binary payload carried as a JSON string).
	Encoding string
	// ReplyTo and Corr carry request/reply correlation: ReplyTo is the topic a
	// responder should publish its reply to, and Corr is an opaque id echoed on
	// the reply so a requester can match it. Both are stamped onto the event and
	// otherwise opaque to the broker — request/reply is an ordinary publish plus
	// a correlated subscribe, so it inherits per-topic authorization and taint
	// containment with no special path.
	ReplyTo string
	Corr    string
}

// Publish authorizes and emits an event to topic (see PublishOpts for the full
// form). extraLabels are unioned with the authorizer's emit labels.
func (b *Broker) Publish(id Identity, topic string, payload json.RawMessage, extraLabels []string) (*Event, error) {
	return b.PublishOpts(id, topic, payload, PublishOptions{Labels: extraLabels})
}

// PublishCap is Publish with a signed capability token that can upgrade a
// default-deny on the topic to allow.
func (b *Broker) PublishCap(id Identity, topic string, payload json.RawMessage, extraLabels []string, capToken string) (*Event, error) {
	return b.PublishOpts(id, topic, payload, PublishOptions{Labels: extraLabels, Capability: capToken})
}

// PublishOpts is the full publish entry point.
func (b *Broker) PublishOpts(id Identity, topic string, payload json.RawMessage, o PublishOptions) (*Event, error) {
	extraLabels, capToken := o.Labels, o.Capability
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
	// The encoding hint is a tiny enum-like string ("base64"); it is retained and
	// hashed, so bound it like a label rather than trusting the wire length.
	if len(o.Encoding) > maxEncodingLen {
		b.record(id, "pubsub/publish", topic, "deny", "encoding hint too long", nil)
		return nil, fmt.Errorf("%w: encoding hint exceeds %d bytes", ErrBadTopic, maxEncodingLen)
	}
	// Request/reply correlation fields are retained and hashed, so bound them:
	// ReplyTo is a topic (a responder publishes to it), Corr an opaque id capped
	// like a topic. Both are validated before allocation, never trusted raw.
	if o.ReplyTo != "" {
		if err := validateTopic(o.ReplyTo, b.lm.MaxTopicLen); err != nil {
			b.record(id, "pubsub/publish", topic, "deny", "invalid reply_to", nil)
			return nil, fmt.Errorf("reply_to: %w", err)
		}
	}
	if len(o.Corr) > b.lm.MaxTopicLen {
		b.record(id, "pubsub/publish", topic, "deny", "correlation id too long", nil)
		return nil, fmt.Errorf("%w: correlation id exceeds %d bytes", ErrBadTopic, b.lm.MaxTopicLen)
	}
	dec := b.auth.Publish(id, topic)
	if !dec.Allow {
		// A signed capability may upgrade a DEFAULT deny (never an explicit
		// allow: false) — the same posture as tool capabilities.
		if !dec.Explicit && b.capAllows(id, topic, capToken) {
			dec = PubDecision{Allow: true, Reason: "capability grant"}
		} else {
			b.record(id, "pubsub/publish", topic, "deny", dec.Reason, nil)
			return nil, fmt.Errorf("%w: publish %q: %s", ErrDenied, topic, dec.Reason)
		}
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
	// Resolve the TTL to an absolute expiry now, so the retained value expires at
	// the same instant on every broker it federates to and after a restart.
	expiresAt := ""
	if o.Retain && o.RetainTTL > 0 {
		expiresAt = b.now().Add(o.RetainTTL).UTC().Format(time.RFC3339Nano)
	}
	ev := &Event{
		Topic:     topic,
		Seq:       b.seq,
		Time:      b.now().UTC().Format(time.RFC3339Nano),
		Publisher: id.Key,
		PubFQDN:   id.FQDN,
		Labels:    labels,
		Enc:       o.Encoding,
		ReplyTo:   o.ReplyTo,
		Corr:      o.Corr,
		Retain:    o.Retain && !o.RetainDelete,
		RetainDel: o.RetainDelete,
		ExpiresAt: expiresAt,
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
	// The retain intent rides the event, so a single helper applies it whether
	// the event came from a publish, a federated mirror, or a restart replay.
	b.applyRetainedLocked(ev)
	// Persist the sealed event in sequence order (best-effort per-event, like
	// the audit ledger; a failed append degrades durability but never blocks
	// delivery). Held under b.mu so the on-disk order matches the chain.
	if b.events != nil {
		_ = b.events.append(*ev)
	}
	b.fanoutLocked(ev)
	b.mu.Unlock()

	b.record(id, "pubsub/publish", topic, "allow", dec.Reason, ev.Labels)
	return ev, nil
}

// fanoutLocked delivers ev to every accepting subscription, with consumer-group
// semantics: an ungrouped subscription receives its own copy, while grouped
// subscriptions form a competing-consumer set — exactly one member of each
// group receives the event, chosen round-robin among the members that accept it
// (topic match *and* label clearance). Delivery is non-blocking. Must hold b.mu.
func (b *Broker) fanoutLocked(ev *Event) {
	var groups map[string][]*Subscription
	for _, s := range b.subs {
		if !s.accepts(ev) {
			continue
		}
		if s.group == "" {
			b.deliverLocked(s, ev)
			continue
		}
		if groups == nil {
			groups = make(map[string][]*Subscription)
		}
		groups[s.group] = append(groups[s.group], s)
	}
	// One copy per group to a member chosen round-robin (see deliverToGroupLocked).
	for name, members := range groups {
		b.deliverToGroupLocked(name, members, ev)
	}
}

// tryPlaceOnGroupLocked delivers ev to one member of a group, chosen round-robin
// starting at the group cursor and skipping members that cannot take it right
// now — buffer full, or (at-least-once) already at their in-flight cap. Records
// the event in the chosen member's in-flight set for an ack member. Returns true
// if placed. Must hold b.mu.
func (b *Broker) tryPlaceOnGroupLocked(name string, members []*Subscription, ev *Event) bool {
	if len(members) == 0 {
		return false
	}
	sort.Slice(members, func(i, j int) bool { return members[i].ID < members[j].ID })
	n := uint64(len(members))
	start := b.groupRR[name] % n
	b.groupRR[name]++
	for i := uint64(0); i < n; i++ {
		s := members[(start+i)%n]
		if s.ackMode && len(s.inflight) >= b.lm.SubQueue {
			continue // member has too many un-acked events; leave it to catch up
		}
		if b.tryDeliverLocked(s, ev) {
			if s.ackMode {
				s.inflight[ev.Seq] = ev
			}
			b.noteGroupDeliveredLocked(name, ev.Seq)
			return true
		}
	}
	return false
}

// noteGroupDeliveredLocked records the highest sequence handed to a durable
// group (delivered or backlogged), so the committed offset can advance to it once
// nothing is outstanding. Must hold b.mu.
func (b *Broker) noteGroupDeliveredLocked(name string, seq uint64) {
	if b.groupStore == nil {
		return
	}
	if seq > b.groupMax[name] {
		b.groupMax[name] = seq
	}
}

// deliverToGroupLocked delivers ev to the group named name (its accepting
// members). Capacity-aware: it prefers a member with room. If none can take it,
// an at-least-once group holds the event in a bounded backlog for redelivery
// when a member frees up; a plain group falls back to the primary's backpressure
// (drop/disconnect), preserving the original at-most-once semantics. Must hold
// b.mu.
func (b *Broker) deliverToGroupLocked(name string, members []*Subscription, ev *Event) {
	if b.tryPlaceOnGroupLocked(name, members, ev) {
		return
	}
	if groupIsAck(members) {
		b.enqueueGroupPendingLocked(name, ev)
		return
	}
	// Plain group, every member full: apply the primary member's backpressure.
	sort.Slice(members, func(i, j int) bool { return members[i].ID < members[j].ID })
	b.deliverLocked(members[0], ev)
}

// groupIsAck reports whether any member of the group runs at-least-once (so an
// undeliverable event should be held rather than dropped).
func groupIsAck(members []*Subscription) bool {
	for _, s := range members {
		if s.ackMode {
			return true
		}
	}
	return false
}

// enqueueGroupPendingLocked holds ev in the group's bounded backlog. If the
// backlog is at its cap the oldest is dropped and counted, so a stalled group
// cannot grow memory without bound (surfaced via Dropped, never silent).
func (b *Broker) enqueueGroupPendingLocked(name string, ev *Event) {
	q := b.groupPend[name]
	if len(q) >= b.lm.MaxGroupPending {
		q = q[1:] // drop oldest
		b.dropped++
	}
	b.groupPend[name] = append(q, ev)
	b.noteGroupDeliveredLocked(name, ev.Seq)
}

// recomputeGroupCommittedLocked recomputes and persists a durable group's
// committed offset: the highest sequence below which no event is still
// outstanding (delivered-unacked or backlogged). With nothing outstanding it is
// the highest sequence ever handed to the group. Persisted only when it advances.
// Must hold b.mu.
func (b *Broker) recomputeGroupCommittedLocked(name string) {
	if b.groupStore == nil || name == "" {
		return
	}
	minOutstanding := ^uint64(0)
	found := false
	for _, ev := range b.groupPend[name] {
		if ev.Seq < minOutstanding {
			minOutstanding = ev.Seq
			found = true
		}
	}
	for _, s := range b.subs {
		if s.group == name && s.ackMode {
			for seq := range s.inflight {
				if seq < minOutstanding {
					minOutstanding = seq
					found = true
				}
			}
		}
	}
	committed := b.groupMax[name]
	if found {
		committed = minOutstanding - 1
	}
	if committed > b.groupCmt[name] {
		b.groupCmt[name] = committed
		_ = b.groupStore.Save(name, committed)
	}
}

// drainGroupPendingLocked delivers as much of the group's backlog as members can
// currently take, in order, stopping at the first event no member can accept
// (so the backlog stays ordered and bounded). Must hold b.mu.
func (b *Broker) drainGroupPendingLocked(name string) {
	if name == "" {
		return
	}
	q := b.groupPend[name]
	for len(q) > 0 {
		ev := q[0]
		var members []*Subscription
		for _, s := range b.subs {
			if s.group == name && s.accepts(ev) {
				members = append(members, s)
			}
		}
		if !b.tryPlaceOnGroupLocked(name, members, ev) {
			break // no member can take it yet; leave the backlog intact
		}
		q = q[1:]
	}
	if len(q) == 0 {
		delete(b.groupPend, name)
	} else {
		b.groupPend[name] = q
	}
}

// resumeDurableGroupLocked is called when a durable group's first member joins
// (broker restart or a total outage): it loads the group's committed offset and
// replays the ring events after it into the group, so no un-acked work is lost
// across the gap. A brand-new group (no stored offset) starts from "now" and
// replays nothing. Must hold b.mu.
func (b *Broker) resumeDurableGroupLocked(name string, s *Subscription) {
	if b.groupStore == nil {
		return
	}
	if _, inmem := b.groupCmt[name]; !inmem {
		if c, ok := b.groupStore.Load(name); ok {
			b.groupCmt[name] = c
			if c > b.groupMax[name] {
				b.groupMax[name] = c
			}
		} else {
			// Brand-new durable group: start from the current sequence so it does
			// not replay all history, only events published from here on. Persist
			// the starting offset so a crash before the first ack still resumes here.
			b.groupCmt[name] = b.seq
			b.groupMax[name] = b.seq
			_ = b.groupStore.Save(name, b.seq)
			return
		}
	}
	committed := b.groupCmt[name]
	if committed >= b.seq {
		return // fully caught up — nothing to replay
	}
	snap := b.ring.snapshot() // oldest-first
	if len(snap) > 0 && snap[0].Seq > committed+1 {
		// The ring aged out events between the committed offset and its oldest
		// entry: they cannot be replayed from memory. Surface it (recover via the
		// event log if configured) rather than silently under-delivering.
		s.truncated = true
	}
	for i := range snap {
		ev := snap[i]
		if ev.Seq <= committed {
			continue
		}
		if b.groupPendHasLocked(name, ev.Seq) {
			continue // already held in the live backlog; don't double-deliver
		}
		var members []*Subscription
		for _, m := range b.subs {
			if m.group == name && m.accepts(&ev) {
				members = append(members, m)
			}
		}
		if len(members) == 0 {
			continue
		}
		evCopy := ev
		b.deliverToGroupLocked(name, members, &evCopy)
	}
}

// groupPendHasLocked reports whether seq is already in the group's backlog.
func (b *Broker) groupPendHasLocked(name string, seq uint64) bool {
	for _, ev := range b.groupPend[name] {
		if ev.Seq == seq {
			return true
		}
	}
	return false
}

// Ack marks a previously delivered event (by sequence) as processed by an
// at-least-once subscription, releasing its in-flight slot and letting the
// group's backlog advance onto this member. A no-op for a non-ack subscription
// or an unknown sequence (idempotent).
func (b *Broker) Ack(s *Subscription, seq uint64) {
	if s == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if s.inflight != nil {
		delete(s.inflight, seq)
	}
	b.drainGroupPendingLocked(s.group)
	b.recomputeGroupCommittedLocked(s.group)
}

// applyRetainedLocked updates the retained last-value store from an event's own
// retain intent (Retain / RetainDel / ExpiresAt). Because the intent is carried
// on the event, the same logic serves a fresh publish, a federated mirror, and a
// restart replay — so retained state is durable and federatable, not a
// broker-local side effect. Must hold b.mu.
func (b *Broker) applyRetainedLocked(ev *Event) {
	switch {
	case ev.RetainDel:
		// Tombstone: clear the topic's retained last-value. The event still fans
		// out live, so current subscribers observe the clear.
		delete(b.retained, ev.Topic)
		delete(b.retainExp, ev.Topic)
	case ev.Retain:
		// Bound the retained map. If a new topic would exceed the cap, first drop
		// any lapsed (TTL-expired) entries to make room — an active sweep bounded
		// to the moment it actually matters (at capacity).
		if _, exists := b.retained[ev.Topic]; !exists && len(b.retained) >= b.lm.MaxRetainedTopics {
			b.sweepExpiredRetainedLocked()
		}
		if _, exists := b.retained[ev.Topic]; exists || len(b.retained) < b.lm.MaxRetainedTopics {
			b.retained[ev.Topic] = ev
			if ev.ExpiresAt != "" {
				if t, err := time.Parse(time.RFC3339Nano, ev.ExpiresAt); err == nil {
					b.retainExp[ev.Topic] = t
				} else {
					delete(b.retainExp, ev.Topic)
				}
			} else {
				delete(b.retainExp, ev.Topic) // an update without a TTL clears any prior expiry
			}
		}
	}
}

// sweepExpiredRetainedLocked drops every retained value whose TTL has lapsed.
// Must hold b.mu.
func (b *Broker) sweepExpiredRetainedLocked() {
	now := b.now()
	for topic, exp := range b.retainExp {
		if now.After(exp) {
			delete(b.retained, topic)
			delete(b.retainExp, topic)
		}
	}
}

// EmitInternal publishes a system event from the broker operator itself — e.g.
// the gateway emitting its own lifecycle events (policy decisions, taint trips)
// onto the bus. It bypasses per-topic authorization and rate limiting (the
// operator running the broker is trusted to emit), but the event is still
// validated, capped, sealed into the hash chain, retained, fanned out subject
// to each subscriber's label clearance, and audited. source names the event's
// Publisher (a system identifier, not a WireGuard key).
func (b *Broker) EmitInternal(source, topic string, payload json.RawMessage, labels []string) (*Event, error) {
	return b.emitTrusted(topic, payload, labels, source, "", retainSpec{})
}

// retainSpec carries the retain intent through the trusted-emission path so a
// federated or internal event can set/clear a retained last-value the same way
// a publish does.
type retainSpec struct {
	set bool   // store as the topic's retained last-value
	del bool   // clear the retained last-value (tombstone)
	exp string // absolute RFC3339 expiry, or "" for none
}

// EmitFederated mirrors an event received from another broker into this one. It
// preserves the original publisher for attribution and sets Origin to the
// source broker so the event is never re-mirrored (loop prevention across a
// federation mesh). Like EmitInternal, it is a trusted operator path.
func (b *Broker) EmitFederated(topic string, payload json.RawMessage, labels []string, publisher, origin string, retain, retainDel bool, expiresAt string) (*Event, error) {
	r := retainSpec{set: retain, del: retainDel, exp: expiresAt}
	// Rate-limit federated ingestion per origin peer, so a compromised or lax
	// upstream cannot flood this broker (federated events otherwise bypass the
	// per-publisher token bucket).
	if !b.lim.allow("federation:" + origin) {
		return nil, fmt.Errorf("%w: federation from %s", ErrRateLimited, origin)
	}
	// Re-apply THIS broker's labeling and authorization for the topic, so an
	// untrustworthy upstream cannot launder taint (by omitting a label) or
	// smuggle past an explicit local deny. Evaluated as a "federation"
	// principal; the local emit labels are unioned in (never removing the
	// peer's), and an explicit local deny drops the mirror. The peer-asserted
	// publisher is preserved for attribution but the event carries Origin, so a
	// consumer knows Publisher is federated (peer-asserted), not locally proven.
	dec := b.auth.Publish(Identity{Key: "federation", FQDN: origin}, topic)
	if dec.Explicit && !dec.Allow {
		return nil, fmt.Errorf("%w: federated topic %q denied by local policy", ErrDenied, topic)
	}
	labels = unionLabels(labels, dec.Labels)
	return b.emitTrusted(topic, payload, labels, publisher, origin, r)
}

// emitTrusted is the shared trusted-emission core (bypasses per-topic authz +
// rate limit, still validated/capped/sealed/retained/fanned-out; not audited).
func (b *Broker) emitTrusted(topic string, payload json.RawMessage, labels []string, publisher, origin string, r retainSpec) (*Event, error) {
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
		Publisher: publisher,
		Labels:    labels,
		Origin:    origin,
		Retain:    r.set && !r.del,
		RetainDel: r.del,
		ExpiresAt: r.exp,
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
	if b.events != nil {
		_ = b.events.append(*ev)
	}
	b.applyRetainedLocked(ev)
	b.fanoutLocked(ev)
	b.mu.Unlock()

	// Trusted emission is not audited here: internal events derive from
	// decisions already in the ledger; federated events were audited by the
	// origin broker. External publish/subscribe are still audited.
	return ev, nil
}

// SubOptions parameterize a subscription.
type SubOptions struct {
	Topics       []string     // topic globs (at least one)
	Backpressure Backpressure // full-buffer policy
	Since        uint64       // >0 replays retained events with Seq > Since first
	// Capability is an optional signed token that can upgrade a default-deny on
	// a topic to allow. A capability-granted topic carries no label clearance
	// (it receives only unlabeled events) — the grant conveys access, not taint
	// clearance.
	Capability string
	// Group, if non-empty, joins this subscription to a named consumer group: a
	// live event matching the topics is delivered to exactly ONE member of the
	// group (round-robin), so a group of subscribers shares the load instead of
	// each receiving every event. Ungrouped subscriptions (the default) each get
	// their own copy. A group is scoped to this broker; retained state and
	// --since replay are per-connection and not supported with a group (Since>0
	// with a Group is refused), since replaying a window to every competing
	// consumer would duplicate it.
	Group string
	// Ack requests at-least-once delivery within a consumer group: each event
	// delivered to this member is held in-flight until the member calls Ack(seq).
	// If the member disconnects with un-acked events, they are redelivered to
	// another group member (so a crashed/rolling worker loses no work while the
	// group has another member). Requires Group; a member that reaches its
	// in-flight cap (SubQueue) is skipped by delivery until it acks.
	Ack bool
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
	if opts.Group != "" {
		// A group name is bounded like a topic (length + no control chars). Group
		// membership is capped implicitly by MaxSubs (each sub joins ≤1 group).
		if err := validateTopic(opts.Group, b.lm.MaxTopicLen); err != nil {
			return nil, fmt.Errorf("group: %w", err)
		}
		// Replay to a competing-consumer group would duplicate the window across
		// members; a group is live-only (at-least-once via Ack + redelivery).
		if opts.Since > 0 {
			return nil, fmt.Errorf("%w: --since replay is not supported with a consumer group", ErrBadTopic)
		}
	}
	// At-least-once needs a group to redeliver an un-acked event to another
	// member; ack mode without a group has no fallback consumer.
	if opts.Ack && opts.Group == "" {
		return nil, fmt.Errorf("%w: at-least-once (ack) requires a consumer group", ErrBadTopic)
	}

	clearAll := true
	var clear map[string]bool
	for _, t := range opts.Topics {
		if err := validateTopic(t, b.lm.MaxTopicLen); err != nil {
			return nil, err
		}
		dec := b.auth.Subscribe(id, t)
		if !dec.Allow {
			// A signed capability may upgrade a DEFAULT deny; the granted topic
			// carries no label clearance (empty Clear, not ClearAll).
			if !dec.Explicit && b.capAllows(id, t, opts.Capability) {
				dec = SubDecision{Allow: true, Reason: "capability grant"}
			} else {
				b.record(id, "pubsub/subscribe", t, "deny", dec.Reason, nil)
				return nil, fmt.Errorf("%w: subscribe %q: %s", ErrDenied, t, dec.Reason)
			}
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
		group:    opts.Group,
		ackMode:  opts.Ack,
		bp:       opts.Backpressure,
		ch:       make(chan *Event, b.lm.SubQueue),
		closed:   make(chan struct{}),
		b:        b,
	}
	if opts.Ack {
		s.inflight = map[uint64]*Event{}
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
	groupWasEmpty := false
	if s.group != "" {
		groupWasEmpty = b.groupN[s.group] == 0
		b.groupN[s.group]++
	}
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
	// A fresh subscriber (no --since) receives the current retained last-value
	// for each matching topic, in sequence order. A resuming subscriber
	// (Since>0) instead relies on --since replay, which already covers those
	// events, so retained is skipped there to avoid duplicates. Grouped
	// (competing-consumer) subscribers are skipped too: retained state fanned to
	// every joining member would duplicate it across the group.
	if opts.Since == 0 && s.group == "" {
		if _, ok := b.subs[s.ID]; ok {
			now := b.now()
			retained := make([]*Event, 0, len(b.retained))
			var expired []string
			for topic, ev := range b.retained {
				if exp, ok := b.retainExp[topic]; ok && now.After(exp) {
					expired = append(expired, topic) // TTL lapsed: evict, don't deliver
					continue
				}
				if s.accepts(ev) {
					retained = append(retained, ev)
				}
			}
			for _, topic := range expired {
				delete(b.retained, topic)
				delete(b.retainExp, topic)
			}
			sort.Slice(retained, func(i, j int) bool { return retained[i].Seq < retained[j].Seq })
			for _, ev := range retained {
				b.deliverLocked(s, ev)
				if _, ok := b.subs[s.ID]; !ok {
					break
				}
			}
		}
	}
	// A durable group resuming (its first member joining after a broker restart
	// or a total outage) replays the events after its committed offset, so no
	// un-acked work is lost across the gap.
	if groupWasEmpty && s.group != "" {
		b.resumeDurableGroupLocked(s.group, s)
	}
	// A newly-joined at-least-once member drains any backlog its group accrued
	// (e.g. events requeued when a peer died), so a replacement worker picks up
	// where the failed one left off.
	if s.ackMode {
		b.drainGroupPendingLocked(s.group)
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

// tryDeliverLocked attempts a non-blocking enqueue of ev to s and reports
// whether it succeeded. Unlike deliverLocked it never drops, disconnects, or
// evicts — a full buffer just returns false. Used by consumer-group fan-out to
// prefer a member with capacity. Must be called with b.mu held.
func (b *Broker) tryDeliverLocked(s *Subscription, ev *Event) bool {
	select {
	case s.ch <- ev:
		return true
	default:
		return false
	}
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
	b.dropped++ // aggregate; deliverLocked runs under b.mu
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
	if s.group != "" {
		remaining := b.groupN[s.group] - 1
		durable := b.groupStore != nil
		// At-least-once: a departing member's un-acked events are requeued to the
		// front of the group backlog so another member reprocesses them (a rolling
		// or crashed worker loses no work). A duplicate is possible if the member
		// died mid-processing — at-least-once, by design.
		if s.ackMode && len(s.inflight) > 0 {
			if remaining > 0 {
				repend := make([]*Event, 0, len(s.inflight))
				for _, ev := range s.inflight {
					repend = append(repend, ev)
				}
				sort.Slice(repend, func(i, j int) bool { return repend[i].Seq < repend[j].Seq })
				b.groupPend[s.group] = append(repend, b.groupPend[s.group]...)
			} else if !durable {
				// Last member of a NON-durable group left holding un-acked work — it
				// cannot be redelivered. Count it (surfaced, not silent).
				b.dropped += uint64(len(s.inflight))
			}
			// Durable group, last member: the un-acked events stay below the
			// committed offset (persisted), so they replay when the group resumes.
		}
		s.inflight = nil
		if remaining <= 0 {
			if durable {
				// Keep the committed offset (persisted) so the group resumes across
				// this outage; the un-acked/backlogged events are below it and will
				// replay when a member rejoins or the broker restarts.
				_ = b.groupStore.Save(s.group, b.groupCmt[s.group])
				delete(b.groupMax, s.group)
			} else if q := b.groupPend[s.group]; len(q) > 0 {
				b.dropped += uint64(len(q))
			}
			delete(b.groupN, s.group)
			delete(b.groupRR, s.group)
			delete(b.groupPend, s.group)
		} else {
			b.groupN[s.group] = remaining
			b.drainGroupPendingLocked(s.group) // hand the requeued work to a survivor
		}
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
	b.groupN = map[string]int{}
	b.groupRR = map[string]uint64{}
	b.groupPend = map[string][]*Event{}
	b.groupCmt = map[string]uint64{}
	b.groupMax = map[string]uint64{}
	b.retained = map[string]*Event{}
	b.retainExp = map[string]time.Time{}
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
