package pubsub

import (
	"sync"
	"sync/atomic"
)

// Subscription is a live delivery stream to one subscriber. Read events from
// C(); the channel is closed when the subscription ends (via Close, a
// Disconnect-policy overflow, or broker shutdown), so a reader loop is simply
// `for ev := range sub.C()`.
type Subscription struct {
	ID       uint64
	ident    Identity
	topics   []string        // topic globs
	clearAll bool            // cleared for every label
	clear    map[string]bool // labels this subscription may receive (when !clearAll)
	bp       Backpressure
	ch       chan *Event
	closed   chan struct{}

	dropped   uint64 // atomic: events dropped by DropOldest backpressure
	truncated bool   // replay could not reach the requested sequence

	closeOnce sync.Once
	b         *Broker
}

// C returns the receive channel of delivered events. It is closed when the
// subscription ends.
func (s *Subscription) C() <-chan *Event { return s.ch }

// Done is closed when the subscription ends; useful in a select alongside
// other work.
func (s *Subscription) Done() <-chan struct{} { return s.closed }

// Identity returns the subscriber's cryptographic identity.
func (s *Subscription) Identity() Identity { return s.ident }

// Dropped returns the number of events dropped so far by DropOldest
// backpressure. A non-zero value means the subscriber saw a gap.
func (s *Subscription) Dropped() uint64 { return atomic.LoadUint64(&s.dropped) }

// Truncated reports whether a replay request could not be fully satisfied
// because the requested sequence had already aged out of retention.
func (s *Subscription) Truncated() bool { return s.truncated }

// Close ends the subscription. Idempotent.
func (s *Subscription) Close() { s.b.Unsubscribe(s) }

// accepts reports whether ev should be delivered to this subscription: the
// topic must match one of its patterns, and every data-flow label the event
// carries must be in the subscription's cleared set (taint containment).
func (s *Subscription) accepts(ev *Event) bool {
	if !matchGlob(s.topics, ev.Topic) {
		return false
	}
	if s.clearAll {
		return true
	}
	for _, l := range ev.Labels {
		if !s.clear[l] {
			return false
		}
	}
	return true
}
