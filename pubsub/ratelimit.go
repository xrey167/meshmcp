package pubsub

import (
	"sync"
	"time"
)

// bucket is a token bucket rate limiter. It refills continuously at rate
// tokens/second up to a burst ceiling. It is used per-publisher-identity so a
// single peer cannot flood the bus and starve others' fan-out.
//
// The clock is injected (now func) so tests are deterministic without sleeping.
type bucket struct {
	mu     sync.Mutex
	rate   float64 // tokens per second (0 disables limiting)
	burst  float64 // maximum accumulated tokens
	tokens float64
	last   time.Time
	now    func() time.Time
}

func newBucket(rate float64, burst int, now func() time.Time) *bucket {
	if now == nil {
		now = time.Now
	}
	return &bucket{
		rate:   rate,
		burst:  float64(burst),
		tokens: float64(burst),
		last:   now(),
		now:    now,
	}
}

// allow consumes one token, refilling first. It returns false when the bucket
// is empty (the caller should reject the publish). A non-positive rate means
// no limiting, so allow always returns true.
func (b *bucket) allow() bool {
	if b.rate <= 0 {
		return true
	}
	b.mu.Lock()
	defer b.mu.Unlock()

	t := b.now()
	elapsed := t.Sub(b.last).Seconds()
	if elapsed > 0 {
		b.tokens += elapsed * b.rate
		if b.tokens > b.burst {
			b.tokens = b.burst
		}
		b.last = t
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// limiter is a map of per-identity token buckets. Buckets are created lazily
// on first publish by an identity and never expire within a broker's lifetime
// (a broker is a bounded, long-lived process; the key space is the mesh peer
// set, which is small and trusted at the WireGuard layer).
type limiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	rate    float64
	burst   int
	now     func() time.Time
}

func newLimiter(rate float64, burst int, now func() time.Time) *limiter {
	return &limiter{buckets: map[string]*bucket{}, rate: rate, burst: burst, now: now}
}

// allow reports whether the identity keyed by k may publish now.
func (l *limiter) allow(k string) bool {
	if l.rate <= 0 {
		return true
	}
	l.mu.Lock()
	b := l.buckets[k]
	if b == nil {
		b = newBucket(l.rate, l.burst, l.now)
		l.buckets[k] = b
	}
	l.mu.Unlock()
	return b.allow()
}
