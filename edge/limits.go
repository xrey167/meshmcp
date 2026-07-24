package edge

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// fixedWindowLimiter is a per-key fixed-window rate limiter used for the cheap
// pre-auth edge checks (registration and unauthenticated requests keyed by
// client IP). It mirrors the ringLimiter pattern used elsewhere in the tree:
// small, allocation-light, clock-injected for tests. It is not a token bucket —
// bursts up to the cap are allowed within a window and reset at the boundary.
type fixedWindowLimiter struct {
	mu     sync.Mutex
	max    int
	window time.Duration
	seen   map[string]*windowCount
	now    func() time.Time
}

type windowCount struct {
	start time.Time
	count int
}

func newFixedWindowLimiter(max int, window time.Duration, now func() time.Time) *fixedWindowLimiter {
	if now == nil {
		now = time.Now
	}
	return &fixedWindowLimiter{max: max, window: window, seen: map[string]*windowCount{}, now: now}
}

// allow reports whether an event for key is permitted right now, recording it
// against the current window when it is.
func (l *fixedWindowLimiter) allow(key string) bool {
	if l.max <= 0 {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	t := l.now()
	wc := l.seen[key]
	if wc == nil || t.Sub(wc.start) >= l.window {
		l.seen[key] = &windowCount{start: t, count: 1}
		return true
	}
	if wc.count >= l.max {
		return false
	}
	wc.count++
	return true
}

// tokenBucket is a per-key token-bucket limiter for authenticated per-client
// request rates. Refills at rate tokens/sec up to burst.
type tokenBucket struct {
	mu      sync.Mutex
	rate    float64
	burst   float64
	buckets map[string]*bucketState
	now     func() time.Time
}

type bucketState struct {
	tokens float64
	last   time.Time
}

func newTokenBucket(ratePerSec, burst int, now func() time.Time) *tokenBucket {
	if now == nil {
		now = time.Now
	}
	return &tokenBucket{
		rate:    float64(ratePerSec),
		burst:   float64(burst),
		buckets: map[string]*bucketState{},
		now:     now,
	}
}

// allow reports whether one request for key is permitted, consuming a token.
func (b *tokenBucket) allow(key string) bool {
	if b.rate <= 0 {
		return true
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	t := b.now()
	st := b.buckets[key]
	if st == nil {
		b.buckets[key] = &bucketState{tokens: b.burst - 1, last: t}
		return true
	}
	elapsed := t.Sub(st.last).Seconds()
	st.tokens += elapsed * b.rate
	if st.tokens > b.burst {
		st.tokens = b.burst
	}
	st.last = t
	if st.tokens < 1 {
		return false
	}
	st.tokens--
	return true
}

// clientIP extracts the connection's remote host — the honest transport peer.
// It intentionally ignores forwarding headers: for audit attribution the
// authority is who actually connected (RemoteAddr). Rate-limit keying uses
// rateLimitKey, which may honor a trusted front's forwarding header.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// rateLimitKey returns the per-caller key for the pre-auth rate limiters. In
// behind_front mode the edge binds loopback, so RemoteAddr is the local front
// for EVERY external caller and clientIP alone would collapse all per-IP buckets
// into one global bucket keyed on the front — a trivial whole-ingress DoS (one
// caller exhausts the limit for all). When the operator has named a trusted
// forwarding header (only permitted with behind_front), key on the right-most
// value of that header: with a single trusted front the right-most entry is the
// address the front observed for the connection — the real peer — and a client
// cannot shrink it by prepending spoofed entries. Falls back to clientIP when no
// header is configured or the header is absent/empty.
func (s *Server) rateLimitKey(r *http.Request) string {
	if s.cfg.BehindFront && s.cfg.ForwardedHeader != "" {
		if v := r.Header.Get(s.cfg.ForwardedHeader); v != "" {
			parts := strings.Split(v, ",")
			if ip := strings.TrimSpace(parts[len(parts)-1]); ip != "" {
				return ip
			}
		}
	}
	return clientIP(r)
}
