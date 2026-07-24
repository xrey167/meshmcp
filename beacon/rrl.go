package beacon

import (
	"context"
	"net"
	"sync"
	"time"
)

// Response Rate Limiting for the authoritative DNS server. The beacon answers
// public UDP queries (A for <label>.<zone>, and TXT for _acme-challenge.* — up to
// a few hundred bytes), which a spoofed-source attacker could use for reflection/
// amplification. RRL caps how fast one client PREFIX can pull full UDP answers:
// over the cap, a fraction of responses are "slipped" (sent truncated with TC=1 so
// a legitimate resolver retries over TCP) and the rest are dropped. TCP queries
// bypass RRL entirely — a completed TCP handshake proves the source is not spoofed.
//
// Keying by prefix (IPv4 /24, IPv6 /64) rather than exact address stops trivial
// per-address evasion; the small collateral (a noisy neighbor in the same /24 can
// nudge you toward TCP) is acceptable and legitimate resolvers still resolve via
// the TCP fall-back. Let's Encrypt validation is unaffected: its distributed
// resolvers each sit in their own prefix and query a given challenge name only a
// handful of times, far under the per-prefix budget.
const (
	rrlRate       = 15.0 // sustained full-answer responses per second per prefix
	rrlBurst      = 30.0 // token-bucket ceiling (short bursts)
	rrlSlipEvery  = 2    // send 1 truncated (TCP-forcing) response per this many over-limit queries
	rrlMaxBuckets = 1 << 16
	rrlGCInterval = 30 * time.Second
)

type rrlDecision int

const (
	rrlAllow rrlDecision = iota // send the full answer
	rrlSlip                     // send a truncated (TC=1) answer, forcing TCP retry
	rrlDrop                     // send nothing
)

type rrlBucket struct {
	tokens  float64
	last    time.Time
	slipCtr int
}

// rrl is a per-prefix token-bucket rate limiter with a bounded number of buckets.
type rrl struct {
	mu         sync.Mutex
	buckets    map[string]*rrlBucket
	rate       float64
	burst      float64
	slip       int
	maxBuckets int
	now        func() time.Time // injectable for tests
}

func newRRL() *rrl {
	return &rrl{
		buckets:    map[string]*rrlBucket{},
		rate:       rrlRate,
		burst:      rrlBurst,
		slip:       rrlSlipEvery,
		maxBuckets: rrlMaxBuckets,
		now:        time.Now,
	}
}

// decide reports how to answer a UDP query from ip: allow, slip (truncate), or drop.
func (r *rrl) decide(ip net.IP) rrlDecision {
	key := rrlPrefix(ip)
	now := r.now()
	r.mu.Lock()
	defer r.mu.Unlock()

	b := r.buckets[key]
	if b == nil {
		if len(r.buckets) >= r.maxBuckets {
			// At capacity: keep no new state so a random-source flood cannot grow the
			// map. ALWAYS slip (never drop): a TC=1 response echoes only the question,
			// so it is ~the query's size (amplification factor ~1) and costs nothing to
			// send, while it preserves the retry-over-TCP signal a genuinely new
			// legitimate client needs to escape the cap. Dropping here would blackhole
			// new clients during a flood with no upside.
			return rrlSlip
		}
		r.buckets[key] = &rrlBucket{tokens: r.burst - 1, last: now}
		return rrlAllow
	}

	if elapsed := now.Sub(b.last).Seconds(); elapsed > 0 {
		b.tokens += elapsed * r.rate
		if b.tokens > r.burst {
			b.tokens = r.burst
		}
		b.last = now
	}
	if b.tokens >= 1 {
		b.tokens--
		return rrlAllow
	}
	b.slipCtr++
	if r.slip > 0 && b.slipCtr%r.slip == 0 {
		return rrlSlip
	}
	return rrlDrop
}

// gc drops buckets that have refilled to full (idle clients): forgetting them is
// safe because they reappear fresh, and it bounds memory to the set of currently
// rate-relevant prefixes.
func (r *rrl) gc() {
	now := r.now()
	r.mu.Lock()
	defer r.mu.Unlock()
	for k, b := range r.buckets {
		if b.tokens+now.Sub(b.last).Seconds()*r.rate >= r.burst {
			delete(r.buckets, k)
		}
	}
}

func (r *rrl) gcLoop(ctx context.Context) {
	t := time.NewTicker(rrlGCInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.gc()
		}
	}
}

// rrlPrefix maps an address to its rate-limiting key: /24 for IPv4, /64 for IPv6.
func rrlPrefix(ip net.IP) string {
	if v4 := ip.To4(); v4 != nil {
		return "4:" + string(v4[:3])
	}
	if v6 := ip.To16(); v6 != nil {
		return "6:" + string(v6[:8])
	}
	return "x:" + ip.String()
}
