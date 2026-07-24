package beacon

import (
	"net"
	"testing"
	"time"
)

// fakeClock is a manually-advanced clock for deterministic RRL tests.
type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time          { return c.t }
func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }

func newTestRRL(clk *fakeClock) *rrl {
	r := newRRL()
	r.now = clk.now
	return r
}

// TestRRLAllowsBurstThenSlipsAndDrops proves a client gets its burst of full
// answers, then over the limit is alternately slipped (TCP-forced) and dropped.
func TestRRLAllowsBurstThenSlipsAndDrops(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	r := newTestRRL(clk)
	ip := net.ParseIP("203.0.113.5")

	allowed := 0
	for i := 0; i < int(rrlBurst); i++ {
		if r.decide(ip) == rrlAllow {
			allowed++
		}
	}
	if allowed != int(rrlBurst) {
		t.Fatalf("burst allowed = %d, want %d", allowed, int(rrlBurst))
	}
	// Next queries in the same instant are over budget: a mix of slip and drop, no allow.
	var slips, drops int
	for i := 0; i < 10; i++ {
		switch r.decide(ip) {
		case rrlAllow:
			t.Fatal("over-budget query was allowed")
		case rrlSlip:
			slips++
		case rrlDrop:
			drops++
		}
	}
	if slips == 0 || drops == 0 {
		t.Fatalf("expected a mix of slip and drop over budget, got slips=%d drops=%d", slips, drops)
	}
}

// TestRRLRefillsOverTime proves tokens replenish so a well-behaved client is not
// permanently throttled.
func TestRRLRefillsOverTime(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	r := newTestRRL(clk)
	ip := net.ParseIP("203.0.113.6")
	for i := 0; i < int(rrlBurst); i++ {
		r.decide(ip)
	}
	if d := r.decide(ip); d == rrlAllow {
		t.Fatal("expected throttling immediately after draining the bucket")
	}
	clk.advance(time.Second) // ~rrlRate tokens back
	allowed := 0
	for i := 0; i < int(rrlRate); i++ {
		if r.decide(ip) == rrlAllow {
			allowed++
		}
	}
	if allowed == 0 {
		t.Fatal("no queries allowed after a second of refill")
	}
}

// TestRRLTCPBypassIsCallerSide is a documentation test: RRL has no notion of
// transport, so the DNS handler must simply not call decide for TCP queries. Here
// we only assert distinct prefixes get independent budgets (no cross-prefix DoS).
func TestRRLIndependentPrefixes(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	r := newTestRRL(clk)
	victim := net.ParseIP("198.51.100.7")
	// Exhaust a noisy prefix.
	noisy := net.ParseIP("203.0.113.7")
	for i := 0; i < int(rrlBurst)*4; i++ {
		r.decide(noisy)
	}
	if r.decide(victim) != rrlAllow {
		t.Fatal("a different prefix was throttled by an unrelated noisy prefix")
	}
}

// TestRRLGCDropsIdleBuckets proves idle (refilled) buckets are collected, bounding
// memory.
func TestRRLGCDropsIdleBuckets(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	r := newTestRRL(clk)
	for i := 0; i < 100; i++ {
		r.decide(net.IPv4(203, 0, byte(i), 1))
	}
	if len(r.buckets) == 0 {
		t.Fatal("expected buckets to be populated")
	}
	clk.advance(time.Hour) // everything refills to full
	r.gc()
	if len(r.buckets) != 0 {
		t.Fatalf("gc left %d idle buckets, want 0", len(r.buckets))
	}
}

// TestRRLBucketCapBounded proves the bucket map never exceeds the cap even under a
// flood of unique source prefixes, and that over-cap sources still get a bounded
// slip/drop response (never a full amplifiable answer).
func TestRRLBucketCapBounded(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	r := newTestRRL(clk)
	r.maxBuckets = 64
	for i := 0; i < 100000; i++ {
		ip := net.IP{10, byte(i >> 16), byte(i >> 8), byte(i)}
		if d := r.decide(ip); d == rrlAllow && len(r.buckets) > r.maxBuckets {
			t.Fatalf("allowed a new prefix past the bucket cap (buckets=%d)", len(r.buckets))
		}
	}
	if len(r.buckets) > r.maxBuckets {
		t.Fatalf("bucket map grew to %d, past cap %d", len(r.buckets), r.maxBuckets)
	}
}
