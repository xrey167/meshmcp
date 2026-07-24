package edge

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestFixedWindowLimiter(t *testing.T) {
	now := time.Unix(0, 0)
	l := newFixedWindowLimiter(3, time.Minute, func() time.Time { return now })

	for i := 0; i < 3; i++ {
		if !l.allow("ip1") {
			t.Fatalf("request %d should be allowed within cap", i)
		}
	}
	if l.allow("ip1") {
		t.Fatal("4th request in window must be denied")
	}
	// A different key has its own window.
	if !l.allow("ip2") {
		t.Fatal("independent key should be allowed")
	}
	// After the window elapses, the counter resets.
	now = now.Add(time.Minute)
	if !l.allow("ip1") {
		t.Fatal("request after window reset should be allowed")
	}
}

func TestFixedWindowLimiterDisabled(t *testing.T) {
	l := newFixedWindowLimiter(0, time.Minute, nil)
	for i := 0; i < 100; i++ {
		if !l.allow("k") {
			t.Fatal("max<=0 must allow all")
		}
	}
}

func TestTokenBucket(t *testing.T) {
	now := time.Unix(0, 0)
	b := newTokenBucket(1 /*per sec*/, 2 /*burst*/, func() time.Time { return now })

	// Burst of 2 allowed immediately.
	if !b.allow("c") || !b.allow("c") {
		t.Fatal("burst of 2 should be allowed")
	}
	if b.allow("c") {
		t.Fatal("3rd immediate request should be denied (burst exhausted)")
	}
	// After 1 second, one token refills.
	now = now.Add(time.Second)
	if !b.allow("c") {
		t.Fatal("request after 1s refill should be allowed")
	}
	if b.allow("c") {
		t.Fatal("second request after single refill should be denied")
	}
}

func TestClientIP(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "203.0.113.9:44321"
	if got := clientIP(r); got != "203.0.113.9" {
		t.Fatalf("clientIP = %q", got)
	}
	// A malformed remote addr falls back to the raw value.
	r.RemoteAddr = "weird"
	if got := clientIP(r); got != "weird" {
		t.Fatalf("clientIP fallback = %q", got)
	}
}

// TestRateLimitKey proves the pre-auth rate-limit key uses the trusted forwarding
// header ONLY behind a front, so per-IP limits stay per-IP instead of collapsing
// to one global bucket keyed on the loopback front.
func TestRateLimitKey(t *testing.T) {
	newReq := func(remote, xff string) *http.Request {
		r := httptest.NewRequest("POST", "/token", nil)
		r.RemoteAddr = remote
		if xff != "" {
			r.Header.Set("X-Forwarded-For", xff)
		}
		return r
	}

	// Behind a front with a configured trusted header: two callers arriving via
	// the same loopback front get DISTINCT keys from the right-most XFF value.
	front := &Server{cfg: Config{BehindFront: true, ForwardedHeader: "X-Forwarded-For"}}
	if got := front.rateLimitKey(newReq("127.0.0.1:5000", "198.51.100.7")); got != "198.51.100.7" {
		t.Fatalf("behind-front key = %q, want the forwarded client IP", got)
	}
	// A client-prepended spoof cannot shrink the key: the right-most entry (added
	// by the trusted front) still wins.
	if got := front.rateLimitKey(newReq("127.0.0.1:5000", "1.2.3.4, 198.51.100.7")); got != "198.51.100.7" {
		t.Fatalf("spoofed prefix changed the key: %q", got)
	}
	// Header absent behind a front: fall back to RemoteAddr (the front) rather
	// than an empty key.
	if got := front.rateLimitKey(newReq("127.0.0.1:5000", "")); got != "127.0.0.1" {
		t.Fatalf("missing-header fallback = %q, want RemoteAddr host", got)
	}

	// Direct-TLS edge (no behind_front): forwarding headers are ignored, so a
	// caller cannot spoof the key — it is always RemoteAddr.
	direct := &Server{cfg: Config{}}
	if got := direct.rateLimitKey(newReq("203.0.113.9:44321", "10.0.0.1")); got != "203.0.113.9" {
		t.Fatalf("direct edge honored a forwarding header: %q", got)
	}
}
