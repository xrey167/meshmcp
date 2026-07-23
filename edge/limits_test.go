package edge

import (
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
