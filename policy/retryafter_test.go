package policy

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// TestRateLimitRetryAfter verifies a rate-limit deny carries a RetryAfter
// derived from the bucket's actual deficit and refill rate.
func TestRateLimitRetryAfter(t *testing.T) {
	pol := &Policy{Rules: []Rule{{
		Peers: []string{"*"},
		Tools: []string{"echo"},
		Allow: true,
		Rate:  &RateLimit{Max: 2, Per: "1m"},
	}}}
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	eng := NewEngine(pol, func() time.Time { return now }, nil)

	// Consume both tokens.
	for i := 0; i < 2; i++ {
		d := eng.DecideToolCall("a.mesh", "k1", "echo", nil)
		if !d.Allow {
			t.Fatalf("call %d: expected allow, got %+v", i, d)
		}
		if d.RetryAfter != 0 {
			t.Fatalf("call %d: allow must carry zero RetryAfter, got %v", i, d.RetryAfter)
		}
	}

	// Bucket is now empty. Refill rate = 2 tokens / 60s, deficit = 1 token,
	// so the honest retry-after is exactly 30s.
	d := eng.DecideToolCall("a.mesh", "k1", "echo", nil)
	if d.Allow || d.Outcome != OutcomeDeny {
		t.Fatalf("third call: expected deny, got %+v", d)
	}
	if !strings.Contains(d.Reason, "rate limit exceeded") {
		t.Fatalf("reason: %q", d.Reason)
	}
	if d.RetryAfter != 30*time.Second {
		t.Fatalf("RetryAfter: got %v want 30s", d.RetryAfter)
	}

	// After 15s the bucket holds 0.5 tokens; deficit 0.5 -> 15s remaining.
	now = now.Add(15 * time.Second)
	d = eng.DecideToolCall("a.mesh", "k1", "echo", nil)
	if d.Allow {
		t.Fatalf("expected deny after 15s, got %+v", d)
	}
	if d.RetryAfter != 15*time.Second {
		t.Fatalf("RetryAfter after partial refill: got %v want 15s", d.RetryAfter)
	}

	// After the full window the call is admitted again and RetryAfter is zero.
	now = now.Add(60 * time.Second)
	d = eng.DecideToolCall("a.mesh", "k1", "echo", nil)
	if !d.Allow || d.RetryAfter != 0 {
		t.Fatalf("expected allow with zero RetryAfter, got %+v", d)
	}
}

// TestRateLimitRetryAfterBounded checks the invariant a client relies on: the
// deny's RetryAfter is within (0, window] for a fresh exhaustion.
func TestRateLimitRetryAfterBounded(t *testing.T) {
	pol := &Policy{Rules: []Rule{{Allow: true, Rate: &RateLimit{Max: 2, Per: "1m"}}}}
	now := time.Now()
	eng := NewEngine(pol, func() time.Time { return now }, nil)
	for i := 0; i < 2; i++ {
		if d := eng.DecideToolCall("a.mesh", "k1", "x", nil); !d.Allow {
			t.Fatalf("call %d: %+v", i, d)
		}
	}
	d := eng.DecideToolCall("a.mesh", "k1", "x", nil)
	if d.Allow {
		t.Fatalf("expected deny: %+v", d)
	}
	if d.RetryAfter <= 0 || d.RetryAfter > time.Minute {
		t.Fatalf("RetryAfter %v not in (0, 1m]", d.RetryAfter)
	}
}

// TestRateLimitImpossibleCostSuppressesRetryAfter: a rule whose cost exceeds
// max can never be admitted (tokens cap at max < cost), so the deny must carry
// NO retry hint — a finite value would send an honoring client into an
// infinite back-off/retry loop on a promise that cannot come true.
func TestRateLimitImpossibleCostSuppressesRetryAfter(t *testing.T) {
	pol := &Policy{Rules: []Rule{{
		Peers: []string{"*"},
		Tools: []string{"echo"},
		Allow: true,
		Rate:  &RateLimit{Max: 5, Per: "1m", Cost: 50},
	}}}
	now := time.Now()
	eng := NewEngine(pol, func() time.Time { return now }, nil)

	// Full bucket (5 tokens) still cannot cover cost 50: deny, no hint.
	d := eng.DecideToolCall("a.mesh", "k1", "echo", nil)
	if d.Allow || d.Outcome != OutcomeDeny {
		t.Fatalf("expected deny, got %+v", d)
	}
	if d.RetryAfter != 0 {
		t.Fatalf("impossible cost must suppress RetryAfter, got %v", d.RetryAfter)
	}

	// Even after a full window's refill the answer is the same.
	now = now.Add(time.Minute)
	d = eng.DecideToolCall("a.mesh", "k1", "echo", nil)
	if d.Allow || d.RetryAfter != 0 {
		t.Fatalf("post-refill: expected deny with zero RetryAfter, got %+v", d)
	}

	// And the wire body carries no data.retryAfterMs for it.
	if body := DenialBody(json.RawMessage(`1`), "blocked", d.RetryAfter); strings.Contains(string(body), "retryAfterMs") {
		t.Fatalf("impossible-cost denial must not carry retryAfterMs: %s", body)
	}
}

// TestDenialBodyRetryAfter verifies the wire form: a rate-limit deny carries
// error.data.retryAfterMs; other denials carry no data field.
func TestDenialBodyRetryAfter(t *testing.T) {
	body := DenialBody(json.RawMessage(`7`), "slow down", 1500*time.Millisecond)
	var resp struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Error   struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
			Data    struct {
				RetryAfterMs int64 `json:"retryAfterMs"`
			} `json:"data"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("unmarshal %s: %v", body, err)
	}
	if resp.Error.Code != -32001 || resp.Error.Message != "slow down" {
		t.Fatalf("error: %+v", resp.Error)
	}
	if resp.Error.Data.RetryAfterMs != 1500 {
		t.Fatalf("retryAfterMs: got %d want 1500", resp.Error.Data.RetryAfterMs)
	}

	plain := DenialBody(nil, "no", 0)
	if strings.Contains(string(plain), "data") {
		t.Fatalf("plain denial must not carry data: %s", plain)
	}
	if !strings.Contains(string(plain), `"id":null`) {
		t.Fatalf("empty id must serialize as null: %s", plain)
	}
}
