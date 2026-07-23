package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// keyedCtx builds the context dispatch would: a ToolCallInfo whose Meta
// carries the router's idempotency key.
func keyedCtx(key string) context.Context {
	meta := json.RawMessage(fmt.Sprintf(`{"meshmcp.io/idempotency-key":%q}`, key))
	return withToolCall(context.Background(), ToolCallInfo{Tool: "x", Meta: meta})
}

// TestIdempotencySingleFlight: N concurrent calls with the SAME key — exactly
// one execution, and every caller receives the first execution's result.
// Run with -count=20 to shake out interleavings (-race is unavailable here).
func TestIdempotencySingleFlight(t *testing.T) {
	var execs int32
	h := Idempotency(NewMemClaimStore(), time.Minute)(func(context.Context, json.RawMessage) (ToolResult, error) {
		atomic.AddInt32(&execs, 1)
		time.Sleep(30 * time.Millisecond) // hold the claim pending while duplicates arrive
		return ToolResult{Content: []Content{Text("payload")}}, nil
	})
	const n = 16
	var wg sync.WaitGroup
	results := make([]ToolResult, n)
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i], errs[i] = h(keyedCtx("k-flight"), nil)
		}(i)
	}
	wg.Wait()
	if got := atomic.LoadInt32(&execs); got != 1 {
		t.Fatalf("want exactly 1 execution, got %d", got)
	}
	for i := 0; i < n; i++ {
		if errs[i] != nil {
			t.Fatalf("caller %d: unexpected error %v", i, errs[i])
		}
		if len(results[i].Content) != 1 || results[i].Content[0].Text != "payload" {
			t.Fatalf("caller %d: wrong result %+v", i, results[i])
		}
	}
}

// TestIdempotencyReplayAfterCompletion: a replay of a completed key returns
// the recorded result without re-executing.
func TestIdempotencyReplayAfterCompletion(t *testing.T) {
	var execs int32
	h := Idempotency(NewMemClaimStore(), time.Minute)(func(context.Context, json.RawMessage) (ToolResult, error) {
		atomic.AddInt32(&execs, 1)
		return ToolResult{Content: []Content{Text("first")}}, nil
	})
	r1, err := h(keyedCtx("k-replay"), nil)
	if err != nil || r1.Content[0].Text != "first" {
		t.Fatalf("first call: %+v err=%v", r1, err)
	}
	r2, err := h(keyedCtx("k-replay"), nil)
	if err != nil || r2.Content[0].Text != "first" {
		t.Fatalf("replay: %+v err=%v", r2, err)
	}
	if execs != 1 {
		t.Fatalf("replay must not re-execute, got %d executions", execs)
	}
}

// TestIdempotencyDistinctKeysIndependent: different keys each execute.
func TestIdempotencyDistinctKeysIndependent(t *testing.T) {
	var execs int32
	h := Idempotency(NewMemClaimStore(), time.Minute)(func(context.Context, json.RawMessage) (ToolResult, error) {
		atomic.AddInt32(&execs, 1)
		return ToolResult{}, nil
	})
	if _, err := h(keyedCtx("k-a"), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := h(keyedCtx("k-b"), nil); err != nil {
		t.Fatal(err)
	}
	if execs != 2 {
		t.Fatalf("distinct keys must both execute, got %d", execs)
	}
}

// TestIdempotencyNoKeyPassesThrough: calls without a key (or without any
// call info) are untouched — every call executes.
func TestIdempotencyNoKeyPassesThrough(t *testing.T) {
	var execs int32
	h := Idempotency(NewMemClaimStore(), time.Minute)(func(context.Context, json.RawMessage) (ToolResult, error) {
		atomic.AddInt32(&execs, 1)
		return ToolResult{}, nil
	})
	for _, ctx := range []context.Context{
		context.Background(), // no call info at all
		withToolCall(context.Background(), ToolCallInfo{Tool: "x"}),                                       // no _meta
		withToolCall(context.Background(), ToolCallInfo{Tool: "x", Meta: json.RawMessage(`{"other":1}`)}), // _meta without our key
	} {
		if _, err := h(ctx, nil); err != nil {
			t.Fatal(err)
		}
		if _, err := h(ctx, nil); err != nil {
			t.Fatal(err)
		}
	}
	if execs != 6 {
		t.Fatalf("keyless calls must all execute, got %d", execs)
	}
}

// TestIdempotencyTTLExpiryReallows: after the TTL passes, the same key
// executes again (the documented dedup horizon).
func TestIdempotencyTTLExpiryReallows(t *testing.T) {
	var execs int32
	h := Idempotency(NewMemClaimStore(), 30*time.Millisecond)(func(context.Context, json.RawMessage) (ToolResult, error) {
		atomic.AddInt32(&execs, 1)
		return ToolResult{}, nil
	})
	if _, err := h(keyedCtx("k-ttl"), nil); err != nil {
		t.Fatal(err)
	}
	time.Sleep(60 * time.Millisecond)
	if _, err := h(keyedCtx("k-ttl"), nil); err != nil {
		t.Fatal(err)
	}
	if execs != 2 {
		t.Fatalf("an expired key must execute again, got %d executions", execs)
	}
}

// errClaimStore always fails — the store-down case.
type errClaimStore struct{}

func (errClaimStore) Claim(string, time.Time, time.Time) (bool, bool, []byte, error) {
	return false, false, nil, errors.New("store down")
}
func (errClaimStore) Complete(string, []byte, time.Time, time.Time) error {
	return errors.New("store down")
}

// TestIdempotencyStoreErrorFailsClosed: a broken store must refuse the call —
// the handler is never invoked (never double-execute on uncertainty).
func TestIdempotencyStoreErrorFailsClosed(t *testing.T) {
	var execs int32
	h := Idempotency(errClaimStore{}, time.Minute)(func(context.Context, json.RawMessage) (ToolResult, error) {
		atomic.AddInt32(&execs, 1)
		return ToolResult{}, nil
	})
	_, err := h(keyedCtx("k-err"), nil)
	if err == nil || !strings.Contains(err.Error(), "refusing to execute") {
		t.Fatalf("want fail-closed refusal, got err=%v", err)
	}
	if execs != 0 {
		t.Fatalf("handler must not run when the store is down, got %d executions", execs)
	}
	// A keyless call is unaffected by the broken store.
	if _, err := h(context.Background(), nil); err != nil {
		t.Fatalf("keyless call must pass through: %v", err)
	}
}

// TestIdempotencyOversizedResultUncacheable: an oversized result reaches the
// first caller intact, but its replay returns an error — never a silent
// re-execution.
func TestIdempotencyOversizedResultUncacheable(t *testing.T) {
	var execs int32
	big := strings.Repeat("x", MaxCachedResultBytes+1)
	h := Idempotency(NewMemClaimStore(), time.Minute)(func(context.Context, json.RawMessage) (ToolResult, error) {
		atomic.AddInt32(&execs, 1)
		return ToolResult{Content: []Content{Text(big)}}, nil
	})
	r1, err := h(keyedCtx("k-big"), nil)
	if err != nil || r1.Content[0].Text != big {
		t.Fatalf("first caller must get the full result, err=%v", err)
	}
	_, err = h(keyedCtx("k-big"), nil)
	if err == nil || !strings.Contains(err.Error(), "cache cap") {
		t.Fatalf("replay of an uncacheable result must error, got %v", err)
	}
	if execs != 1 {
		t.Fatalf("replay must not re-execute, got %d executions", execs)
	}
}

// TestIdempotencyHandlerErrorReplayed: a handler error is the terminal
// outcome — a replay returns the same error without re-executing.
func TestIdempotencyHandlerErrorReplayed(t *testing.T) {
	var execs int32
	h := Idempotency(NewMemClaimStore(), time.Minute)(func(context.Context, json.RawMessage) (ToolResult, error) {
		atomic.AddInt32(&execs, 1)
		return ToolResult{}, errors.New("boom once")
	})
	_, err1 := h(keyedCtx("k-fail"), nil)
	_, err2 := h(keyedCtx("k-fail"), nil)
	if err1 == nil || err2 == nil || err1.Error() != err2.Error() {
		t.Fatalf("replay must return the recorded error: %v vs %v", err1, err2)
	}
	if execs != 1 {
		t.Fatalf("a failed execution must not be re-run, got %d executions", execs)
	}
}

// TestIdempotencyPanicCompletesClaim: a handler panic still terminates the
// claim (redacted, like RecoverPanics) so replays are not stalled until TTL.
func TestIdempotencyPanicCompletesClaim(t *testing.T) {
	var execs int32
	h := Idempotency(NewMemClaimStore(), time.Minute)(func(context.Context, json.RawMessage) (ToolResult, error) {
		atomic.AddInt32(&execs, 1)
		panic("secret internal detail")
	})
	_, err1 := h(keyedCtx("k-panic"), nil)
	if err1 == nil || strings.Contains(err1.Error(), "secret internal detail") {
		t.Fatalf("panic must become a redacted error, got %v", err1)
	}
	_, err2 := h(keyedCtx("k-panic"), nil)
	if err2 == nil || err2.Error() != err1.Error() {
		t.Fatalf("replay must return the recorded panic error without re-executing: %v", err2)
	}
	if execs != 1 {
		t.Fatalf("want 1 execution, got %d", execs)
	}
}

// TestIdempotencyClaimsAreToolScoped: the conveyed key namespace is
// client-controllable, so the SAME key presented on two DIFFERENT tools must
// never share a claim — a shared claim would silently suppress the second
// tool's execution and serve it the first tool's recorded result.
func TestIdempotencyClaimsAreToolScoped(t *testing.T) {
	var execs int32
	mw := Idempotency(NewMemClaimStore(), time.Minute)
	handler := func(tool string) ToolHandler {
		return mw(func(context.Context, json.RawMessage) (ToolResult, error) {
			atomic.AddInt32(&execs, 1)
			return ToolResult{Content: []Content{Text("executed:" + tool)}}, nil
		})
	}
	ctxFor := func(tool string) context.Context {
		meta := json.RawMessage(`{"meshmcp.io/idempotency-key":"shared-key"}`)
		return withToolCall(context.Background(), ToolCallInfo{Tool: tool, Meta: meta})
	}
	alpha, beta := handler("tool_alpha"), handler("tool_beta")
	ra, err := alpha(ctxFor("tool_alpha"), nil)
	if err != nil || len(ra.Content) != 1 || ra.Content[0].Text != "executed:tool_alpha" {
		t.Fatalf("tool_alpha: %+v err=%v", ra, err)
	}
	rb, err := beta(ctxFor("tool_beta"), nil)
	if err != nil || len(rb.Content) != 1 || rb.Content[0].Text != "executed:tool_beta" {
		t.Fatalf("tool_beta with tool_alpha's key must run its own handler, got %+v err=%v", rb, err)
	}
	if got := atomic.LoadInt32(&execs); got != 2 {
		t.Fatalf("both tools must execute, got %d executions", got)
	}
	// Replays stay scoped: each tool receives its OWN recorded outcome.
	if r, err := alpha(ctxFor("tool_alpha"), nil); err != nil || r.Content[0].Text != "executed:tool_alpha" {
		t.Fatalf("tool_alpha replay: %+v err=%v", r, err)
	}
	if r, err := beta(ctxFor("tool_beta"), nil); err != nil || r.Content[0].Text != "executed:tool_beta" {
		t.Fatalf("tool_beta replay: %+v err=%v", r, err)
	}
	if got := atomic.LoadInt32(&execs); got != 2 {
		t.Fatalf("replays must not re-execute, got %d executions", got)
	}
}

// TestIdempotencyMalformedKeyFailsClosed: a conveyed but unusable key refuses
// the call rather than running it undeduplicated.
func TestIdempotencyMalformedKeyFailsClosed(t *testing.T) {
	var execs int32
	h := Idempotency(NewMemClaimStore(), time.Minute)(func(context.Context, json.RawMessage) (ToolResult, error) {
		atomic.AddInt32(&execs, 1)
		return ToolResult{}, nil
	})
	for _, meta := range []string{
		`{"meshmcp.io/idempotency-key":""}`,
		`{"meshmcp.io/idempotency-key":42}`,
		fmt.Sprintf(`{"meshmcp.io/idempotency-key":%q}`, strings.Repeat("k", 201)),
	} {
		ctx := withToolCall(context.Background(), ToolCallInfo{Tool: "x", Meta: json.RawMessage(meta)})
		if _, err := h(ctx, nil); err == nil {
			t.Fatalf("meta %s must be refused", meta)
		}
	}
	if execs != 0 {
		t.Fatalf("handler must not run on a malformed key, got %d executions", execs)
	}
}

// TestMemClaimStoreCapFailsClosed: at capacity, a NEW key is refused (store
// error → the middleware refuses the call) instead of evicting a live claim.
func TestMemClaimStoreCapFailsClosed(t *testing.T) {
	s := &MemClaimStore{cap: 2, claims: map[string]*memClaim{}}
	now := time.Unix(1000, 0)
	expiry := now.Add(time.Minute)
	for _, k := range []string{"a", "b"} {
		if won, _, _, err := s.Claim(k, expiry, now); err != nil || !won {
			t.Fatalf("claim %q: won=%v err=%v", k, won, err)
		}
	}
	if _, _, _, err := s.Claim("c", expiry, now); err == nil {
		t.Fatal("a full store must refuse a new key")
	}
	// An existing key still answers at capacity.
	if won, done, _, err := s.Claim("a", expiry, now); err != nil || won || done {
		t.Fatalf("existing key at capacity: won=%v done=%v err=%v, want pending", won, done, err)
	}
	// Expired claims free capacity.
	if won, _, _, err := s.Claim("c", now.Add(2*time.Minute), now.Add(90*time.Second)); err != nil || !won {
		t.Fatalf("after expiry the store must accept new keys: won=%v err=%v", won, err)
	}
}
