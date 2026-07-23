package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"sync"
	"time"
)

// Idempotency-key enforcement (the backend half of the router's retry
// protocol). The meshmcp router stamps every retry-eligible tools/call with a
// stable random key in _meta[IdempotencyKeyMeta] and presents the SAME key on
// every re-dispatch of that logical call. A server built on this framework
// enforces at-most-once execution per (tool, key) by claiming the tool-scoped
// key before running the handler:
//
//   - first claimant executes and records the terminal outcome;
//   - concurrent duplicates wait (single-flight) and receive that outcome;
//   - later replays within the TTL receive the recorded outcome without
//     re-executing;
//   - a claim-store error refuses the call — FAIL CLOSED: an unreachable
//     store must never allow a possibly-duplicate execution.
//
// Claims are namespaced by the called tool: the key namespace is
// client-controllable (any caller may convey a key), and an unscoped claim
// would let key K on tool A suppress a later call to tool B carrying the same
// K — B would silently receive A's recorded result. The router re-dispatches
// a logical call with the same tool name, so tool scoping preserves
// cross-replica dedup.
//
// This is at-most-once execution per (tool, key) within the TTL, not global
// exactly-once: once a claim expires the key is forgotten and a replay
// executes again, so the TTL must comfortably exceed the longest tool
// execution plus the router's retry window.

// IdempotencyKeyMeta is the _meta key the meshmcp router attaches to
// retry-eligible tools/call dispatches (see the router's withIdempotencyKey).
const IdempotencyKeyMeta = "meshmcp.io/idempotency-key"

// DefaultIdempotencyTTL is how long a claim (and its recorded outcome) is
// retained when Idempotency is given a non-positive ttl.
const DefaultIdempotencyTTL = 10 * time.Minute

// MaxCachedResultBytes caps the encoded terminal outcome a claim may store.
// A larger outcome is still returned to the first caller, but is NOT cached:
// the claim completes as "executed, result uncacheable" and replays receive an
// error result instead of the payload — never a silent second execution.
const MaxCachedResultBytes = 64 << 10

// maxIdempotencyKeyLen bounds accepted keys (the router's are 32 hex chars);
// an oversized key is rejected rather than stored — bounded state, fail closed.
const maxIdempotencyKeyLen = 200

// claimPollInterval is how often a duplicate claimant re-checks a pending
// claim while waiting for the first execution to complete.
const claimPollInterval = 25 * time.Millisecond

// ClaimStore is the durable state behind Idempotency. Implementations must
// make Claim atomic (a check-then-act store would let two racing duplicates
// both "win" and double-execute).
//
// Claim outcomes:
//   - won=true: the caller is the first claimant and MUST later Complete the
//     claim (the middleware guarantees this, even on handler panic).
//   - won=false, done=false: another claimant holds the key and has not
//     completed — the call is in flight.
//   - won=false, done=true: a terminal outcome exists; result is the encoded
//     outcome, or empty if the outcome was too large to cache.
//   - err != nil: the store cannot answer. Callers FAIL CLOSED and refuse to
//     execute.
//
// A claim expires at expiry; implementations may forget expired claims (and
// must bound retention). Complete records the terminal outcome of the claim
// GENERATION identified by expiry — the exact expiry the winning Claim was
// given. It is a no-op for an absent, already-done, expired, or
// different-generation claim: a winner whose execution outlives its own TTL
// must not overwrite a successor's live claim for the same key, and a
// recorded terminal outcome is immutable. (A successor can only claim at or
// after the predecessor's expiry, with a positive TTL, so its expiry is
// strictly later — the expiry value identifies exactly one generation.)
type ClaimStore interface {
	Claim(key string, expiry, now time.Time) (won, done bool, result []byte, err error)
	Complete(key string, result []byte, expiry, now time.Time) error
}

// claimRecord is the encoded terminal outcome stored on Complete: exactly one
// of Result (the handler's ToolResult) or Err (the handler's error text).
type claimRecord struct {
	Result *ToolResult `json:"result,omitempty"`
	Err    string      `json:"err,omitempty"`
}

// Idempotency returns middleware enforcing at-most-once execution per
// (tool, _meta[IdempotencyKeyMeta]) — claims are namespaced by the called
// tool, so the same conveyed key on two different tools never shares a claim
// (see the package comment above for the exact semantics). Calls without a
// key pass straight through — the router only stamps retry-eligible calls. A
// non-positive ttl uses DefaultIdempotencyTTL.
//
// The recorded outcome is capped at MaxCachedResultBytes; an oversized
// outcome is returned to the first caller but replays of it get an error
// result. A handler error is recorded and replayed as the same error (the
// tool ran; re-running it is exactly what the key exists to prevent).
func Idempotency(store ClaimStore, ttl time.Duration) ToolMiddleware {
	if ttl <= 0 {
		ttl = DefaultIdempotencyTTL
	}
	return func(next ToolHandler) ToolHandler {
		return func(ctx context.Context, args json.RawMessage) (ToolResult, error) {
			info, ok := ToolCallFrom(ctx)
			if !ok {
				return next(ctx, args)
			}
			key, present, err := idempotencyKeyFromMeta(info.Meta)
			if err != nil {
				// A key was conveyed but is unusable: refuse rather than run
				// a call the sender believes is deduplicated.
				return ToolResult{}, err
			}
			if !present {
				return next(ctx, args)
			}
			// The claim is scoped to the called tool: the key namespace is
			// client-controllable, and an unscoped claim would let the same
			// key on another tool suppress this call and answer it with that
			// tool's recorded result.
			ck := claimKey(info.Tool, key)
			for {
				now := time.Now()
				expiry := now.Add(ttl)
				won, done, cached, err := store.Claim(ck, expiry, now)
				if err != nil {
					// FAIL CLOSED: cannot prove first execution → do not execute.
					return ToolResult{}, errors.New("idempotency: claim store unavailable; refusing to execute")
				}
				if won {
					return executeAndComplete(ctx, next, args, store, ck, expiry)
				}
				if done {
					return decodeClaimOutcome(cached)
				}
				// Pending: the first claimant is executing. Wait bounded and
				// re-check; the loop terminates when the claim completes, the
				// context ends, or the claim expires (at which point the next
				// Claim wins — the documented TTL horizon).
				select {
				case <-ctx.Done():
					return ToolResult{}, ctx.Err()
				case <-time.After(claimPollInterval):
				}
			}
		}
	}
}

// claimKey namespaces a conveyed idempotency key by the called tool. The
// length prefix makes the encoding injective for arbitrary tool names and
// keys, so no (tool, key) pair can collide with any other.
func claimKey(tool, key string) string {
	return strconv.Itoa(len(tool)) + ":" + tool + ":" + key
}

// idempotencyKeyFromMeta extracts the conveyed key. present=false means no
// key was conveyed (pass through); err means a key was conveyed but is
// malformed (fail closed).
func idempotencyKeyFromMeta(meta json.RawMessage) (key string, present bool, err error) {
	if len(meta) == 0 {
		return "", false, nil
	}
	var m map[string]json.RawMessage
	if json.Unmarshal(meta, &m) != nil {
		// _meta is not an object: nothing was conveyed under our key.
		return "", false, nil
	}
	raw, ok := m[IdempotencyKeyMeta]
	if !ok {
		return "", false, nil
	}
	if json.Unmarshal(raw, &key) != nil || key == "" || len(key) > maxIdempotencyKeyLen {
		return "", true, errors.New("idempotency: invalid idempotency key in _meta")
	}
	return key, true, nil
}

// executeAndComplete runs the handler as the winning claimant and records the
// terminal outcome. The claim MUST reach a terminal state — an abandoned
// pending claim would stall every replay until the TTL — so a handler panic
// is converted to an error here (redacted, exactly as RecoverPanics does)
// rather than escaping past the un-Completed claim.
func executeAndComplete(ctx context.Context, next ToolHandler, args json.RawMessage, store ClaimStore, key string, expiry time.Time) (ToolResult, error) {
	res, err := func() (r ToolResult, e error) {
		defer func() {
			if p := recover(); p != nil {
				e = errors.New("tool panicked (recovered)")
			}
		}()
		return next(ctx, args)
	}()
	rec := claimRecord{}
	if err != nil {
		rec.Err = err.Error()
	} else {
		r := res
		rec.Result = &r
	}
	payload, mErr := json.Marshal(rec)
	if mErr != nil || len(payload) > MaxCachedResultBytes {
		// Uncacheable (oversized or unencodable): complete with an empty
		// payload so replays get a clear error instead of a re-execution.
		payload = nil
	}
	// A Complete failure is not surfaced: the execution already happened and
	// the outcome belongs to this caller. Replays then stay pending until the
	// claim expires — delayed, but never a silent double execution. Likewise
	// an execution that outlived its own claim (now past expiry) completes as
	// a no-op: the dedup horizon passed mid-flight and the key may already be
	// re-claimed, so the stale outcome must not be recorded over it.
	_ = store.Complete(key, payload, expiry, time.Now())
	return res, err
}

// decodeClaimOutcome turns a completed claim back into the handler outcome.
func decodeClaimOutcome(cached []byte) (ToolResult, error) {
	if len(cached) == 0 {
		return ToolResult{}, errors.New("idempotent replay: the original result exceeded the cache cap and was not stored; not re-executing")
	}
	var rec claimRecord
	if json.Unmarshal(cached, &rec) != nil || (rec.Result == nil && rec.Err == "") {
		return ToolResult{}, errors.New("idempotent replay: recorded outcome is undecodable; not re-executing")
	}
	if rec.Err != "" {
		return ToolResult{}, errors.New(rec.Err)
	}
	return *rec.Result, nil
}

// --- in-memory ClaimStore ---

// memClaimCap bounds live claims: at the cap, NEW keys are refused (fail
// closed) rather than evicting a live claim, which could admit a duplicate.
const memClaimCap = 4096

// MemClaimStore is a bounded in-memory ClaimStore for single-process servers
// and tests. It forgets expired claims opportunistically (like MemNonceStore)
// and refuses new claims at capacity (memClaimCap live claims), which the
// middleware turns into a fail-closed refusal of every call carrying a NEW
// key until claims expire. The key namespace is client-controllable, so a
// deployment accepting keys from untrusted clients can have its keyed
// (retry-safe) tools wedged for up to the TTL by cap exhaustion — use the
// PostgreSQL store or upstream rate limiting where that matters.
type MemClaimStore struct {
	mu     sync.Mutex
	cap    int
	claims map[string]*memClaim
}

type memClaim struct {
	expiry int64 // unix nanos
	done   bool
	result []byte
}

func NewMemClaimStore() *MemClaimStore {
	return &MemClaimStore{cap: memClaimCap, claims: map[string]*memClaim{}}
}

func (m *MemClaimStore) Claim(key string, expiry, now time.Time) (bool, bool, []byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	// Opportunistically drop expired claims, bounding retention.
	for k, c := range m.claims {
		if now.UnixNano() > c.expiry {
			delete(m.claims, k)
		}
	}
	if c, ok := m.claims[key]; ok {
		return false, c.done, c.result, nil
	}
	if len(m.claims) >= m.cap {
		return false, false, nil, errors.New("mcp: idempotency claim store is full")
	}
	m.claims[key] = &memClaim{expiry: expiry.UnixNano()}
	return true, false, nil, nil
}

// Complete is a no-op unless the claim generation identified by expiry is
// still live and pending (see the ClaimStore contract): a stale completer —
// a winner whose execution outlived its TTL — must never mark a successor's
// claim done, and a recorded terminal outcome is immutable.
func (m *MemClaimStore) Complete(key string, result []byte, expiry, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.claims[key]
	if !ok || c.done || c.expiry != expiry.UnixNano() || now.UnixNano() > c.expiry {
		return nil
	}
	c.done = true
	c.result = result
	return nil
}
