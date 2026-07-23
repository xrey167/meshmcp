package harness

import (
	"fmt"
	"sync"
	"time"
)

// Budget bounds a run: token spend, wall-clock, loop rounds, and fan-out width.
// Budgets are policy artifacts (rate/time-window policy) as well as run config;
// gjc's per-worker/per-run retry budgets live here too. A zero field means
// "unbounded for that dimension" except where noted.
type Budget struct {
	Tokens         int           // total token budget across the run (0 = unbounded)
	WallClock      time.Duration // total wall-clock (0 = unbounded)
	LoopRounds     int           // max loop rounds (0 = unbounded → clamped by policy)
	FanOut         int           // max parallel workers per round (0 = scheduler default)
	RetryPerWorker int           // max retries for one worker (0 = default 3)
	RetryPerRun    int           // max retries across the run (0 = default 20)
}

// DefaultBudget is the seed budget used when a request omits one.
func DefaultBudget() Budget {
	return Budget{
		Tokens:         2_000_000,
		WallClock:      45 * time.Minute,
		LoopRounds:     12,
		FanOut:         8,
		RetryPerWorker: 3,
		RetryPerRun:    20,
	}
}

// tracker accounts spend against a Budget across a run. Safe for concurrent use.
type tracker struct {
	b       Budget
	start   time.Time
	now     func() time.Time
	mu      sync.Mutex
	tokens  int
	rounds  int
	retries int
}

func newTracker(b Budget, now func() time.Time) *tracker {
	if now == nil {
		now = time.Now
	}
	return &tracker{b: b, start: now(), now: now}
}

// spendTokens adds n tokens; returns an error if the token budget is exhausted.
func (t *tracker) spendTokens(n int) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.tokens += n
	if t.b.Tokens > 0 && t.tokens > t.b.Tokens {
		return fmt.Errorf("token budget exhausted: %d/%d", t.tokens, t.b.Tokens)
	}
	return nil
}

// nextRound consumes one loop round; returns false when no rounds remain.
func (t *tracker) nextRound() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.b.LoopRounds > 0 && t.rounds >= t.b.LoopRounds {
		return false
	}
	t.rounds++
	return true
}

// expired reports whether the wall-clock budget is spent.
func (t *tracker) expired() bool {
	if t.b.WallClock <= 0 {
		return false
	}
	return t.now().Sub(t.start) >= t.b.WallClock
}

// retry consumes one run-level retry; returns false when the run retry budget
// is exhausted.
func (t *tracker) retry() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	limit := t.b.RetryPerRun
	if limit <= 0 {
		limit = 20
	}
	if t.retries >= limit {
		return false
	}
	t.retries++
	return true
}

// snapshot returns the current spend for observability/audit.
func (t *tracker) snapshot() (tokens, rounds, retries int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.tokens, t.rounds, t.retries
}
