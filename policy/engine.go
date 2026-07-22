package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"
)

// RateLimit caps how often an identity may make calls matching a rule. Max
// tokens refill over Per (e.g. max: 10, per: "1m"). Empty Per means per second.
//
// Cost generalizes a rate limit into a cost/quota budget: each matching call
// consumes Cost tokens instead of 1, so an expensive tool (an LLM-backed
// retrieval, a large embedding batch) can be weighted against a per-identity
// budget — e.g. {max: 1000, per: "24h", cost: 10} is a 100-call/day budget, or
// a 1000-unit/day spend cap if Cost reflects price. Cost <= 0 means 1.
type RateLimit struct {
	Max  int    `yaml:"max"`
	Per  string `yaml:"per"`
	Cost int    `yaml:"cost,omitempty"`
}

func (rl *RateLimit) window() time.Duration {
	if rl.Per == "" {
		return time.Second
	}
	d, err := time.ParseDuration(rl.Per)
	if err != nil || d <= 0 {
		return time.Second
	}
	return d
}

// Window restricts a rule to a set of weekdays and an hours range in a
// timezone. An empty field means "any" (any day / any hour / UTC).
type Window struct {
	Days  []string `yaml:"days"`  // "mon".."sun"; empty = every day
	Hours string   `yaml:"hours"` // "09:00-17:00"; empty = all day
	TZ    string   `yaml:"tz"`    // IANA name; empty = UTC
}

var weekdayNames = map[string]time.Weekday{
	"sun": time.Sunday, "mon": time.Monday, "tue": time.Tuesday, "wed": time.Wednesday,
	"thu": time.Thursday, "fri": time.Friday, "sat": time.Saturday,
}

// active reports whether instant t falls inside the window.
func (w *Window) active(t time.Time) bool {
	loc := time.UTC
	if w.TZ != "" {
		if l, err := time.LoadLocation(w.TZ); err == nil {
			loc = l
		}
	}
	lt := t.In(loc)
	if len(w.Days) > 0 {
		ok := false
		for _, d := range w.Days {
			if wd, found := weekdayNames[strings.ToLower(strings.TrimSpace(d))]; found && wd == lt.Weekday() {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	if w.Hours == "" {
		return true
	}
	lo, hi, ok := parseHourRange(w.Hours)
	if !ok {
		// Fail closed: a malformed hours range makes the window inactive, so
		// the rule falls through to the next rule / the default (deny) rather
		// than an allow rule firing 24/7 on a typo. Config load validates
		// windows (Policy.Validate), so this is defense in depth.
		return false
	}
	mins := lt.Hour()*60 + lt.Minute()
	if lo <= hi {
		return mins >= lo && mins < hi
	}
	// Overnight window (e.g. 22:00-06:00).
	return mins >= lo || mins < hi
}

func parseHourRange(s string) (lo, hi int, ok bool) {
	parts := strings.SplitN(s, "-", 2)
	if len(parts) != 2 {
		return 0, 0, false
	}
	lo, ok1 := parseHM(parts[0])
	hi, ok2 := parseHM(parts[1])
	return lo, hi, ok1 && ok2
}

func parseHM(s string) (int, bool) {
	s = strings.TrimSpace(s)
	hm := strings.SplitN(s, ":", 2)
	h, err := strconv.Atoi(hm[0])
	if err != nil || h < 0 || h > 24 {
		return 0, false
	}
	m := 0
	if len(hm) == 2 {
		m, err = strconv.Atoi(hm[1])
		if err != nil || m < 0 || m > 59 {
			return 0, false
		}
	}
	return h*60 + m, true
}

// CosignStore records and reports human co-sign approvals. A call gated by
// require_cosign is held until Approved(key) is true. Approvals are granted
// out of band by a human identity on the mesh (see the FileCosign directory).
type CosignStore interface {
	Approved(key string) bool
}

// MemCosign is an in-memory CosignStore for tests and single-process use.
type MemCosign struct {
	mu       sync.Mutex
	approved map[string]bool
}

func NewMemCosign() *MemCosign { return &MemCosign{approved: map[string]bool{}} }

func (m *MemCosign) Approve(key string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.approved[key] = true
}

func (m *MemCosign) Approved(key string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.approved[key]
}

// CosignKey is the canonical approval key for a (peer, tool) pair.
func CosignKey(peer, tool string) string { return peer + "|" + tool }

// bucket is a token bucket refilling max tokens per window.
type bucket struct {
	tokens float64
	last   time.Time
}

// Engine adds stateful capability enforcement on top of a Policy: rate-limit
// buckets and the co-sign store are shared across every connection the policy
// governs, so limits and approvals are per-identity, not per-connection. Taint
// is NOT held here — it is per-session and lives on the Filter — but the Engine
// evaluates the taint_guard/taint_source rule flags against the taint state the
// caller passes in.
type Engine struct {
	pol          *Policy
	now          func() time.Time
	cosign       CosignStore
	reqApprovals RequestApprovalStore // optional: request-bound single-use approvals (Phase 3)
	groups       GroupResolver        // optional: resolves group:<name> peer patterns (F17)

	mu      sync.Mutex
	buckets map[string]*bucket // key: ruleID|peerKey

	phOnce sync.Once
	ph     string // cached policy hash
}

// PolicyHash returns a stable hash of the active policy, used to bind a
// request-approval to the policy version in force when it was granted.
func (e *Engine) PolicyHash() string {
	e.phOnce.Do(func() {
		b, _ := json.Marshal(e.pol)
		sum := sha256.Sum256(b)
		e.ph = hex.EncodeToString(sum[:])
	})
	return e.ph
}

// SetRequestApprovals attaches a request-bound approval store. When set,
// DecideToolCallBound enforces argument-bound, single-use co-sign approvals in
// place of the ambient (peer, tool) co-sign store.
func (e *Engine) SetRequestApprovals(s RequestApprovalStore) { e.reqApprovals = s }

// SetGroupResolver attaches a group resolver so rules may match `group:<name>`
// peers (nil disables group matching — such patterns then never match).
func (e *Engine) SetGroupResolver(g GroupResolver) { e.groups = g }

// peerMatches reports whether rule r applies to this caller, handling
// `group:<name>` patterns via the resolver in addition to the pubkey/FQDN forms
// the pure Rule matcher understands.
func (e *Engine) peerMatches(r Rule, fqdn, key string) bool {
	if len(r.Peers) == 0 {
		return true
	}
	for _, p := range r.Peers {
		if g, ok := strings.CutPrefix(p, "group:"); ok {
			if e.groups != nil && e.groups.InGroup(key, fqdn, g) {
				return true
			}
			continue
		}
		if k, ok := strings.CutPrefix(p, "pubkey:"); ok {
			if k == key {
				return true
			}
			continue
		}
		if p == "*" || fqdn == p {
			return true
		}
		if ok, _ := path.Match(p, fqdn); ok {
			return true
		}
	}
	return false
}

// NewEngine wraps pol. now defaults to time.Now; cosign may be nil (then
// require_cosign rules deny with an explanatory reason rather than hang).
func NewEngine(pol *Policy, now func() time.Time, cosign CosignStore) *Engine {
	if now == nil {
		now = time.Now
	}
	return &Engine{pol: pol, now: now, cosign: cosign, buckets: map[string]*bucket{}}
}

// Policy exposes the wrapped policy (for method decisions and reporting).
func (e *Engine) Policy() *Policy { return e.pol }

// DecideToolCall authorizes a tools/call, applying rate limits, time windows,
// co-sign, and data-flow labels. labels is the session's current label set
// (nil is fine). The returned Decision's Outcome is allow, deny, or cosign,
// and AddLabels lists labels the caller should add on an allowed call.
//
// This form uses the legacy ambient (peer, tool) co-sign store. Prefer
// DecideToolCallBound, which binds co-sign approvals to the exact arguments and
// backend and consumes them single-use.
func (e *Engine) DecideToolCall(peerFQDN, peerKey, tool string, labels map[string]bool) Decision {
	return e.decideTool(peerFQDN, peerKey, "", tool, nil, labels, false)
}

// DecideToolCallBound is DecideToolCall with request-bound co-sign: when a
// request-approval store is configured (SetRequestApprovals), a require_cosign
// rule is satisfied only by a signed, non-expired, single-use approval bound to
// this exact (peer, backend, tool, arguments), which it atomically consumes.
// Changing the arguments or backend no longer matches an approval.
func (e *Engine) DecideToolCallBound(peerFQDN, peerKey, backend, tool string, args []byte, labels map[string]bool) Decision {
	return e.decideTool(peerFQDN, peerKey, backend, tool, args, labels, true)
}

func (e *Engine) decideTool(peerFQDN, peerKey, backend, tool string, args []byte, labels map[string]bool, bound bool) Decision {
	now := e.now()
	for i, r := range e.pol.Rules {
		if len(r.Methods) > 0 {
			continue
		}
		if !e.peerMatches(r, peerFQDN, peerKey) || !r.matchesTool(tool) {
			continue
		}
		// A window-gated rule only applies inside its window; otherwise fall
		// through so a later rule (or the default) decides.
		if r.When != nil && !r.When.active(now) {
			continue
		}
		if !r.Allow {
			return Decision{RuleID: i, Outcome: OutcomeDeny, Reason: "denied by rule"}
		}
		// Allow branch, refined by capability constraints.
		if blocked := firstPresent(r.blockSet(), labels); blocked != "" {
			reason := fmt.Sprintf("blocked: session carries label %q which this tool forbids", blocked)
			if blocked == "tainted" {
				reason = "blocked: session tainted by untrusted data (prompt-injection guard)"
			}
			return Decision{RuleID: i, Outcome: OutcomeDeny, Reason: reason}
		}
		if r.Rate != nil && !e.allowRate(i, peerKey, *r.Rate, now) {
			return Decision{RuleID: i, Outcome: OutcomeDeny,
				Reason: fmt.Sprintf("rate limit exceeded (max %d per %s)", r.Rate.Max, r.Rate.window())}
		}
		if r.RequireCosign {
			// Request-bound approvals (preferred): a signed, single-use approval
			// bound to these exact arguments and backend. Consume atomically.
			if bound && e.reqApprovals != nil {
				req := ApprovalRequest{PeerKey: peerKey, Backend: backend, Tool: tool, ArgsHash: canonicalArgsHash(args), PolicyHash: e.PolicyHash()}
				if ok, _ := e.reqApprovals.ConsumeApproval(req, now); ok {
					return Decision{Allow: true, RuleID: i, Outcome: OutcomeAllow,
						Reason: "request-bound co-sign consumed", AddLabels: r.emitSet(), Cost: ruleCost(r)}
				}
				return Decision{RuleID: i, Outcome: OutcomeCosign,
					Reason: fmt.Sprintf("awaiting request-bound human co-sign for %q", tool)}
			}
			// Legacy ambient (peer, tool) co-sign.
			if e.cosign != nil && e.cosign.Approved(CosignKey(peerFQDN, tool)) {
				return Decision{Allow: true, RuleID: i, Outcome: OutcomeAllow,
					Reason: "co-signed", AddLabels: r.emitSet(), Cost: ruleCost(r)}
			}
			return Decision{RuleID: i, Outcome: OutcomeCosign,
				Reason: fmt.Sprintf("awaiting human co-sign for %q", tool)}
		}
		return Decision{Allow: true, RuleID: i, Outcome: OutcomeAllow, AddLabels: r.emitSet(), Cost: ruleCost(r)}
	}
	return Decision{Allow: e.pol.DefaultAllow, RuleID: -1, Outcome: outcomeOf(e.pol.DefaultAllow)}
}

// ruleCost is the cost/quota units an allowed call under rule r consumes: the
// rule's rate.cost (default 1 when a rate limit is set), or 0 when the rule has
// no rate/cost (cost is untracked for that rule).
func ruleCost(r Rule) int {
	if r.Rate == nil {
		return 0
	}
	if r.Rate.Cost > 0 {
		return r.Rate.Cost
	}
	return 1
}

// firstPresent returns the first label in want that is set in have, or "".
func firstPresent(want []string, have map[string]bool) string {
	for _, l := range want {
		if have[l] {
			return l
		}
	}
	return ""
}

// allowRate consumes one token from the (rule, identity) bucket, refilling by
// elapsed time. Returns false when the bucket is empty.
func (e *Engine) allowRate(ruleID int, peerKey string, rl RateLimit, now time.Time) bool {
	if rl.Max <= 0 {
		return true
	}
	key := strconv.Itoa(ruleID) + "|" + peerKey
	perSec := float64(rl.Max) / e.perSeconds(rl)

	e.mu.Lock()
	defer e.mu.Unlock()
	b := e.buckets[key]
	if b == nil {
		b = &bucket{tokens: float64(rl.Max), last: now}
		e.buckets[key] = b
	} else {
		elapsed := now.Sub(b.last).Seconds()
		if elapsed > 0 {
			b.tokens += elapsed * perSec
			if b.tokens > float64(rl.Max) {
				b.tokens = float64(rl.Max)
			}
			b.last = now
		}
	}
	cost := float64(rl.Cost)
	if cost <= 0 {
		cost = 1
	}
	if b.tokens >= cost {
		b.tokens -= cost
		return true
	}
	return false
}

func (e *Engine) perSeconds(rl RateLimit) float64 {
	s := rl.window().Seconds()
	if s <= 0 {
		return 1
	}
	return s
}
