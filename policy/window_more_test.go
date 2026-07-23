package policy

import (
	"testing"
	"time"
)

// TestWindowMinuteBoundaries pins the range semantics: the low bound is
// inclusive and the high bound exclusive, to the minute.
func TestWindowMinuteBoundaries(t *testing.T) {
	w := &Window{Hours: "09:00-17:00"}
	at := func(h, m int) time.Time { return time.Date(2026, 7, 15, h, m, 0, 0, time.UTC) }
	tests := []struct {
		h, m int
		want bool
	}{
		{8, 59, false},
		{9, 0, true}, // lo inclusive
		{16, 59, true},
		{17, 0, false}, // hi exclusive
	}
	for _, tc := range tests {
		if got := w.active(at(tc.h, tc.m)); got != tc.want {
			t.Fatalf("%02d:%02d active = %v, want %v", tc.h, tc.m, got, tc.want)
		}
	}
}

// TestWindowDaysOnly: with no Hours, the day filter alone decides.
func TestWindowDaysOnly(t *testing.T) {
	w := &Window{Days: []string{"sat", "sun"}}
	if !w.active(time.Date(2026, 7, 18, 3, 0, 0, 0, time.UTC)) { // Saturday
		t.Fatal("Saturday must be inside a weekend-only window at any hour")
	}
	if w.active(time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)) { // Wednesday
		t.Fatal("Wednesday must be outside a weekend-only window")
	}
}

// TestOvernightWindowWithDays pins how Days combine with an overnight Hours
// range: the day filter applies to the calendar day of the INSTANT, so a
// fri 22:00-06:00 window covers Friday 23:00 but NOT the early-Saturday
// portion (Saturday 03:00 is weekday sat, excluded by Days).
func TestOvernightWindowWithDays(t *testing.T) {
	w := &Window{Days: []string{"fri"}, Hours: "22:00-06:00", TZ: "UTC"}
	// Friday 2026-07-17 23:00 — inside.
	if !w.active(time.Date(2026, 7, 17, 23, 0, 0, 0, time.UTC)) {
		t.Fatal("Friday 23:00 must be inside a fri 22:00-06:00 window")
	}
	// Saturday 03:00 — hours match the wraparound, but the day is now sat.
	if w.active(time.Date(2026, 7, 18, 3, 0, 0, 0, time.UTC)) {
		t.Fatal("Saturday 03:00 is outside: Days filter on the instant's own weekday")
	}
	// Friday 12:00 — right day, wrong hours.
	if w.active(time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)) {
		t.Fatal("Friday noon must be outside an overnight window")
	}
}

// TestWindowTimezoneShiftsDecision: the same instant is inside a 09:00-17:00
// window in one timezone and outside it in another — the TZ field genuinely
// converts, it is not decoration. Asia/Tokyo (UTC+9, no DST) keeps the
// arithmetic stable year-round.
func TestWindowTimezoneShiftsDecision(t *testing.T) {
	if _, err := time.LoadLocation("Asia/Tokyo"); err != nil {
		t.Skipf("tzdata unavailable: %v", err)
	}
	tokyo := &Window{Hours: "09:00-17:00", TZ: "Asia/Tokyo"}
	utc := &Window{Hours: "09:00-17:00", TZ: "UTC"}

	// 01:00 UTC == 10:00 JST: inside for Tokyo, outside for UTC.
	at0100 := time.Date(2026, 7, 15, 1, 0, 0, 0, time.UTC)
	if !tokyo.active(at0100) {
		t.Fatal("01:00 UTC is 10:00 JST — must be inside the Tokyo window")
	}
	if utc.active(at0100) {
		t.Fatal("01:00 UTC must be outside the UTC window")
	}
	// 12:00 UTC == 21:00 JST: the verdicts flip.
	at1200 := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	if tokyo.active(at1200) {
		t.Fatal("12:00 UTC is 21:00 JST — must be outside the Tokyo window")
	}
	if !utc.active(at1200) {
		t.Fatal("12:00 UTC must be inside the UTC window")
	}
}

// TestWindowBadTZFallsBackToUTC pins the documented fallback: an unknown TZ
// evaluates the window in UTC (it does not disable the rule or fail open).
func TestWindowBadTZFallsBackToUTC(t *testing.T) {
	w := &Window{Hours: "09:00-17:00", TZ: "No/Such_Zone"}
	if !w.active(time.Date(2026, 7, 15, 10, 0, 0, 0, time.UTC)) {
		t.Fatal("10:00 UTC must be inside after falling back to UTC")
	}
	if w.active(time.Date(2026, 7, 15, 20, 0, 0, 0, time.UTC)) {
		t.Fatal("20:00 UTC must be outside after falling back to UTC")
	}
}

// TestWindowTimezoneAtDecisionTime drives the TZ conversion through the full
// engine path: a rule window active in Tokyo but not in UTC decides an
// engine-evaluated call at 01:00 UTC.
func TestWindowTimezoneAtDecisionTime(t *testing.T) {
	if _, err := time.LoadLocation("Asia/Tokyo"); err != nil {
		t.Skipf("tzdata unavailable: %v", err)
	}
	pol := &Policy{DefaultAllow: false, Rules: []Rule{
		{Peers: []string{"*"}, Tools: []string{"deploy"}, Allow: true,
			When: &Window{Hours: "09:00-17:00", TZ: "Asia/Tokyo"}},
	}}
	at0100 := time.Date(2026, 7, 15, 1, 0, 0, 0, time.UTC)
	eng := NewEngine(pol, func() time.Time { return at0100 }, nil)
	if d := eng.DecideToolCall("p", "K", "deploy", nil); d.Outcome != OutcomeAllow {
		t.Fatalf("01:00 UTC is inside Tokyo business hours — must allow, got %v", d.Outcome)
	}
	// The same policy with a UTC window falls through to default deny.
	polUTC := &Policy{DefaultAllow: false, Rules: []Rule{
		{Peers: []string{"*"}, Tools: []string{"deploy"}, Allow: true,
			When: &Window{Hours: "09:00-17:00", TZ: "UTC"}},
	}}
	engUTC := NewEngine(polUTC, func() time.Time { return at0100 }, nil)
	if d := engUTC.DecideToolCall("p", "K", "deploy", nil); d.Outcome != OutcomeDeny {
		t.Fatalf("01:00 UTC is outside UTC business hours — must deny, got %v", d.Outcome)
	}
}
