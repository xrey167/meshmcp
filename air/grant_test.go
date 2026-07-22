package air

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func grantTestNow() time.Time { return time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC) }

// always is an authorizes predicate that accepts any scope — used to consume a
// single-use grant irrespective of scope semantics (the store is verb-agnostic).
func always(string) bool { return true }

func openTempGrantStore(t *testing.T) (*GrantStore, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "grants.json")
	s, err := OpenGrantStore(path)
	if err != nil {
		t.Fatalf("OpenGrantStore: %v", err)
	}
	return s, path
}

// TestGrantAddCheckRemove proves the basic lifecycle: a written grant is present
// until revoked, then gone (invariant 2 default-deny + invariant 5 revoke).
func TestGrantAddCheckRemove(t *testing.T) {
	s, _ := openTempGrantStore(t)
	if s.Check("peer", "kg", "proj") {
		t.Fatal("no grant should exist yet (default-deny)")
	}
	if _, err := s.Add("peer", "kg", "proj", false, "op", grantTestNow()); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if !s.Check("peer", "kg", "proj") {
		t.Fatal("grant should exist after Add")
	}
	removed, err := s.Remove("peer", "kg", "proj")
	if err != nil || !removed {
		t.Fatalf("Remove: removed=%v err=%v", removed, err)
	}
	if s.Check("peer", "kg", "proj") {
		t.Fatal("grant must be gone after Remove")
	}
}

// TestGrantOnceConsumedExactlyOnce proves a single-use grant authorizes exactly
// one call, then is gone — the second attempt finds nothing (invariant 3).
func TestGrantOnceConsumedExactlyOnce(t *testing.T) {
	s, _ := openTempGrantStore(t)
	if _, err := s.Add("peer", "kg", "proj", true, "op", grantTestNow()); err != nil {
		t.Fatalf("Add: %v", err)
	}
	g, ok, err := s.ConsumeOnceMatching("peer", "kg", always, grantTestNow())
	if err != nil || !ok || g.Scope != "proj" {
		t.Fatalf("first consume: g=%+v ok=%v err=%v", g, ok, err)
	}
	_, ok, err = s.ConsumeOnceMatching("peer", "kg", always, grantTestNow())
	if err != nil {
		t.Fatalf("second consume err: %v", err)
	}
	if ok {
		t.Fatal("a single-use grant must not be consumable twice")
	}
	if s.Check("peer", "kg", "proj") {
		t.Fatal("consumed once-grant must be gone")
	}
}

// TestGrantPersistentNotConsumed proves a persistent ("always") grant is never
// spent by ConsumeOnceMatching — it only consumes single-use grants.
func TestGrantPersistentNotConsumed(t *testing.T) {
	s, _ := openTempGrantStore(t)
	if _, err := s.Add("peer", "kg", "proj", false, "op", grantTestNow()); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if _, ok, _ := s.ConsumeOnceMatching("peer", "kg", always, grantTestNow()); ok {
		t.Fatal("a persistent grant must not be consumed as single-use")
	}
	if !s.Check("peer", "kg", "proj") {
		t.Fatal("persistent grant must survive a consume attempt")
	}
}

// TestGrantScopesForSplit proves ScopesFor separates persistent and single-use
// scopes and never leaks another verb's grants (invariant 6, verb isolation).
func TestGrantScopesForSplit(t *testing.T) {
	s, _ := openTempGrantStore(t)
	mustAdd(t, s, "peer", "kg", "always-scope", false)
	mustAdd(t, s, "peer", "kg", "once-scope", true)
	mustAdd(t, s, "peer", "database", "db.table", false) // a different verb

	persistent, once := s.ScopesFor("peer", "kg")
	if strings.Join(persistent, ",") != "always-scope" {
		t.Fatalf("persistent = %v, want [always-scope]", persistent)
	}
	if strings.Join(once, ",") != "once-scope" {
		t.Fatalf("once = %v, want [once-scope]", once)
	}
	// The database grant must not appear under the kg verb.
	for _, p := range append(persistent, once...) {
		if p == "db.table" {
			t.Fatal("a grant for verb=database leaked into verb=kg")
		}
	}
}

// TestGrantConsumeScopeIsolation proves ConsumeOnceMatching only removes a grant
// whose scope the predicate accepts — a grant of X is not spent by a request the
// predicate rejects (invariant 6, scope isolation).
func TestGrantConsumeScopeIsolation(t *testing.T) {
	s, _ := openTempGrantStore(t)
	mustAdd(t, s, "peer", "kg", "X", true)
	onlyY := func(scope string) bool { return scope == "Y" }
	if _, ok, _ := s.ConsumeOnceMatching("peer", "kg", onlyY, grantTestNow()); ok {
		t.Fatal("a once-grant of X must not be consumed by a request for Y")
	}
	if !s.Check("peer", "kg", "X") {
		t.Fatal("grant of X must remain after a non-matching consume")
	}
}

// TestGrantRecordDedupAndDrop proves opportunities dedup (Count bumps, no new
// row) and that granting the scope drops the pending opportunity.
func TestGrantRecordDedupAndDrop(t *testing.T) {
	s, _ := openTempGrantStore(t)
	_, added, err := s.Record("peer", "kg", "proj", grantTestNow())
	if err != nil || !added {
		t.Fatalf("first Record: added=%v err=%v", added, err)
	}
	_, added, _ = s.Record("peer", "kg", "proj", grantTestNow())
	if added {
		t.Fatal("a repeat ask must dedup (added=false)")
	}
	pend := s.Pending()
	if len(pend) != 1 || pend[0].Count != 2 {
		t.Fatalf("pending = %+v, want one entry with count 2", pend)
	}
	// Granting the scope resolves and drops the opportunity.
	if _, err := s.Add("peer", "kg", "proj", false, "op", grantTestNow()); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if len(s.Pending()) != 0 {
		t.Fatal("granting the scope must drop the matching pending opportunity")
	}
	// A recorded opportunity for an already-granted scope adds nothing.
	if _, added, _ := s.Record("peer", "kg", "proj", grantTestNow()); added {
		t.Fatal("no opportunity should be recorded for an already-granted scope")
	}
}

// TestGrantDropOpportunity proves the operator "deny" tap discards a pending ask
// without granting anything.
func TestGrantDropOpportunity(t *testing.T) {
	s, _ := openTempGrantStore(t)
	if _, _, err := s.Record("peer", "kg", "proj", grantTestNow()); err != nil {
		t.Fatalf("Record: %v", err)
	}
	removed, err := s.DropOpportunity("peer", "kg", "proj")
	if err != nil || !removed {
		t.Fatalf("DropOpportunity: removed=%v err=%v", removed, err)
	}
	if len(s.Pending()) != 0 {
		t.Fatal("opportunity must be gone after DropOpportunity")
	}
	if s.Check("peer", "kg", "proj") {
		t.Fatal("DropOpportunity must not grant anything")
	}
}

// TestGrantAtomicPersistenceRoundTrip proves grants survive a store reopen (the
// atomic temp+fsync+rename write persisted them), and a consumed once-grant does
// not reappear (invariant 5 atomic persistence + invariant 3).
func TestGrantAtomicPersistenceRoundTrip(t *testing.T) {
	s, path := openTempGrantStore(t)
	mustAdd(t, s, "peer", "kg", "always-scope", false)
	mustAdd(t, s, "peer", "kg", "once-scope", true)
	if _, ok, _ := s.ConsumeOnceMatching("peer", "kg", func(sc string) bool { return sc == "once-scope" }, grantTestNow()); !ok {
		t.Fatal("expected to consume once-scope")
	}

	reopened, err := OpenGrantStore(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if !reopened.Check("peer", "kg", "always-scope") {
		t.Fatal("persistent grant must survive a reopen")
	}
	if reopened.Check("peer", "kg", "once-scope") {
		t.Fatal("a consumed once-grant must not reappear after reopen")
	}
}

// TestGrantValidation proves malformed or hostile triples are rejected before
// they can land in the store.
func TestGrantValidation(t *testing.T) {
	s, _ := openTempGrantStore(t)
	cases := []struct{ id, verb, scope string }{
		{"", "kg", "proj"},
		{"peer", "", "proj"},
		{"peer", "kg", ""},
		{"peer", "kg", "bad\nscope"},
		{strings.Repeat("k", maxGrantText+1), "kg", "proj"},
	}
	for _, c := range cases {
		if _, err := s.Add(c.id, c.verb, c.scope, false, "op", grantTestNow()); err == nil {
			t.Fatalf("Add(%q,%q,%q) should have been rejected", c.id, c.verb, c.scope)
		}
	}
}

func mustAdd(t *testing.T, s *GrantStore, id, verb, scope string, once bool) {
	t.Helper()
	if _, err := s.Add(id, verb, scope, once, "op", grantTestNow()); err != nil {
		t.Fatalf("Add(%q,%q,%q,once=%v): %v", id, verb, scope, once, err)
	}
}
