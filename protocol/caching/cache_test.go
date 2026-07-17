package caching

import (
	"testing"
	"time"
)

// clock is a controllable time source for deterministic TTL tests.
type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func newTestCache() (*ResponseCache, *clock) {
	clk := &clock{t: time.Unix(1_700_000_000, 0)}
	rc := NewResponseCache(0)
	rc.now = clk.now
	return rc, clk
}

func TestModeUseServesFreshThenRefetches(t *testing.T) {
	rc, clk := newTestCache()
	calls := 0
	fetch := func() (CacheableResult, []byte, error) {
		calls++
		return CacheableResult{TTLMs: 1000, CacheScope: CachePublic}, []byte(`{"n":1}`), nil
	}

	// First call fetches and stores.
	if v, _ := rc.Fetch(ModeUse, "tools/list", "", fetch); string(v) != `{"n":1}` {
		t.Fatalf("v = %s", v)
	}
	// Second call (still within TTL) is served from cache — no new fetch.
	if _, _ = rc.Fetch(ModeUse, "tools/list", "", fetch); calls != 1 {
		t.Fatalf("expected cache hit, calls = %d", calls)
	}
	// After TTL elapses, it refetches.
	clk.t = clk.t.Add(2 * time.Second)
	if _, _ = rc.Fetch(ModeUse, "tools/list", "", fetch); calls != 2 {
		t.Fatalf("expected refetch after expiry, calls = %d", calls)
	}
}

func TestModeRefreshAndBypass(t *testing.T) {
	rc, _ := newTestCache()
	calls := 0
	fetch := func() (CacheableResult, []byte, error) {
		calls++
		return CacheableResult{TTLMs: 10000, CacheScope: CachePublic}, []byte(`x`), nil
	}
	_, _ = rc.Fetch(ModeUse, "k", "", fetch)     // stores
	_, _ = rc.Fetch(ModeRefresh, "k", "", fetch) // always fetches, overwrites
	if calls != 2 {
		t.Fatalf("refresh should fetch, calls = %d", calls)
	}
	// Bypass fetches but does not read cache; and does not write it either.
	rc2, _ := newTestCache()
	byCalls := 0
	fb := func() (CacheableResult, []byte, error) {
		byCalls++
		return CacheableResult{TTLMs: 10000, CacheScope: CachePublic}, []byte(`y`), nil
	}
	_, _ = rc2.Fetch(ModeBypass, "k", "", fb)
	if _, ok := rc2.Lookup("k", ""); ok {
		t.Fatal("bypass must not write the cache")
	}
}

func TestPrivateScopeIsolation(t *testing.T) {
	rc, _ := newTestCache()
	rc.Store("resources/read", CacheableResult{TTLMs: 5000, CacheScope: CachePrivate}, []byte(`secret`), "user-A")

	if _, ok := rc.Lookup("resources/read", "user-A"); !ok {
		t.Fatal("owner should see their private entry")
	}
	if _, ok := rc.Lookup("resources/read", "user-B"); ok {
		t.Fatal("private entry must not leak across auth contexts")
	}
}

func TestPublicScopeShared(t *testing.T) {
	rc, _ := newTestCache()
	rc.Store("tools/list", CacheableResult{TTLMs: 5000, CacheScope: CachePublic}, []byte(`shared`), "user-A")
	if _, ok := rc.Lookup("tools/list", "user-B"); !ok {
		t.Fatal("public entry should be served across auth contexts")
	}
}

func TestInvalidateEvictsRegardlessOfTTL(t *testing.T) {
	rc, _ := newTestCache()
	rc.Store("tools/list", CacheableResult{TTLMs: 999999, CacheScope: CachePublic}, []byte(`a`), "")
	rc.Store("tools/list", CacheableResult{TTLMs: 999999, CacheScope: CachePrivate}, []byte(`b`), "user-A")
	rc.Invalidate("tools/list")
	if _, ok := rc.Lookup("tools/list", "user-A"); ok {
		t.Fatal("invalidate must drop the entry even though it is still fresh")
	}
}

func TestInvalidateForNotification(t *testing.T) {
	rc, _ := newTestCache()
	fresh := CacheableResult{TTLMs: 999999, CacheScope: CachePublic}

	// tools/list_changed evicts the tools list.
	rc.Store(KeyToolsList, fresh, []byte(`tools`), "")
	if got := rc.InvalidateForNotification("notifications/tools/list_changed", ""); len(got) != 1 || got[0] != KeyToolsList {
		t.Fatalf("tools evict keys = %v", got)
	}
	if _, ok := rc.Lookup(KeyToolsList, ""); ok {
		t.Fatal("tools/list should be evicted")
	}

	// resources/list_changed evicts both the list and templates list.
	rc.Store(KeyResourcesList, fresh, []byte(`r`), "")
	rc.Store(KeyResourceTemplatesList, fresh, []byte(`rt`), "")
	got := rc.InvalidateForNotification("notifications/resources/list_changed", "")
	if len(got) != 2 {
		t.Fatalf("resources evict keys = %v", got)
	}
	if _, ok := rc.Lookup(KeyResourcesList, ""); ok {
		t.Fatal("resources/list should be evicted")
	}

	// resources/updated evicts only the specific resource read, by URI.
	uri := "file:///project/config.json"
	rc.Store(ResourceReadKey(uri), fresh, []byte(`cfg`), "")
	rc.Store(ResourceReadKey("file:///other.txt"), fresh, []byte(`other`), "")
	rc.InvalidateForNotification("notifications/resources/updated", uri)
	if _, ok := rc.Lookup(ResourceReadKey(uri), ""); ok {
		t.Fatal("updated resource should be evicted")
	}
	if _, ok := rc.Lookup(ResourceReadKey("file:///other.txt"), ""); !ok {
		t.Fatal("unrelated resource must not be evicted")
	}

	// An unrelated notification evicts nothing.
	if got := rc.InvalidateForNotification("notifications/message", ""); got != nil {
		t.Fatalf("unrelated notification evicted %v", got)
	}
}

func TestZeroTTLIsStale(t *testing.T) {
	rc, _ := newTestCache()
	rc.Store("k", CacheableResult{TTLMs: 0, CacheScope: CachePublic}, []byte(`v`), "")
	if _, ok := rc.Lookup("k", ""); ok {
		t.Fatal("ttl 0 should be immediately stale")
	}
}
