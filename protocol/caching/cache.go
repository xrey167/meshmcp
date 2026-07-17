package caching

import (
	"sort"
	"sync"
	"time"
)

// Mode selects a per-call caching strategy, mirroring the way a page can
// combine static pre-rendering with client-side refetching:
//
//   - ModeUse: serve a still-fresh cached response without a round trip;
//     otherwise fetch and store (the default, like SSG + read-through).
//   - ModeRefresh: always fetch, then overwrite the cache (like SWR revalidate).
//   - ModeBypass: fetch without reading or writing the cache (like no-store).
type Mode int

const (
	ModeUse Mode = iota
	ModeRefresh
	ModeBypass
)

// entry is a stored response with its freshness and scope.
type entry struct {
	value     []byte
	expiresAt time.Time
	scope     CacheScope
}

// ResponseCache is an in-memory, TTL- and scope-aware store for cacheable MCP
// results. It honours CacheableResult hints: TTLMs sets freshness (0 =
// immediately stale) and CacheScope partitions entries — "public" responses are
// shared across authorization contexts, "private" ones are keyed to one.
//
// It is safe for concurrent use. It is a client-side helper, not a wire type.
type ResponseCache struct {
	mu      sync.Mutex
	entries map[string]entry
	max     int
	now     func() time.Time
}

// DefaultMaxEntries bounds a cache created with NewResponseCache(0).
const DefaultMaxEntries = 512

// NewResponseCache creates a cache holding at most maxEntries (<=0 uses
// DefaultMaxEntries).
func NewResponseCache(maxEntries int) *ResponseCache {
	if maxEntries <= 0 {
		maxEntries = DefaultMaxEntries
	}
	return &ResponseCache{
		entries: make(map[string]entry),
		max:     maxEntries,
		now:     time.Now,
	}
}

// storeKey composes the map key. Public entries ignore authContext so they are
// shared; private entries are bound to their authContext.
func storeKey(key string, scope CacheScope, authContext string) string {
	if scope == CachePrivate {
		return "priv\x00" + authContext + "\x00" + key
	}
	return "pub\x00" + key
}

// Store records value under key using the freshness/scope from hint. A
// non-positive TTLMs stores an immediately-stale entry (served only via a
// concurrent read before expiry; effectively refetched each time).
func (c *ResponseCache) Store(key string, hint CacheableResult, value []byte, authContext string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	scope := hint.CacheScope
	if scope == "" {
		scope = CachePrivate // conservative default
	}
	expires := c.now().Add(time.Duration(hint.TTLMs) * time.Millisecond)
	c.entries[storeKey(key, scope, authContext)] = entry{
		value:     append([]byte(nil), value...),
		expiresAt: expires,
		scope:     scope,
	}
	c.evictLocked()
}

// Lookup returns a still-fresh cached value for key, trying the caller's
// private scope first, then the shared public scope.
func (c *ResponseCache) Lookup(key, authContext string) ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	for _, k := range []string{
		storeKey(key, CachePrivate, authContext),
		storeKey(key, CachePublic, authContext),
	} {
		if e, ok := c.entries[k]; ok {
			if now.Before(e.expiresAt) {
				return append([]byte(nil), e.value...), true
			}
			delete(c.entries, k) // drop stale
		}
	}
	return nil, false
}

// Invalidate drops every entry for key across scopes and authorization
// contexts. Use it on a list_changed notification, which evicts immediately
// regardless of TTL.
func (c *ResponseCache) Invalidate(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	pub := storeKey(key, CachePublic, "")
	for k := range c.entries {
		if k == pub || hasKeySuffix(k, key) {
			delete(c.entries, k)
		}
	}
}

// hasKeySuffix reports whether a private composite key ends with the given key.
func hasKeySuffix(composite, key string) bool {
	const sep = "\x00"
	return len(composite) >= len(key)+len(sep) &&
		composite[len(composite)-len(key):] == key &&
		composite[len(composite)-len(key)-len(sep):len(composite)-len(key)] == sep
}

// Fetch applies the caching strategy for mode. On ModeUse it returns a fresh
// cached value when present; otherwise (and always for ModeRefresh) it calls
// fetch and, unless bypassing, stores the returned hint+value. fetch returns
// the freshness hint alongside the raw response bytes.
func (c *ResponseCache) Fetch(
	mode Mode,
	key, authContext string,
	fetch func() (CacheableResult, []byte, error),
) ([]byte, error) {
	if mode == ModeUse {
		if v, ok := c.Lookup(key, authContext); ok {
			return v, nil
		}
	}
	hint, value, err := fetch()
	if err != nil {
		return nil, err
	}
	if mode != ModeBypass {
		c.Store(key, hint, value, authContext)
	}
	return value, nil
}

// evictLocked bounds the store by dropping the soonest-to-expire entries.
func (c *ResponseCache) evictLocked() {
	if len(c.entries) <= c.max {
		return
	}
	type kv struct {
		key     string
		expires time.Time
	}
	all := make([]kv, 0, len(c.entries))
	for k, e := range c.entries {
		all = append(all, kv{k, e.expiresAt})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].expires.Before(all[j].expires) })
	for _, item := range all[:len(c.entries)-c.max] {
		delete(c.entries, item.key)
	}
}
