package caching_test

import (
	"encoding/json"
	"testing"

	"meshmcp/protocol/caching"
	"meshmcp/protocol/discover"
)

func TestCacheableResultRoundTrip(t *testing.T) {
	in := caching.CacheableResult{
		ResultType: caching.ResultTypeComplete,
		TTLMs:      3600000,
		CacheScope: caching.CachePublic,
	}
	data, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out caching.CacheableResult
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.TTLMs != 3600000 || out.CacheScope != caching.CachePublic || out.ResultType != "complete" {
		t.Fatalf("round-trip mismatch: %+v", out)
	}
}

// TestDiscoverAlias verifies discover still exposes the caching types via
// aliases, so DiscoverResult embeds the shared CacheableResult.
func TestDiscoverAlias(t *testing.T) {
	var r discover.DiscoverResult
	raw := `{"resultType":"complete","ttlMs":1000,"cacheScope":"private","supportedVersions":["2026-07-28"],"capabilities":{}}`
	if err := json.Unmarshal([]byte(raw), &r); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	// The embedded field is the shared caching.CacheableResult.
	var _ caching.CacheableResult = r.CacheableResult
	if r.CacheScope != discover.CachePrivate || discover.CachePrivate != caching.CachePrivate {
		t.Fatalf("alias mismatch: %v", r.CacheScope)
	}
}
