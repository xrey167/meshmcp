package discover_test

import (
	"encoding/json"
	"testing"

	"github.com/xrey167/meshmcp/protocol/discover"
)

func TestDiscoverResultRoundTrip(t *testing.T) {
	raw := `{
		"resultType": "complete",
		"ttlMs": 60000,
		"cacheScope": "public",
		"supportedVersions": ["2025-06-18", "2026-07-28"],
		"capabilities": {"tools": {"listChanged": true}, "resources": {"subscribe": true}},
		"instructions": "Use the weather tools."
	}`
	var res discover.DiscoverResult
	if err := json.Unmarshal([]byte(raw), &res); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if res.ResultType != discover.ResultTypeComplete || res.CacheScope != discover.CachePublic {
		t.Fatalf("cacheable fields lost: %+v", res.CacheableResult)
	}
	if len(res.SupportedVersions) != 2 {
		t.Fatalf("supportedVersions = %v", res.SupportedVersions)
	}
	if res.Capabilities.Tools == nil || !res.Capabilities.Tools.ListChanged {
		t.Fatalf("tools capability lost: %+v", res.Capabilities)
	}

	out, err := json.Marshal(&res)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var probe map[string]any
	if err := json.Unmarshal(out, &probe); err != nil {
		t.Fatalf("re-unmarshal: %v", err)
	}
	if probe["resultType"] != "complete" || probe["ttlMs"].(float64) != 60000 {
		t.Fatalf("cacheable fields not marshalled inline: %v", probe)
	}
}
