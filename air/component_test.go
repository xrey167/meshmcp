package air

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestStableComponentID(t *testing.T) {
	a, err := StableComponentID("owner-key", ComponentBackend, "files")
	if err != nil {
		t.Fatal(err)
	}
	b, err := StableComponentID("owner-key", ComponentBackend, "files")
	if err != nil {
		t.Fatal(err)
	}
	if a != b || !strings.HasPrefix(a, "cmp_") {
		t.Fatalf("component id is not stable/opaque: %q %q", a, b)
	}
	c, _ := StableComponentID("owner-key", ComponentBackend, "search")
	if c == a {
		t.Fatal("different components received the same id")
	}
	for _, bad := range []struct {
		owner string
		kind  ComponentKind
		name  string
	}{{"", ComponentBackend, "x"}, {"k", "unknown", "x"}, {"k", ComponentBackend, ""}} {
		if _, err := StableComponentID(bad.owner, bad.kind, bad.name); err == nil {
			t.Fatalf("invalid id inputs accepted: %+v", bad)
		}
	}
}

func TestValidateComponentID(t *testing.T) {
	for _, id := range []string{"backend:files", "files.v2", "cmp_012345"} {
		if err := ValidateComponentID(id); err != nil {
			t.Errorf("valid id %q rejected: %v", id, err)
		}
	}
	for _, id := range []string{"", " spaces ", "slash/not-allowed", strings.Repeat("x", 129)} {
		if err := ValidateComponentID(id); err == nil {
			t.Errorf("invalid id %q accepted", id)
		}
	}
}

func TestNormalizeFeaturesDeterministic(t *testing.T) {
	got, err := NormalizeFeatures([]Feature{
		{Name: " AIR.STEER.V1 "},
		{Name: FeatureAirBrowseV1, Version: "1.0"},
		{Name: FeatureAirSteerV1}, // exact duplicate after normalization
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Name != FeatureAirBrowseV1 || got[1].Name != FeatureAirSteerV1 {
		t.Fatalf("features not normalized/sorted: %+v", got)
	}
	if _, err := NormalizeFeatures([]Feature{{Name: "bad feature"}}); err == nil {
		t.Fatal("invalid feature name accepted")
	}
	if _, err := NormalizeFeatures([]Feature{{Name: "x", Version: "1"}, {Name: "x", Version: "2"}}); err == nil {
		t.Fatal("conflicting feature versions accepted")
	}
}

func TestCatalogEntryLegacyFeatureBridge(t *testing.T) {
	legacy := CatalogEntry{
		Name: "fs", Address: "host:9101", Transport: TransportStdio,
		Resumable: true, Steerable: true,
	}
	got, err := legacy.Normalized()
	if err != nil {
		t.Fatalf("legacy entry rejected: %v", err)
	}
	if got.ID != "" || got.Kind != "" {
		t.Fatalf("normalizing legacy entry invented card identity: %+v", got)
	}
	if !got.Supports(FeatureAirResumeV1) || !got.Supports(FeatureAirSteerV1) || len(got.Features) != 0 {
		t.Fatalf("legacy booleans not preserved without inventing card fields: %+v", got)
	}
	second, err := got.Normalized()
	if err != nil {
		t.Fatalf("normalizing a normalized legacy entry is not idempotent: %v", err)
	}
	if !reflect.DeepEqual(second, got) {
		t.Fatalf("second normalization changed legacy entry: first=%+v second=%+v", got, second)
	}
	wire, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	var decoded CatalogEntry
	if err := json.Unmarshal(wire, &decoded); err != nil {
		t.Fatal(err)
	}
	if err := decoded.Validate(); err != nil {
		t.Fatalf("normalized legacy entry failed after a JSON round trip: %v", err)
	}

	featureOnly := CatalogEntry{
		ID: "backend:fs", Kind: ComponentBackend, Name: "fs",
		Address: "host:9101", Transport: TransportStdio,
		Features: []Feature{{Name: FeatureAirResumeV1}, {Name: FeatureAirSteerV1}},
	}
	got, err = featureOnly.Normalized()
	if err != nil {
		t.Fatal(err)
	}
	if !got.Resumable || !got.Steerable {
		t.Fatalf("standard features not mirrored to legacy booleans: %+v", got)
	}

	cardWithLegacyFlag := CatalogEntry{
		ID: "backend:search", Kind: ComponentBackend, Name: "search",
		Address: "host:9102", Transport: TransportStdio, Resumable: true,
	}
	got, err = cardWithLegacyFlag.Normalized()
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Features) != 1 || got.Features[0].Name != FeatureAirResumeV1 {
		t.Fatalf("component-card legacy flag not mirrored to features: %+v", got)
	}
	second, err = got.Normalized()
	if err != nil || !reflect.DeepEqual(second, got) {
		t.Fatalf("component-card normalization is not idempotent: second=%+v err=%v", second, err)
	}
}

func TestCatalogEntryCardValidation(t *testing.T) {
	valid := CatalogEntry{
		ID:      "backend:files",
		Kind:    ComponentBackend,
		Name:    "files",
		Version: "2.1.0",
		Owner: IdentityRef{
			PubKey: "wireguard-key",
			FQDN:   "GW.MESH",
			SPIFFE: "spiffe://example.test/peer/key",
		},
		Address:   "100.64.0.2:9101",
		Transport: TransportStdio,
		Features:  []Feature{{Name: FeatureMCP20250618}, {Name: FeatureAirBrowseV1}},
		Lifecycle: Lifecycle{State: LifecycleServing, Since: "2026-07-22T12:00:00Z", Generation: 3},
	}
	normalized, err := valid.Normalized()
	if err != nil {
		t.Fatalf("valid card rejected: %v", err)
	}
	if normalized.Owner.FQDN != "gw.mesh" {
		t.Fatalf("owner FQDN not canonicalized: %+v", normalized.Owner)
	}

	bad := []CatalogEntry{
		func() CatalogEntry { e := valid; e.ID = ""; return e }(),
		func() CatalogEntry { e := valid; e.Kind = "other"; return e }(),
		func() CatalogEntry { e := valid; e.ID = "bad/id"; return e }(),
		func() CatalogEntry { e := valid; e.Address = "missing-port"; return e }(),
		func() CatalogEntry { e := valid; e.Address = "host\x1b[2J:9101"; return e }(),
		func() CatalogEntry { e := valid; e.Owner.SPIFFE = "https://not-spiffe.test/x"; return e }(),
		func() CatalogEntry { e := valid; e.Lifecycle.State = "healthy"; return e }(),
		func() CatalogEntry { e := valid; e.Lifecycle.Since = "yesterday"; return e }(),
	}
	for _, e := range bad {
		if err := e.Validate(); err == nil {
			t.Fatalf("invalid card accepted: %+v", e)
		}
	}
}

func TestLegacyCatalogEntryJSONStaysCompact(t *testing.T) {
	b, err := json.Marshal(CatalogEntry{Name: "fs", Address: "a:1", Transport: TransportStdio})
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, unwanted := range []string{`"id"`, `"kind"`, `"owner"`, `"features"`, `"lifecycle"`} {
		if strings.Contains(s, unwanted) {
			t.Errorf("legacy JSON unexpectedly contains %s: %s", unwanted, s)
		}
	}
}
