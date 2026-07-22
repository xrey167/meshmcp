package air

import "testing"

// TestCatalogBuilder covers NewCatalog/Add/Names/Sorted.
func TestCatalogBuilder(t *testing.T) {
	c := NewCatalog("meshmcp", "1.0", "gw.mesh").
		Add(CatalogEntry{Name: "web", Address: "a:2", Transport: TransportHTTP}).
		Add(CatalogEntry{Name: "fs", Address: "a:1", Transport: TransportStdio})
	if c.Service != "meshmcp" || c.Gateway != "gw.mesh" || len(c.Endpoints) != 2 {
		t.Fatalf("builder: %+v", c)
	}
	if c.Schema != CatalogSchemaV1 {
		t.Fatalf("NewCatalog schema = %q, want %q", c.Schema, CatalogSchemaV1)
	}
	if names := c.Names(); len(names) != 2 || names[0] != "web" {
		t.Fatalf("Names() = %v", names)
	}
	if s := c.Sorted().Names(); s[0] != "fs" || s[1] != "web" {
		t.Fatalf("Sorted() = %v", s)
	}
	// Sorted returns a copy; the original order is untouched.
	if c.Names()[0] != "web" {
		t.Fatal("Sorted must not mutate the original")
	}
}

func TestCatalogNormalizeAndValidate(t *testing.T) {
	c := Catalog{
		Schema: " " + CatalogSchemaV1 + " ", Service: " meshmcp ", Version: " 1 ", Gateway: " gw.mesh ",
		Endpoints: []CatalogEntry{{
			ID: "backend:fs", Kind: ComponentBackend, Name: " fs ", Address: " a:1 ", Transport: " STDIO ",
			Features: []Feature{{Name: FeatureAirSteerV1}, {Name: FeatureAirBrowseV1}, {Name: FeatureAirSteerV1}},
		}},
	}
	n, err := c.Normalized()
	if err != nil {
		t.Fatal(err)
	}
	if n.Service != "meshmcp" || n.Endpoints[0].Name != "fs" || n.Endpoints[0].Transport != TransportStdio {
		t.Fatalf("catalog strings not normalized: %+v", n)
	}
	if len(n.Endpoints[0].Features) != 2 || n.Endpoints[0].Features[0].Name != FeatureAirBrowseV1 {
		t.Fatalf("features not normalized: %+v", n.Endpoints[0].Features)
	}
	if !n.Endpoints[0].Steerable {
		t.Fatal("standard steer feature did not populate legacy boolean")
	}
	if c.Service != " meshmcp " || len(c.Endpoints[0].Features) != 3 {
		t.Fatal("Normalized mutated its receiver")
	}

	dup := n
	dup.Endpoints = append(dup.Endpoints, n.Endpoints[0])
	dup.Endpoints[1].Name = "another"
	if err := dup.Validate(); err == nil {
		t.Fatal("duplicate stable component id accepted")
	}
	badSchema := n
	badSchema.Schema = "com.example/unknown"
	if err := badSchema.Validate(); err == nil {
		t.Fatal("unknown catalog schema accepted")
	}
}

func TestCatalogResolveStableIDAndAmbiguity(t *testing.T) {
	c := Catalog{Endpoints: []CatalogEntry{
		{ID: "backend:one", Name: "search", Address: "a:1", Transport: TransportStdio},
		{ID: "backend:two", Name: "search", Address: "b:2", Transport: TransportStdio},
		{ID: "backend:fs", Name: "files", Address: "c:3", Transport: TransportStdio},
	}}
	if got, err := c.Resolve("backend:two"); err != nil || got.Address != "b:2" {
		t.Fatalf("Resolve by id = %+v, %v", got, err)
	}
	if got, err := c.Resolve("files"); err != nil || got.ID != "backend:fs" {
		t.Fatalf("Resolve by unique name = %+v, %v", got, err)
	}
	if _, err := c.Resolve("search"); err == nil {
		t.Fatal("ambiguous component name did not fail")
	}
	if _, err := c.Resolve("missing"); err == nil {
		t.Fatal("missing component did not fail")
	}
}

// TestCatalogEntryValid covers the transport/field validation.
func TestCatalogEntryValid(t *testing.T) {
	if err := (CatalogEntry{Name: "fs", Address: "a:1", Transport: TransportStdio}).Valid(); err != nil {
		t.Fatalf("valid entry rejected: %v", err)
	}
	bad := []CatalogEntry{
		{Address: "a:1", Transport: TransportStdio},    // no name
		{Name: "fs", Transport: TransportStdio},        // no address
		{Name: "fs", Address: "a:1", Transport: "ftp"}, // unknown transport
		{Name: "fs", Address: "a:1"},                   // empty transport
	}
	for _, e := range bad {
		if err := e.Valid(); err == nil {
			t.Fatalf("invalid entry accepted: %+v", e)
		}
	}
}
