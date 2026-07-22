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
