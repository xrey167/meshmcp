package air

import (
	"sort"
	"strings"
	"testing"
)

func cat(entries ...CatalogEntry) Catalog {
	return Catalog{Service: "meshmcp", Version: "ard1", Endpoints: entries}
}

func TestDiffCatalogsAddedRemovedChanged(t *testing.T) {
	old := cat(
		CatalogEntry{Name: "fs", Address: "100.64.0.2:9101", Transport: TransportStdio, Steerable: true},
		CatalogEntry{Name: "search", Address: "100.64.0.2:9102", Transport: TransportHTTP},
		CatalogEntry{Name: "gone", Address: "100.64.0.2:9103", Transport: TransportStdio},
	)
	cur := cat(
		// fs flipped steerable true->false and moved address.
		CatalogEntry{Name: "fs", Address: "100.64.0.2:9111", Transport: TransportStdio},
		// search unchanged.
		CatalogEntry{Name: "search", Address: "100.64.0.2:9102", Transport: TransportHTTP},
		// vision is new.
		CatalogEntry{Name: "vision", Address: "100.64.0.2:9104", Transport: TransportHTTP, Resumable: true},
	)

	d := DiffCatalogs(old, cur)
	if d.Empty() {
		t.Fatal("delta should not be empty")
	}
	if len(d.Added) != 1 || d.Added[0].Name != "vision" {
		t.Errorf("added = %+v, want [vision]", d.Added)
	}
	if len(d.Removed) != 1 || d.Removed[0].Name != "gone" {
		t.Errorf("removed = %+v, want [gone]", d.Removed)
	}
	if len(d.Changed) != 1 || d.Changed[0].Name != "fs" {
		t.Fatalf("changed = %+v, want [fs]", d.Changed)
	}
	got := append([]string(nil), d.Changed[0].Fields...)
	sort.Strings(got)
	if strings.Join(got, ",") != "address,steerable" {
		t.Errorf("changed fields = %v, want [address steerable]", d.Changed[0].Fields)
	}
	if s := d.Summary(); s != "+1 -1 ~1" {
		t.Errorf("summary = %q, want %q", s, "+1 -1 ~1")
	}
}

func TestDiffCatalogsIdentical(t *testing.T) {
	c := cat(
		CatalogEntry{Name: "a", Address: "x:1", Transport: TransportStdio},
		CatalogEntry{Name: "b", Address: "x:2", Transport: TransportHTTP, Steerable: true},
	)
	// Order should not matter — diff is keyed by name.
	reordered := cat(c.Endpoints[1], c.Endpoints[0])
	d := DiffCatalogs(c, reordered)
	if !d.Empty() {
		t.Fatalf("identical catalogs (reordered) should have no delta, got %+v", d)
	}
	if d.Summary() != "no changes" {
		t.Errorf("summary = %q, want %q", d.Summary(), "no changes")
	}
}

func TestDiffCatalogsFromEmpty(t *testing.T) {
	cur := cat(CatalogEntry{Name: "a", Address: "x:1", Transport: TransportStdio})
	d := DiffCatalogs(Catalog{}, cur)
	if len(d.Added) != 1 || len(d.Removed) != 0 || len(d.Changed) != 0 {
		t.Fatalf("first snapshot should be all-added: %+v", d)
	}
}

func TestChangedFieldsEachField(t *testing.T) {
	base := CatalogEntry{Name: "x", Address: "a:1", Transport: TransportStdio}
	cases := []struct {
		mut   func(CatalogEntry) CatalogEntry
		field string
	}{
		{func(e CatalogEntry) CatalogEntry { e.ID = "backend:x"; return e }, "id"},
		{func(e CatalogEntry) CatalogEntry { e.Name = "renamed"; return e }, "name"},
		{func(e CatalogEntry) CatalogEntry { e.Kind = ComponentBackend; return e }, "kind"},
		{func(e CatalogEntry) CatalogEntry { e.Version = "2"; return e }, "version"},
		{func(e CatalogEntry) CatalogEntry { e.Owner.PubKey = "key"; return e }, "owner"},
		{func(e CatalogEntry) CatalogEntry { e.Address = "a:2"; return e }, "address"},
		{func(e CatalogEntry) CatalogEntry { e.Transport = TransportHTTP; return e }, "transport"},
		{func(e CatalogEntry) CatalogEntry { e.Features = []Feature{{Name: FeatureAirBrowseV1}}; return e }, "features"},
		{func(e CatalogEntry) CatalogEntry { e.Lifecycle.State = LifecycleServing; return e }, "lifecycle"},
		{func(e CatalogEntry) CatalogEntry { e.Steerable = true; return e }, "steerable"},
		{func(e CatalogEntry) CatalogEntry { e.Resumable = true; return e }, "resumable"},
	}
	for _, c := range cases {
		f := changedFields(base, c.mut(base))
		if len(f) != 1 || f[0] != c.field {
			t.Errorf("changedFields for %s = %v", c.field, f)
		}
	}
	if f := changedFields(base, base); len(f) != 0 {
		t.Errorf("identical entries should have no changed fields, got %v", f)
	}
}

func TestDiffCatalogsMatchesStableIDAcrossRename(t *testing.T) {
	old := cat(CatalogEntry{
		ID: "backend:files", Kind: ComponentBackend, Name: "files", Version: "1",
		Address: "a:1", Transport: TransportStdio,
	})
	cur := cat(CatalogEntry{
		ID: "backend:files", Kind: ComponentBackend, Name: "documents", Version: "2",
		Address: "a:2", Transport: TransportStdio,
	})
	d := DiffCatalogs(old, cur)
	if len(d.Added) != 0 || len(d.Removed) != 0 || len(d.Changed) != 1 {
		t.Fatalf("stable-id rename should be one change: %+v", d)
	}
	c := d.Changed[0]
	if c.ID != "backend:files" || c.Name != "documents" {
		t.Fatalf("change did not retain stable/current identity: %+v", c)
	}
	if strings.Join(c.Fields, ",") != "name,version,address" {
		t.Fatalf("rename fields = %v, want name,version,address", c.Fields)
	}
}

func TestDiffCatalogsDoesNotMergeDifferentStableIDsByName(t *testing.T) {
	old := cat(CatalogEntry{ID: "backend:old", Kind: ComponentBackend, Name: "search", Address: "a:1", Transport: TransportStdio})
	cur := cat(CatalogEntry{ID: "backend:new", Kind: ComponentBackend, Name: "search", Address: "a:1", Transport: TransportStdio})
	d := DiffCatalogs(old, cur)
	if len(d.Added) != 1 || len(d.Removed) != 1 || len(d.Changed) != 0 {
		t.Fatalf("identity replacement collapsed into a change: %+v", d)
	}
}

func TestDiffCatalogsLegacyToCardFallsBackToName(t *testing.T) {
	old := cat(CatalogEntry{Name: "files", Address: "a:1", Transport: TransportStdio})
	cur := cat(CatalogEntry{ID: "backend:files", Kind: ComponentBackend, Name: "files", Address: "a:1", Transport: TransportStdio})
	d := DiffCatalogs(old, cur)
	if len(d.Changed) != 1 || len(d.Added) != 0 || len(d.Removed) != 0 || strings.Join(d.Changed[0].Fields, ",") != "id,kind" {
		t.Fatalf("legacy-to-card transition should enrich one entry: %+v", d)
	}
}

func TestChangedFieldsIgnoresFeatureOrderAndDuplicates(t *testing.T) {
	a := CatalogEntry{Features: []Feature{{Name: FeatureAirSteerV1}, {Name: FeatureAirBrowseV1}}}
	b := CatalogEntry{Features: []Feature{{Name: FeatureAirBrowseV1}, {Name: FeatureAirSteerV1}, {Name: FeatureAirSteerV1}}}
	if fields := changedFields(a, b); len(fields) != 0 {
		t.Fatalf("equivalent feature sets changed: %v", fields)
	}
	b.Features[0].Version = "2"
	if fields := changedFields(a, b); len(fields) != 1 || fields[0] != "features" {
		t.Fatalf("feature-version change not detected: %v", fields)
	}
}
