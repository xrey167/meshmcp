package air

import (
	"fmt"
	"sort"
	"strings"
)

// CatalogPath is the standard well-known discovery URL a gateway serves its Air
// catalog at, mirroring the ARD spec's /.well-known/ai-catalog.json.
const CatalogPath = "/.well-known/ai-catalog.json"

// Transport is how a backend is reached. A discoverable backend is one of these.
const (
	TransportStdio  = "stdio"
	TransportHTTP   = "http"
	TransportRemote = "remote"
)

// Catalog is the discovery document a gateway serves: the service, its version,
// the gateway identity, and the endpoints the calling identity may reach. It is
// filtered per-caller by the gateway so a peer never discovers a backend it
// could not already call.
type Catalog struct {
	// Schema is optional for backward compatibility with catalogs emitted
	// before component cards. NewCatalog emits CatalogSchemaV1.
	Schema    string         `json:"schema,omitempty"`
	Service   string         `json:"service"`
	Version   string         `json:"version"`
	Gateway   string         `json:"gateway,omitempty"`
	Endpoints []CatalogEntry `json:"endpoints"`
}

// NewCatalog starts an empty catalog for a gateway.
func NewCatalog(service, version, gateway string) Catalog {
	return Catalog{Schema: CatalogSchemaV1, Service: service, Version: version, Gateway: gateway}
}

// Add appends an endpoint and returns the catalog, so entries can be chained.
func (c Catalog) Add(e CatalogEntry) Catalog {
	c.Endpoints = append(c.Endpoints, e)
	return c
}

// Names returns the endpoint names in catalog order.
func (c Catalog) Names() []string {
	out := make([]string, len(c.Endpoints))
	for i, e := range c.Endpoints {
		out[i] = e.Name
	}
	return out
}

// Sorted returns a copy with endpoints ordered by name, for a stable view.
func (c Catalog) Sorted() Catalog {
	eps := append([]CatalogEntry(nil), c.Endpoints...)
	sort.Slice(eps, func(i, j int) bool {
		if eps[i].Name != eps[j].Name {
			return eps[i].Name < eps[j].Name
		}
		if eps[i].ID != eps[j].ID {
			return eps[i].ID < eps[j].ID
		}
		return eps[i].Address < eps[j].Address
	})
	c.Endpoints = eps
	return c
}

// CatalogEntry is one discoverable backend: how to address it and what it
// supports, so a client knows whether it can list tools, resume, or steer.
type CatalogEntry struct {
	// ID is the stable logical identity of the component. Kind and ID are an
	// additive pair: both are omitted by legacy catalogs and both are required
	// by a component card.
	ID      string        `json:"id,omitempty"`
	Kind    ComponentKind `json:"kind,omitempty"`
	Name    string        `json:"name"`
	Version string        `json:"version,omitempty"`
	Owner   IdentityRef   `json:"owner,omitzero"`

	Address   string `json:"address"`   // mesh-ip:port to dial
	Transport string `json:"transport"` // stdio | http | remote

	// Features and Lifecycle are the component-card surface. Resumable and
	// Steerable remain on the wire for older clients; Normalized mirrors them to
	// and from the corresponding standard feature identifiers.
	Features  []Feature `json:"features,omitempty"`
	Lifecycle Lifecycle `json:"lifecycle,omitzero"`
	Resumable bool      `json:"resumable,omitempty"`
	Steerable bool      `json:"steerable,omitempty"` // has a live session server (Air · Steer)
}

// Valid reports whether the entry is well-formed: a name, a mesh address, and a
// known transport. Kept as a compatibility alias for Validate.
func (e CatalogEntry) Valid() error {
	return e.Validate()
}

// Normalized validates the catalog and returns a canonical copy. Component
// feature sets are sorted/deduplicated, legacy feature booleans are mirrored,
// and user-facing strings are trimmed. Endpoint order is deliberately retained
// because callers may use it for presentation; Sorted provides an ordered view.
func (c Catalog) Normalized() (Catalog, error) {
	c.Schema = strings.TrimSpace(c.Schema)
	c.Service = strings.TrimSpace(c.Service)
	c.Version = strings.TrimSpace(c.Version)
	c.Gateway = strings.TrimSpace(c.Gateway)
	if c.Schema != "" && c.Schema != CatalogSchemaV1 {
		return Catalog{}, fmt.Errorf("unsupported Air catalog schema %q", c.Schema)
	}
	if c.Service == "" || c.Version == "" {
		return Catalog{}, fmt.Errorf("Air catalog needs service and version")
	}
	if err := validDisplayText("catalog service", c.Service, 128); err != nil {
		return Catalog{}, err
	}
	if err := validDisplayText("catalog version", c.Version, 128); err != nil {
		return Catalog{}, err
	}
	if err := validDisplayText("catalog gateway", c.Gateway, 1024); err != nil {
		return Catalog{}, err
	}

	ids := make(map[string]string, len(c.Endpoints))
	eps := make([]CatalogEntry, len(c.Endpoints))
	for i, raw := range c.Endpoints {
		e, err := raw.Normalized()
		if err != nil {
			return Catalog{}, fmt.Errorf("endpoint %d: %w", i+1, err)
		}
		if e.ID != "" {
			if prior, exists := ids[e.ID]; exists {
				return Catalog{}, fmt.Errorf("duplicate component id %q on %q and %q", e.ID, prior, e.Name)
			}
			ids[e.ID] = e.Name
		}
		eps[i] = e
	}
	c.Endpoints = eps
	return c, nil
}

// Validate reports whether a catalog is a well-formed legacy catalog or v1
// component-card catalog. It does not mutate the receiver.
func (c Catalog) Validate() error {
	_, err := c.Normalized()
	return err
}

// Entry looks up a discovered backend by name, so a client can resolve a
// logical name to its mesh address without re-scanning the slice.
func (c Catalog) Entry(name string) (CatalogEntry, bool) {
	for _, e := range c.Endpoints {
		if e.Name == name {
			return e, true
		}
	}
	return CatalogEntry{}, false
}

// Resolve finds a component by stable ID first, then by its human-readable
// name. Name resolution fails on ambiguity instead of silently choosing a
// replica/component; legacy Entry retains its historical first-match behavior.
func (c Catalog) Resolve(ref string) (CatalogEntry, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return CatalogEntry{}, fmt.Errorf("component reference is required")
	}
	for _, e := range c.Endpoints {
		if e.ID != "" && e.ID == ref {
			return e, nil
		}
	}
	var match CatalogEntry
	n := 0
	for _, e := range c.Endpoints {
		if e.Name == ref {
			match = e
			n++
		}
	}
	switch n {
	case 0:
		return CatalogEntry{}, fmt.Errorf("component %q not found", ref)
	case 1:
		return match, nil
	default:
		return CatalogEntry{}, fmt.Errorf("component name %q is ambiguous across %d entries; use a stable id", ref, n)
	}
}

// Steerable returns the discovered backends that expose a live session server,
// i.e. the ones `air steer` can drive.
func (c Catalog) Steerable() []CatalogEntry {
	return c.filter(func(e CatalogEntry) bool { return e.Supports(FeatureAirSteerV1) })
}

// Resumable returns the discovered backends whose sessions survive a reconnect.
func (c Catalog) Resumable() []CatalogEntry {
	return c.filter(func(e CatalogEntry) bool { return e.Supports(FeatureAirResumeV1) })
}

func (c Catalog) filter(keep func(CatalogEntry) bool) []CatalogEntry {
	var out []CatalogEntry
	for _, e := range c.Endpoints {
		if keep(e) {
			out = append(out, e)
		}
	}
	return out
}
