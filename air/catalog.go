package air

// CatalogPath is the standard well-known discovery URL a gateway serves its Air
// catalog at, mirroring the ARD spec's /.well-known/ai-catalog.json.
const CatalogPath = "/.well-known/ai-catalog.json"

// Catalog is the discovery document a gateway serves: the service, its version,
// the gateway identity, and the endpoints the calling identity may reach. It is
// filtered per-caller by the gateway so a peer never discovers a backend it
// could not already call.
type Catalog struct {
	Service   string         `json:"service"`
	Version   string         `json:"version"`
	Gateway   string         `json:"gateway,omitempty"`
	Endpoints []CatalogEntry `json:"endpoints"`
}

// CatalogEntry is one discoverable backend: how to address it and what it
// supports, so a client knows whether it can list tools, resume, or steer.
type CatalogEntry struct {
	Name      string `json:"name"`
	Address   string `json:"address"`   // mesh-ip:port to dial
	Transport string `json:"transport"` // stdio | http | remote
	Resumable bool   `json:"resumable,omitempty"`
	Steerable bool   `json:"steerable,omitempty"` // has a live session server (Air · Steer)
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

// Steerable returns the discovered backends that expose a live session server,
// i.e. the ones `air steer` can drive.
func (c Catalog) Steerable() []CatalogEntry {
	return c.filter(func(e CatalogEntry) bool { return e.Steerable })
}

// Resumable returns the discovered backends whose sessions survive a reconnect.
func (c Catalog) Resumable() []CatalogEntry {
	return c.filter(func(e CatalogEntry) bool { return e.Resumable })
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
