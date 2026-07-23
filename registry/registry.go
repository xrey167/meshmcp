// Package registry is a file-based service registry: MCP backends register
// their mesh address under a logical name, and the router discovers upstreams
// dynamically instead of from a static list. Each registration is its own
// file in a shared directory, so multiple gateway processes can register
// concurrently without coordinating writes.
package registry

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Registry advertises and discovers backend addresses by logical name.
type Registry interface {
	Register(name, addr string) error
	Deregister(name, addr string) error
	Lookup() (map[string][]string, error)
}

// FileRegistry stores one JSON file per (name, addr) registration.
type FileRegistry struct {
	dir string
	mu  sync.Mutex
}

func NewFileRegistry(dir string) (*FileRegistry, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	return &FileRegistry{dir: dir}, nil
}

// registrySchemaVersion is the current on-disk format version of a registration
// file. The registry is discovery state, not a security store, so a newer-format
// entry is skipped on lookup (like any unreadable entry) rather than failing the
// whole lookup closed.
const registrySchemaVersion = 1

type entry struct {
	// SchemaVersion self-describes the registration format so a newer build's
	// entry is skipped by an older reader instead of being misinterpreted.
	SchemaVersion int    `json:"schema_version,omitempty"`
	Name          string `json:"name"`
	Addr          string `json:"addr"`
}

func (r *FileRegistry) file(name, addr string) string {
	sum := sha256.Sum256([]byte(name + "|" + addr))
	safe := strings.Map(func(c rune) rune {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' {
			return c
		}
		return '_'
	}, name)
	return filepath.Join(r.dir, fmt.Sprintf("%s_%s.json", safe, hex.EncodeToString(sum[:6])))
}

func (r *FileRegistry) Register(name, addr string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	b, err := json.Marshal(entry{SchemaVersion: registrySchemaVersion, Name: name, Addr: addr})
	if err != nil {
		return err
	}
	return os.WriteFile(r.file(name, addr), b, 0o644)
}

func (r *FileRegistry) Deregister(name, addr string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	err := os.Remove(r.file(name, addr))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

// Lookup returns name -> deduplicated addresses across all registrations.
func (r *FileRegistry) Lookup() (map[string][]string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	ents, err := os.ReadDir(r.dir)
	if err != nil {
		return nil, err
	}
	seen := map[string]map[string]bool{}
	out := map[string][]string{}
	for _, de := range ents {
		if de.IsDir() || !strings.HasSuffix(de.Name(), ".json") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(r.dir, de.Name()))
		if err != nil {
			continue
		}
		var e entry
		if json.Unmarshal(b, &e) != nil || e.Name == "" || e.Addr == "" {
			continue
		}
		if e.SchemaVersion > registrySchemaVersion {
			continue // written by a newer build — skip rather than misread
		}
		if seen[e.Name] == nil {
			seen[e.Name] = map[string]bool{}
		}
		if !seen[e.Name][e.Addr] {
			seen[e.Name][e.Addr] = true
			out[e.Name] = append(out[e.Name], e.Addr)
		}
	}
	return out, nil
}
