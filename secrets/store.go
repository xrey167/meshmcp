// Package secrets is a credential broker on the mesh. The gateway already sits
// in the data path and parses every tools/call, so it can inject secrets by
// cryptographic identity: an agent references a secret by name
// ({{secret:stripe_key}}) and NEVER holds the raw value — the broker resolves
// the reference against per-identity grants, substitutes it into the outbound
// call to the backend, and audits the use (the name, never the value).
//
// It composes with the firewall: a grant can refuse injection into a tainted
// session, so untrusted data that entered a session can never cause a
// credential to be used — credential-exfiltration defense at the network layer.
package secrets

import (
	"encoding/json"
	"fmt"
	"os"
)

// Store resolves a secret name to its value. Implementations wrap env vars, a
// file, or (later) a real KMS/Vault. A Store must never log or expose values.
type Store interface {
	Get(name string) (string, bool)
}

// MapStore is an in-memory Store (tests, small deployments).
type MapStore map[string]string

func (m MapStore) Get(name string) (string, bool) { v, ok := m[name]; return v, ok }

// EnvStore reads secrets from environment variables named Prefix+name, so
// values live in the process environment (injected by a supervisor / systemd
// credentials / a k8s secret) rather than on disk.
type EnvStore struct {
	Prefix string
}

func (e EnvStore) Get(name string) (string, bool) {
	return os.LookupEnv(e.Prefix + name)
}

// FileStore reads a flat JSON object {"name":"value",...} from a file. The file
// SHOULD be mode 0600; the broker warns if it is group/world readable.
type FileStore struct {
	m map[string]string
}

// NewFileStore loads a JSON secrets file.
func NewFileStore(path string) (*FileStore, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m map[string]string
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("parse secrets file %s: %w", path, err)
	}
	return &FileStore{m: m}, nil
}

func (f *FileStore) Get(name string) (string, bool) { v, ok := f.m[name]; return v, ok }

// Names returns the secret names in the store (NOT the values) — for a config
// check that confirms availability without ever revealing a secret.
func (f *FileStore) Names() []string {
	out := make([]string, 0, len(f.m))
	for k := range f.m {
		out = append(out, k)
	}
	return out
}

// Chain tries each Store in order, returning the first hit. Useful to layer a
// file of local dev secrets under environment-provided production ones.
type Chain []Store

func (c Chain) Get(name string) (string, bool) {
	for _, s := range c {
		if v, ok := s.Get(name); ok {
			return v, true
		}
	}
	return "", false
}
