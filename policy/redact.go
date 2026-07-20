package policy

import (
	"bytes"
	"sync"
)

// redactMinLen is the shortest injected value the redactor will scrub from
// responses. Very short values would over-match ordinary output; real
// credentials are long, so this avoids mangling legitimate responses.
const redactMinLen = 4

// redactPlaceholder replaces an injected secret value found in a response.
var redactPlaceholder = []byte("[redacted-secret]")

// Redactor scrubs injected secret values out of the backend->peer stream, so a
// backend cannot trivially echo an injected credential back to the agent
// (defeating credential isolation). It holds the exact byte values injected into
// this session's requests and replaces any occurrence in responses (and traces)
// with a placeholder. It is safe for concurrent use.
//
// This is best-effort response hygiene, not a guarantee: a malicious backend can
// transform a value (encode, split, leak out of band) and remains within the
// secret's exposure boundary (see docs/THREAT-MODEL.md). It defeats the trivial
// echo, which is the common accidental-leak path.
type Redactor struct {
	mu   sync.RWMutex
	vals [][]byte
}

// Add records injected secret values to scrub from later responses. Values
// shorter than redactMinLen are ignored, and duplicates are skipped.
func (r *Redactor) Add(vals ...[]byte) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, v := range vals {
		if len(v) < redactMinLen {
			continue
		}
		dup := false
		for _, existing := range r.vals {
			if bytes.Equal(existing, v) {
				dup = true
				break
			}
		}
		if !dup {
			r.vals = append(r.vals, append([]byte(nil), v...))
		}
	}
}

// active reports whether the redactor has any values to scrub (fast path).
func (r *Redactor) active() bool {
	if r == nil {
		return false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.vals) > 0
}

// Redact returns b with every recorded injected value replaced by the
// placeholder. It returns b unchanged (no allocation) when nothing matches.
func (r *Redactor) Redact(b []byte) []byte {
	if r == nil {
		return b
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := b
	for _, v := range r.vals {
		if bytes.Contains(out, v) {
			out = bytes.ReplaceAll(out, v, redactPlaceholder)
		}
	}
	return out
}
