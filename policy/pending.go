package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Pending is a held require_cosign tool call awaiting a human decision. The
// approver (a human identity on the mesh — typically a phone) lists these and
// approves or denies them, which is how the co-sign flow becomes an actual
// inbox rather than a silent deny.
type Pending struct {
	Peer    string `json:"peer"`
	PeerKey string `json:"peer_key,omitempty"`
	Backend string `json:"backend"`
	Tool    string `json:"tool"`
	RPCID   string `json:"rpc_id,omitempty"`
	// ArgsHash is the canonical hash of the exact arguments the held call carried,
	// and PolicyHash the policy version in force when it was held. They let an
	// approver mint a request-bound approval (FileApprovalStore.Grant) that the
	// gateway consumes only for THESE arguments under THIS policy — turning the
	// approver into the request-bound signer without giving it the raw arguments
	// or a copy of the policy.
	ArgsHash   string `json:"args_hash,omitempty"`
	PolicyHash string `json:"policy_hash,omitempty"`
	Requested  string `json:"requested"` // RFC3339
}

// Key identifies the (peer, tool) a pending request is about — the same key
// CosignKey uses, so approving a pending grants exactly that call.
func (p Pending) Key() string { return CosignKey(p.Peer, p.Tool) }

// ApprovalRequest rebuilds the exact request-bound operation this held call
// represents, so an approver can Grant a signed approval bound to it. Session is
// intentionally left unset to match the gateway's DecideToolCallBound request.
func (p Pending) ApprovalRequest() ApprovalRequest {
	return ApprovalRequest{
		PeerKey:    p.PeerKey,
		Backend:    p.Backend,
		Tool:       p.Tool,
		ArgsHash:   p.ArgsHash,
		PolicyHash: p.PolicyHash,
	}
}

// PendingStore records and lists held co-sign requests.
type PendingStore interface {
	Record(p Pending) error
	List() ([]Pending, error)
	Clear(peer, tool string) error
}

// FilePending stores one JSON file per held (peer, tool) request in a shared
// directory — typically the same directory as the co-sign approvals, so the
// approver sees requests and writes grants in one place.
type FilePending struct {
	Dir string
	TTL time.Duration // requests older than TTL are treated as expired (0 = no expiry)
}

func pendingFile(dir, peer, tool string) string {
	sum := sha256.Sum256([]byte(CosignKey(peer, tool)))
	return filepath.Join(dir, "pending-"+hex.EncodeToString(sum[:8])+".json")
}

// Record writes (or refreshes) a pending request.
func (s *FilePending) Record(p Pending) error {
	if s == nil || s.Dir == "" {
		return nil
	}
	if err := os.MkdirAll(s.Dir, 0o755); err != nil {
		return err
	}
	if p.Requested == "" {
		p.Requested = time.Now().UTC().Format(time.RFC3339)
	}
	b, _ := json.MarshalIndent(p, "", "  ")
	return os.WriteFile(pendingFile(s.Dir, p.Peer, p.Tool), b, 0o644)
}

// List returns the outstanding (non-expired) pending requests, newest first.
func (s *FilePending) List() ([]Pending, error) {
	if s == nil || s.Dir == "" {
		return nil, nil
	}
	ents, err := os.ReadDir(s.Dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []Pending
	for _, e := range ents {
		if e.IsDir() || !strings.HasPrefix(e.Name(), "pending-") || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(s.Dir, e.Name()))
		if err != nil {
			continue
		}
		var p Pending
		if json.Unmarshal(b, &p) != nil {
			continue
		}
		if s.TTL > 0 {
			if t, err := time.Parse(time.RFC3339, p.Requested); err == nil && time.Since(t) > s.TTL {
				continue // expired
			}
		}
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Requested > out[j].Requested })
	return out, nil
}

// Get returns the (non-expired) pending record for (peer, tool), so an approver
// can read its request-bound binding (ArgsHash/PolicyHash) before granting.
func (s *FilePending) Get(peer, tool string) (Pending, bool) {
	if s == nil || s.Dir == "" {
		return Pending{}, false
	}
	b, err := os.ReadFile(pendingFile(s.Dir, peer, tool))
	if err != nil {
		return Pending{}, false
	}
	var p Pending
	if json.Unmarshal(b, &p) != nil {
		return Pending{}, false
	}
	if s.TTL > 0 {
		if t, err := time.Parse(time.RFC3339, p.Requested); err == nil && time.Since(t) > s.TTL {
			return Pending{}, false // expired
		}
	}
	return p, true
}

// Has reports whether a (non-expired) pending request exists for (peer, tool).
func (s *FilePending) Has(peer, tool string) bool {
	if s == nil || s.Dir == "" {
		return false
	}
	b, err := os.ReadFile(pendingFile(s.Dir, peer, tool))
	if err != nil {
		return false
	}
	if s.TTL > 0 {
		var p Pending
		if json.Unmarshal(b, &p) == nil {
			if t, err := time.Parse(time.RFC3339, p.Requested); err == nil && time.Since(t) > s.TTL {
				return false
			}
		}
	}
	return true
}

// Clear removes the pending record for (peer, tool) — called once it is
// approved or denied.
func (s *FilePending) Clear(peer, tool string) error {
	if s == nil || s.Dir == "" {
		return nil
	}
	err := os.Remove(pendingFile(s.Dir, peer, tool))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}
