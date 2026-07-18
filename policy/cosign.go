package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// FileCosign is a CosignStore backed by a shared directory: each approval is a
// small JSON file named for the (peer, tool) key. A human identity on the mesh
// grants an approval out of band (see Grant / the `meshmcp approve` command),
// and the gateway checks the directory when a require_cosign call arrives.
// Because the directory can be the same shared store used for session
// migration, no extra infrastructure is needed.
//
// Approvals optionally expire: if TTL > 0, an approval older than TTL no longer
// counts, so a co-sign authorizes a bounded window rather than forever.
type FileCosign struct {
	Dir string
	TTL time.Duration
}

// Approval is the on-disk record of a co-sign.
type Approval struct {
	Key       string `json:"key"`
	Peer      string `json:"peer"`
	Tool      string `json:"tool"`
	Approver  string `json:"approver"`   // the human identity who signed
	GrantedAt string `json:"granted_at"` // RFC3339
	unix      int64  // parsed granted_at, for TTL checks
}

func cosignFile(dir, key string) string {
	sum := sha256.Sum256([]byte(key))
	return filepath.Join(dir, "cosign-"+hex.EncodeToString(sum[:8])+".json")
}

// Approved reports whether a valid, non-expired approval exists for key. It
// fails CLOSED: a missing, malformed, mismatched, or (when a TTL is set)
// bad-timestamp record is not an approval. An approval file must parse to a
// well-formed record for the exact key — a corrupt or hand-crafted file no
// longer authorizes a privileged call.
func (fc *FileCosign) Approved(key string) bool {
	if fc == nil || fc.Dir == "" {
		return false
	}
	b, err := os.ReadFile(cosignFile(fc.Dir, key))
	if err != nil {
		return false
	}
	var a Approval
	if json.Unmarshal(b, &a) != nil {
		return false // malformed approval — fail closed
	}
	if a.Key != key {
		return false // wrong/corrupt record — fail closed
	}
	if fc.TTL <= 0 {
		return true
	}
	t, err := time.Parse(time.RFC3339, a.GrantedAt)
	if err != nil {
		return false // unparseable timestamp — fail closed
	}
	return time.Since(t) <= fc.TTL
}

// Grant writes an approval for (peer, tool) into dir, attributed to approver.
// now supplies the timestamp (injectable for tests).
func Grant(dir, peer, tool, approver string, now time.Time) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	a := Approval{
		Key:       CosignKey(peer, tool),
		Peer:      peer,
		Tool:      tool,
		Approver:  approver,
		GrantedAt: now.UTC().Format(time.RFC3339),
	}
	b, _ := json.MarshalIndent(a, "", "  ")
	return os.WriteFile(cosignFile(dir, a.Key), b, 0o644)
}

// Revoke removes an approval for (peer, tool) from dir.
func Revoke(dir, peer, tool string) error {
	err := os.Remove(cosignFile(dir, CosignKey(peer, tool)))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

// denyFile is the on-disk marker for an explicit denial, kept separate from the
// grant so an approver's decision has three distinguishable states — approved,
// denied, pending — which an external requester can poll.
func denyFile(dir, key string) string {
	sum := sha256.Sum256([]byte("deny:" + key))
	return filepath.Join(dir, "deny-"+hex.EncodeToString(sum[:8])+".json")
}

// Deny records an explicit denial of (peer, tool), attributed to by.
func Deny(dir, peer, tool, by string, now time.Time) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	a := Approval{Key: CosignKey(peer, tool), Peer: peer, Tool: tool, Approver: by, GrantedAt: now.UTC().Format(time.RFC3339)}
	b, _ := json.MarshalIndent(a, "", "  ")
	return os.WriteFile(denyFile(dir, a.Key), b, 0o644)
}

// IsDenied reports whether (peer, tool) was explicitly denied.
func IsDenied(dir, peer, tool string) bool {
	_, err := os.Stat(denyFile(dir, CosignKey(peer, tool)))
	return err == nil
}

// ClearDeny removes any denial marker for (peer, tool).
func ClearDeny(dir, peer, tool string) error {
	err := os.Remove(denyFile(dir, CosignKey(peer, tool)))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}
