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

// Approved reports whether a non-expired approval exists for key.
func (fc *FileCosign) Approved(key string) bool {
	if fc == nil || fc.Dir == "" {
		return false
	}
	b, err := os.ReadFile(cosignFile(fc.Dir, key))
	if err != nil {
		return false
	}
	if fc.TTL <= 0 {
		return true
	}
	var a Approval
	if json.Unmarshal(b, &a) != nil {
		return true // present but unparseable: fail open on the record, not on access
	}
	t, err := time.Parse(time.RFC3339, a.GrantedAt)
	if err != nil {
		return true
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
