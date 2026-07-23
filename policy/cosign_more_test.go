package policy

import (
	"testing"
	"time"
)

// TestFileCosignDenyMarkerLifecycle pins the three-state approve/deny/pending
// surface: a deny marker is independent of the grant (a denial is NOT an
// approval, and an approval does not clear a denial), and ClearDeny is
// idempotent.
func TestFileCosignDenyMarkerLifecycle(t *testing.T) {
	dir := t.TempDir()
	fc := &FileCosign{Dir: dir}
	key := CosignKey("agent.mesh", "wire")

	if IsDenied(dir, "agent.mesh", "wire") {
		t.Fatal("nothing recorded yet: must not be denied")
	}
	if err := Deny(dir, "agent.mesh", "wire", "alice", time.Now()); err != nil {
		t.Fatal(err)
	}
	if !IsDenied(dir, "agent.mesh", "wire") {
		t.Fatal("explicit denial must be reported by IsDenied")
	}
	// A denial is not an approval — the deny marker must never satisfy Approved.
	if fc.Approved(key) {
		t.Fatal("a deny marker must not count as an approval")
	}
	// A denial for one (peer, tool) does not leak to another.
	if IsDenied(dir, "agent.mesh", "other_tool") {
		t.Fatal("denial must be scoped to its (peer, tool)")
	}
	// The two markers are independent files: granting while denied leaves both
	// states visible for the caller to arbitrate.
	if err := Grant(dir, "agent.mesh", "wire", "bob", time.Now()); err != nil {
		t.Fatal(err)
	}
	if !fc.Approved(key) || !IsDenied(dir, "agent.mesh", "wire") {
		t.Fatal("grant and deny markers must coexist independently")
	}
	if err := ClearDeny(dir, "agent.mesh", "wire"); err != nil {
		t.Fatal(err)
	}
	if IsDenied(dir, "agent.mesh", "wire") {
		t.Fatal("ClearDeny must remove the denial")
	}
	// Idempotent: clearing an absent marker is not an error.
	if err := ClearDeny(dir, "agent.mesh", "wire"); err != nil {
		t.Fatalf("ClearDeny on a missing marker must be a no-op, got %v", err)
	}
	// Revoke of a missing approval is likewise a no-op.
	if err := Revoke(dir, "nobody.mesh", "wire"); err != nil {
		t.Fatalf("Revoke on a missing approval must be a no-op, got %v", err)
	}
}

// TestFileCosignNilAndEmptyDirFailClosed: an unconfigured store approves
// nothing.
func TestFileCosignNilAndEmptyDirFailClosed(t *testing.T) {
	var nilStore *FileCosign
	if nilStore.Approved("p|t") {
		t.Fatal("nil FileCosign must fail closed")
	}
	if (&FileCosign{}).Approved("p|t") {
		t.Fatal("FileCosign with no Dir must fail closed")
	}
}

// TestFileCosignZeroTTLNeverExpires: TTL <= 0 means approvals do not age out,
// even with an ancient (but valid) timestamp.
func TestFileCosignZeroTTLNeverExpires(t *testing.T) {
	dir := t.TempDir()
	if err := Grant(dir, "agent.mesh", "deploy", "alice", time.Now().Add(-24*365*time.Hour)); err != nil {
		t.Fatal(err)
	}
	fc := &FileCosign{Dir: dir} // TTL zero
	if !fc.Approved(CosignKey("agent.mesh", "deploy")) {
		t.Fatal("with no TTL an old approval must still count")
	}
	// The same record under a TTL is expired — the TTL is what bounds it.
	fcTTL := &FileCosign{Dir: dir, TTL: time.Hour}
	if fcTTL.Approved(CosignKey("agent.mesh", "deploy")) {
		t.Fatal("the same old approval must expire under a TTL")
	}
}

// TestFileCosignCrossInstanceSharedDir: two FileCosign instances over one
// shared directory see the same grants and revocations — the property that lets
// a gateway fleet share the migration store as its approval store.
func TestFileCosignCrossInstanceSharedDir(t *testing.T) {
	dir := t.TempDir()
	gwA := &FileCosign{Dir: dir}
	gwB := &FileCosign{Dir: dir}
	key := CosignKey("agent.mesh", "transfer")

	if err := Grant(dir, "agent.mesh", "transfer", "alice", time.Now()); err != nil {
		t.Fatal(err)
	}
	if !gwA.Approved(key) || !gwB.Approved(key) {
		t.Fatal("a grant must be visible to every instance sharing the dir")
	}
	if err := Revoke(dir, "agent.mesh", "transfer"); err != nil {
		t.Fatal(err)
	}
	if gwA.Approved(key) || gwB.Approved(key) {
		t.Fatal("a revocation must be visible to every instance sharing the dir")
	}
}
