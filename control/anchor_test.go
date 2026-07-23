package control

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xrey167/meshmcp/policy"
)

// newWitnessServer builds a control server exposing only the anchor witness,
// identifying every caller as callerKey with the given grants.
func newWitnessServer(t *testing.T, callerKey string, grants map[string][]Role, witnessPath string, signers []string) (*Server, *httptest.Server) {
	t.Helper()
	auth, err := NewStaticAuthorizer(grants)
	if err != nil {
		t.Fatal(err)
	}
	wt, err := NewAnchorWitness(witnessPath, signers)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = wt.Close() })
	s := &Server{
		Auth: auth,
		Identify: func(string) (Identity, bool) {
			if callerKey == "" {
				return Identity{}, false
			}
			return Identity{PubKey: callerKey, FQDN: "caller.netbird.cloud"}, true
		},
		Audit:   &captureAudit{},
		Witness: wt,
	}
	return s, httptest.NewServer(s.Handler())
}

// buildCheckpoints drives the real Checkpointer to emit n signed checkpoints
// (one leaf each). salt varies the leaf content, so two chains from the same
// signer produce DIFFERENT checkpoints for the same ordinal — the fork case.
func buildCheckpoints(t *testing.T, signer *policy.Signer, n int, salt byte) []policy.Checkpoint {
	t.Helper()
	var buf bytes.Buffer
	c := policy.NewCheckpointer(signer, &buf, 1, func() string { return "T" }, nil)
	for seq := 1; seq <= n; seq++ {
		sum := sha256.Sum256([]byte{salt, byte(seq)})
		c.Add(seq, hex.EncodeToString(sum[:]))
	}
	var out []policy.Checkpoint
	for _, line := range strings.Split(strings.TrimRight(buf.String(), "\n"), "\n") {
		var cp policy.Checkpoint
		if err := json.Unmarshal([]byte(line), &cp); err != nil {
			t.Fatal(err)
		}
		out = append(out, cp)
	}
	if len(out) != n {
		t.Fatalf("expected %d checkpoints, got %d", n, len(out))
	}
	return out
}

func postCP(t *testing.T, url string, cp policy.Checkpoint) int {
	t.Helper()
	b, err := json.Marshal(cp)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.Post(url+"/v1/anchor", "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

// TestAnchorWitnessEndToEnd: an authorized caller's pinned-signer checkpoint
// is witnessed and lands in the witness file with self-linkage; a re-POST of
// the identical checkpoint is idempotent (200, no second record); a
// conflicting checkpoint for the same ordinal is 409 and the original stands.
func TestAnchorWitnessEndToEnd(t *testing.T) {
	signer, err := policy.GenerateSigner()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "witness.jsonl")
	_, ts := newWitnessServer(t, "GW-KEY", map[string][]Role{"GW-KEY": {RoleAnchorSubmit}}, path, []string{signer.PubKeyHex()})
	defer ts.Close()

	chain := buildCheckpoints(t, signer, 2, 0)
	cp1, cp2 := chain[0], chain[1]
	if code := postCP(t, ts.URL, cp1); code != http.StatusOK {
		t.Fatalf("pinned, authorized checkpoint should be witnessed, got %d", code)
	}
	// Idempotent replay of the same (signer, seq, hash).
	if code := postCP(t, ts.URL, cp1); code != http.StatusOK {
		t.Fatalf("idempotent re-POST should be 200, got %d", code)
	}
	// Conflicting checkpoint for the same ordinal (a fork chain re-signed with
	// the REAL key): fork/rollback evidence.
	forged := buildCheckpoints(t, signer, 1, 1)[0]
	if code := postCP(t, ts.URL, forged); code != http.StatusConflict {
		t.Fatalf("conflicting seq should be 409, got %d", code)
	}
	// Checkpoint 2 extends normally.
	if code := postCP(t, ts.URL, cp2); code != http.StatusOK {
		t.Fatalf("checkpoint 2 should be witnessed, got %d", code)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	recs, _, err := policy.ReadAnchorRecords(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 || recs[0].Seq != 1 || recs[1].Seq != 2 {
		t.Fatalf("witness file must hold exactly the two accepted checkpoints: %+v", recs)
	}
	if recs[0].Checkpoint != cp1.Hash() || recs[1].Checkpoint != cp2.Hash() {
		t.Fatal("witnessed hashes must match the accepted checkpoints")
	}
	if recs[0].Signer != signer.PubKeyHex() || recs[1].Signer != signer.PubKeyHex() {
		t.Fatal("witness records must name the pinned signer")
	}
	// Self-linkage: record 2 links to record 1's line.
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if recs[1].PrevAnchor != policy.AnchorLineHash([]byte(lines[0])) {
		t.Fatal("witness file must be self-linked")
	}
}

// TestAnchorWitnessAuthz: an unauthorized (or unattributable) caller is 403
// before any signature work; the RBAC role is required.
func TestAnchorWitnessAuthz(t *testing.T) {
	signer, err := policy.GenerateSigner()
	if err != nil {
		t.Fatal(err)
	}
	cp := buildCheckpoints(t, signer, 1, 0)[0]

	// Identified peer with no roles.
	path := filepath.Join(t.TempDir(), "w.jsonl")
	_, ts := newWitnessServer(t, "PEER-KEY", map[string][]Role{"ADMIN": {RoleAdmin}}, path, []string{signer.PubKeyHex()})
	defer ts.Close()
	if code := postCP(t, ts.URL, cp); code != http.StatusForbidden {
		t.Fatalf("role-less peer should be 403, got %d", code)
	}
	if b, _ := os.ReadFile(path); len(b) != 0 {
		t.Fatal("nothing may be witnessed on a denied request")
	}

	// Unattributable caller.
	path2 := filepath.Join(t.TempDir(), "w2.jsonl")
	_, ts2 := newWitnessServer(t, "", map[string][]Role{"ADMIN": {RoleAdmin}}, path2, []string{signer.PubKeyHex()})
	defer ts2.Close()
	if code := postCP(t, ts2.URL, cp); code != http.StatusForbidden {
		t.Fatalf("unattributable caller should be 403, got %d", code)
	}

	// No witness configured: 501.
	s := &Server{}
	ts3 := httptest.NewServer(s.Handler())
	defer ts3.Close()
	if code := postCP(t, ts3.URL, cp); code != http.StatusNotImplemented {
		t.Fatalf("unconfigured witness should be 501, got %d", code)
	}
}

// TestAnchorWitnessRejectsUnpinnedAndInvalid: a signer outside the pinned
// allowlist is rejected (403) even with a valid signature; a pinned signer
// with a broken signature is 400.
func TestAnchorWitnessRejectsUnpinnedAndInvalid(t *testing.T) {
	pinned, _ := policy.GenerateSigner()
	rogue, err := policy.GenerateSigner()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "w.jsonl")
	_, ts := newWitnessServer(t, "GW-KEY", map[string][]Role{"GW-KEY": {RoleAnchorSubmit}}, path, []string{pinned.PubKeyHex()})
	defer ts.Close()

	if code := postCP(t, ts.URL, buildCheckpoints(t, rogue, 1, 0)[0]); code != http.StatusForbidden {
		t.Fatalf("unpinned signer should be rejected, got %d", code)
	}
	bad := buildCheckpoints(t, pinned, 1, 0)[0]
	bad.MerkleRoot = "tampered"
	if code := postCP(t, ts.URL, bad); code != http.StatusBadRequest {
		t.Fatalf("broken signature should be 400, got %d", code)
	}
	if b, _ := os.ReadFile(path); len(b) != 0 {
		t.Fatal("nothing may be witnessed from a rejected POST")
	}
}

// TestAnchorWitnessSeedsFromExistingFile: a restarted witness re-reads its
// file — the dedup state and self-linkage continue, so a conflicting replay of
// an ordinal witnessed BEFORE the restart is still 409, an identical replay is
// still 200, and a new record links to the pre-restart tail.
func TestAnchorWitnessSeedsFromExistingFile(t *testing.T) {
	signer, err := policy.GenerateSigner()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "w.jsonl")
	_, ts := newWitnessServer(t, "GW-KEY", map[string][]Role{"GW-KEY": {RoleAnchorSubmit}}, path, []string{signer.PubKeyHex()})
	chain := buildCheckpoints(t, signer, 2, 0)
	cp1 := chain[0]
	if code := postCP(t, ts.URL, cp1); code != http.StatusOK {
		t.Fatal("seed POST failed")
	}
	ts.Close()

	// Restart the witness on the same file.
	_, ts2 := newWitnessServer(t, "GW-KEY", map[string][]Role{"GW-KEY": {RoleAnchorSubmit}}, path, []string{signer.PubKeyHex()})
	defer ts2.Close()
	if code := postCP(t, ts2.URL, cp1); code != http.StatusOK {
		t.Fatalf("identical replay across restart should be 200, got %d", code)
	}
	if code := postCP(t, ts2.URL, buildCheckpoints(t, signer, 1, 1)[0]); code != http.StatusConflict {
		t.Fatalf("conflict across restart should be 409, got %d", code)
	}
	if code := postCP(t, ts2.URL, chain[1]); code != http.StatusOK {
		t.Fatalf("checkpoint 2 after restart should be 200, got %d", code)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	recs, _, err := policy.ReadAnchorRecords(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 {
		t.Fatalf("replays must not duplicate records: %+v", recs)
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if recs[1].PrevAnchor != policy.AnchorLineHash([]byte(lines[0])) {
		t.Fatal("post-restart record must link to the pre-restart line")
	}
}

// TestAnchorWitnessRequiresPinnedSigners: an empty signer allowlist is a
// configuration error — fail closed, never an accept-anything witness.
func TestAnchorWitnessRequiresPinnedSigners(t *testing.T) {
	if _, err := NewAnchorWitness(filepath.Join(t.TempDir(), "w.jsonl"), nil); err == nil {
		t.Fatal("witness with no pinned signers must be refused")
	}
}
