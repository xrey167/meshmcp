package main

import (
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xrey167/meshmcp/policy"
)

// TestHTTPEnforcerRequestBoundApprovals proves HTTP-backend parity for
// request-bound approvals (the follow-up flagged in the gap-10 correction):
// with approval_signing_key configured, a require_cosign call over HTTP is
// released ONLY by a signed, single-use approval bound to the exact arguments
// — an ambient (peer, tool) co-sign grant no longer releases it, changed
// arguments don't match, and a consumed approval doesn't work twice. This is
// the same contract the stdio filter enforces via backendFactory.
func TestHTTPEnforcerRequestBoundApprovals(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "approval.key")
	signer, err := policy.GenerateSigner()
	if err != nil {
		t.Fatal(err)
	}
	if err := signer.SaveSigner(keyPath); err != nil {
		t.Fatal(err)
	}
	cosignDir := filepath.Join(dir, "cosign")

	b := &Backend{
		Name: "payments",
		Policy: &policy.Policy{Rules: []policy.Rule{{
			Peers: []string{"*"}, Tools: []string{"transfer"}, Allow: true, RequireCosign: true,
		}}},
		CosignStore:        cosignDir,
		ApprovalSigningKey: keyPath,
	}
	enf, err := newHTTPEnforcer(b, policy.NewAuditLog(io.Discard, func() string { return "T" }))
	if err != nil {
		t.Fatalf("newHTTPEnforcer: %v", err)
	}

	decide := func(body string) (bool, string) {
		req, err := http.NewRequest(http.MethodPost, "http://x/mcp", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		ok, _, denial := enf.decide("agent.mesh", "peer-key", req)
		return ok, string(denial)
	}
	callBody := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"transfer","arguments":{"amount":10}}}`

	// 1) Held without any approval.
	if ok, denial := decide(callBody); ok || !strings.Contains(denial, "co-sign") {
		t.Fatalf("unapproved call: ok=%v denial=%q, want held for co-sign", ok, denial)
	}

	// 2) An ambient (peer, tool) grant must NOT release it — that is exactly the
	// downgrade approval_signing_key exists to prevent.
	if err := policy.Grant(cosignDir, "agent.mesh", "transfer", "approver", time.Now()); err != nil {
		t.Fatal(err)
	}
	if ok, _ := decide(callBody); ok {
		t.Fatal("ambient (peer, tool) grant released a request-bound call over HTTP")
	}

	// 3) A signed approval bound to the EXACT arguments releases exactly one call.
	store := policy.NewFileApprovalStore(cosignDir, time.Minute, signer)
	req := policy.NewApprovalRequest("peer-key", "payments", "transfer", []byte(`{"amount":10}`), "")
	if _, err := store.Grant(req, "approver", enf.eng.PolicyHash(), time.Now()); err != nil {
		t.Fatal(err)
	}
	// Different arguments: the approval must not match.
	otherBody := `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"transfer","arguments":{"amount":10000}}}`
	if ok, _ := decide(otherBody); ok {
		t.Fatal("approval for amount=10 released amount=10000 over HTTP")
	}
	// Exact arguments: released.
	if ok, denial := decide(callBody); !ok {
		t.Fatalf("exact approved call still held: %q", denial)
	}
	// Single-use: the same call is held again.
	if ok, _ := decide(callBody); ok {
		t.Fatal("consumed approval released a second call")
	}
}

// TestNewHTTPEnforcerFailsClosedOnBadKey proves a configured-but-unreadable
// approval signing key is a hard startup error for an HTTP backend — never a
// silent fall-back to the weaker ambient co-sign path.
func TestNewHTTPEnforcerFailsClosedOnBadKey(t *testing.T) {
	b := &Backend{
		Name:               "payments",
		Policy:             &policy.Policy{DefaultAllow: false},
		CosignStore:        t.TempDir(),
		ApprovalSigningKey: filepath.Join(t.TempDir(), "does-not-exist.key"),
	}
	if _, err := newHTTPEnforcer(b, policy.NewAuditLog(io.Discard, func() string { return "T" })); err == nil {
		t.Fatal("expected a hard error for an unloadable approval signing key")
	}
}
