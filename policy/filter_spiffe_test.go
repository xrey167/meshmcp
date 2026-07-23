package policy

import (
	"bufio"
	"bytes"
	"strings"
	"testing"
	"time"
)

// These tests prove Feature A end to end at the local-gateway choke point:
// Filter.record stamps Caller.SpiffeID onto every audit record, the resulting
// chain verifies, and an unset label (no trust_domain configured) leaves the
// audit bytes — and therefore every Hash/PrevHash — identical to a build that
// never heard of the field.

// driveOneCall runs a single allowed tools/call through a filter built with
// the given caller, auditing into the returned buffer.
func driveOneCall(t *testing.T, caller Caller) string {
	t.Helper()
	backend := newEchoBackend()
	pol := &Policy{DefaultAllow: true}
	eng := NewEngine(pol, nil, nil)
	var buf bytes.Buffer
	audit := NewAuditLog(&buf, func() string { return "T" })
	f := NewFilterEngine(backend, caller, eng, audit, nil)

	replies := make(chan string, 1)
	go func() {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			replies <- sc.Text()
			return
		}
	}()
	if _, err := f.Write([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{}}}` + "\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	select {
	case <-replies:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for backend reply")
	}
	return buf.String()
}

// TestFilter_EmitsPeerSpiffeIDWhenCallerLabeled proves the local gateway path
// actually emits: a caller carrying a derived SPIFFE label produces an audit
// record WITH peer_spiffe_id, and the chain containing it verifies.
func TestFilter_EmitsPeerSpiffeIDWhenCallerLabeled(t *testing.T) {
	label := SpiffeID("mesh.example.org", netbirdShapedKey)
	if label == "" {
		t.Fatal("fixture should derive a non-empty label")
	}
	out := driveOneCall(t, Caller{
		Backend: "fs", Peer: "agent.mesh", PeerKey: netbirdShapedKey,
		SpiffeID: label,
	})
	if !strings.Contains(out, `"peer_spiffe_id":"`+string(label)+`"`) {
		t.Fatalf("audit record should carry peer_spiffe_id %q, got: %s", label, out)
	}
	res, err := VerifyChain(strings.NewReader(out))
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !res.OK {
		t.Fatalf("chain with a labeled record did not verify: %s", res.Reason)
	}
}

// TestFilter_NoTrustDomainLeavesRecordsByteIdentical proves the off switch: a
// deployment with no trust_domain (SpiffeID("", key) == "") writes audit
// bytes — including every Hash and PrevHash — identical to a caller that
// never set the field, so existing chains and verifiers are untouched.
func TestFilter_NoTrustDomainLeavesRecordsByteIdentical(t *testing.T) {
	base := Caller{Backend: "fs", Peer: "agent.mesh", PeerKey: netbirdShapedKey}
	withEmptyDerivation := base
	withEmptyDerivation.SpiffeID = SpiffeID("", netbirdShapedKey) // trust_domain unset

	out1 := driveOneCall(t, base)
	out2 := driveOneCall(t, withEmptyDerivation)
	if out1 != out2 {
		t.Fatalf("empty trust domain must not perturb audit bytes:\n%s\nvs\n%s", out1, out2)
	}
	if strings.Contains(out1, "peer_spiffe_id") {
		t.Fatalf("no label configured, yet peer_spiffe_id appears: %s", out1)
	}
	res, err := VerifyChain(strings.NewReader(out1))
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !res.OK {
		t.Fatalf("unlabeled chain did not verify: %s", res.Reason)
	}
}
