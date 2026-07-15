package policy

import (
	"bufio"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// TestFilterTaintBlocksPrivilegedTool drives the taint guard through the real
// filter: a fetch (untrusted source) taints the session, after which a
// write_file (privileged) is blocked at the network layer — the backend never
// sees it. This is prompt-injection defense that no jailbreak can talk past.
func TestFilterTaintBlocksPrivilegedTool(t *testing.T) {
	backend := newEchoBackend()
	pol := &Policy{
		DefaultAllow: false,
		Rules: []Rule{
			{Peers: []string{"*"}, Tools: []string{"fetch"}, Allow: true, TaintSource: true},
			{Peers: []string{"*"}, Tools: []string{"write_file"}, Allow: true, TaintGuard: true},
		},
	}
	eng := NewEngine(pol, nil, nil)
	f := NewFilterEngine(backend, Caller{Backend: "fs", Peer: "agent.mesh"}, eng, NewAuditLog(nil, nil), nil)

	replies := make(chan string, 8)
	go func() {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			replies <- sc.Text()
		}
		close(replies)
	}()
	write := func(s string) {
		if _, err := f.Write([]byte(s + "\n")); err != nil {
			t.Fatalf("write: %v", err)
		}
	}

	// 1) write_file BEFORE any taint: allowed (backend echoes it).
	write(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"write_file","arguments":{}}}`)
	// 2) fetch: allowed, taints the session.
	write(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"fetch","arguments":{}}}`)
	// 3) write_file AFTER taint: must be blocked before reaching the backend.
	write(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"write_file","arguments":{}}}`)

	got := map[string]string{}
	timeout := time.After(5 * time.Second)
	for len(got) < 3 {
		select {
		case line := <-replies:
			var r struct {
				ID json.Number `json:"id"`
			}
			_ = json.Unmarshal([]byte(line), &r)
			got[r.ID.String()] = line
		case <-timeout:
			t.Fatalf("timed out; got %v", got)
		}
	}

	if !strings.Contains(got["1"], `"tool":"write_file"`) {
		t.Fatalf("pre-taint write_file should reach backend, got %q", got["1"])
	}
	if !strings.Contains(got["2"], `"tool":"fetch"`) {
		t.Fatalf("fetch should reach backend, got %q", got["2"])
	}
	if !strings.Contains(got["3"], "tainted") {
		t.Fatalf("post-taint write_file should be blocked with a taint reason, got %q", got["3"])
	}

	// The backend must have received write_file exactly once (the pre-taint one).
	if n := strings.Count(strings.Join(backend.got, "\n"), "write_file"); n != 1 {
		t.Fatalf("backend should see write_file once, saw %d: %v", n, backend.got)
	}
}

func TestFileCosignGrantRevoke(t *testing.T) {
	dir := t.TempDir()
	store := &FileCosign{Dir: dir}
	key := CosignKey("agent.mesh", "transfer_funds")

	if store.Approved(key) {
		t.Fatal("should not be approved before granting")
	}
	if err := Grant(dir, "agent.mesh", "transfer_funds", "alice", time.Now()); err != nil {
		t.Fatal(err)
	}
	if !store.Approved(key) {
		t.Fatal("should be approved after granting")
	}
	if err := Revoke(dir, "agent.mesh", "transfer_funds"); err != nil {
		t.Fatal(err)
	}
	if store.Approved(key) {
		t.Fatal("should not be approved after revoke")
	}
}

func TestFileCosignTTL(t *testing.T) {
	dir := t.TempDir()
	store := &FileCosign{Dir: dir, TTL: time.Hour}
	// Grant an approval stamped two hours ago → already expired.
	if err := Grant(dir, "agent.mesh", "deploy", "alice", time.Now().Add(-2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if store.Approved(CosignKey("agent.mesh", "deploy")) {
		t.Fatal("an approval older than the TTL should not count")
	}
}
