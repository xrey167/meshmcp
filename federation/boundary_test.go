package federation

import (
	"bytes"
	"strings"
	"testing"

	"meshmcp/policy"
)

func testBoundary(audit *policy.AuditLog) *Boundary {
	return NewBoundary(
		[]Grant{
			{Org: "acme", Tools: []string{"read_*", "search"}, Corpora: []string{"public", "shared-*"}},
			{Org: "globex", Tools: []string{}}, // known org, but no tools granted
		},
		[]Mapping{
			{Match: "pubkey:ACMEKEY", Org: "acme", Principal: "partner:acme"},
			{Match: "*.globex.netbird.cloud", Org: "globex"},
		},
		audit,
	)
}

func TestOrgIdentityMapping(t *testing.T) {
	b := testBoundary(nil)
	if org := b.OrgFor("host.acme.net", "ACMEKEY"); org != "acme" {
		t.Fatalf("pubkey should map to acme, got %q", org)
	}
	if org := b.OrgFor("gw.globex.netbird.cloud", "OTHER"); org != "globex" {
		t.Fatalf("fqdn glob should map to globex, got %q", org)
	}
	if org := b.OrgFor("stranger.net", "NOPE"); org != "" {
		t.Fatalf("unknown peer should map to no org, got %q", org)
	}
	if p := b.Principal("acme"); p != "partner:acme" {
		t.Fatalf("acme principal wrong: %q", p)
	}
	if p := b.Principal("globex"); p != "globex" {
		t.Fatalf("globex principal should fall back to org id, got %q", p)
	}
}

func TestCrossOrgCorpusGrant(t *testing.T) {
	var buf bytes.Buffer
	audit := policy.NewAuditLog(&buf, func() string { return "T" })
	b := testBoundary(audit)

	// acme granted "public" and "shared-*" corpora.
	if ok, _ := b.CheckCorpus("acme", "public"); !ok {
		t.Fatal("acme should query the public corpus")
	}
	if ok, _ := b.CheckCorpus("acme", "shared-legal"); !ok {
		t.Fatal("acme should query a shared-* subgraph")
	}
	// An ungranted corpus is blocked.
	if ok, reason := b.CheckCorpus("acme", "private"); ok || !strings.Contains(reason, "not granted") {
		t.Fatalf("acme private corpus should be blocked, got ok=%v reason=%q", ok, reason)
	}
	// globex has no corpus grant at all → blocked.
	if ok, _ := b.CheckCorpus("globex", "public"); ok {
		t.Fatal("globex has no corpus grant; must be blocked")
	}
	// Every corpus crossing is audited on the boundary.
	if n := strings.Count(buf.String(), `"method":"federation/corpus/query"`); n != 4 {
		t.Fatalf("expected 4 audited corpus crossings, got %d", n)
	}
}

func TestBoundaryAuthorizesByGrant(t *testing.T) {
	var buf bytes.Buffer
	audit := policy.NewAuditLog(&buf, func() string { return "T" })
	b := testBoundary(audit)

	// acme granted read_* → read_file crosses.
	if ok, _ := b.Check("acme", "read_file"); !ok {
		t.Fatal("acme read_file should be allowed")
	}
	// acme not granted delete_all → blocked.
	if ok, reason := b.Check("acme", "delete_all"); ok || !strings.Contains(reason, "not granted") {
		t.Fatalf("acme delete_all should be blocked, got ok=%v reason=%q", ok, reason)
	}
	// globex has a grant entry but no tools → blocked.
	if ok, _ := b.Check("globex", "read_file"); ok {
		t.Fatal("globex read_file should be blocked (no tools granted)")
	}
	// unknown org → blocked.
	if ok, reason := b.Check("", "read_file"); ok || !strings.Contains(reason, "unrecognized org") {
		t.Fatalf("empty org should be blocked, got ok=%v reason=%q", ok, reason)
	}

	// Every crossing (allow and deny) must be in the tamper-evident audit trail.
	as := buf.String()
	if n := strings.Count(as, `"method":"federation/tools/call"`); n != 4 {
		t.Fatalf("expected 4 audited crossings, got %d:\n%s", n, as)
	}
	if res, _ := policy.VerifyChain(strings.NewReader(as)); !res.OK {
		t.Fatalf("federation audit chain should verify: %+v", res)
	}
}
