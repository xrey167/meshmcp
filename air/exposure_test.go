package air

import (
	"strings"
	"testing"
)

// findingByRule returns the first finding with the given rule id, or false.
func findingByRule(fs []Finding, rule string) (Finding, bool) {
	for _, f := range fs {
		if f.Rule == rule {
			return f, true
		}
	}
	return Finding{}, false
}

func hasRule(fs []Finding, rule string) bool {
	_, ok := findingByRule(fs, rule)
	return ok
}

func TestAnalyze_SecretsNoCosign_IsCritical(t *testing.T) {
	m := MeshExposure{Backends: []BackendExposure{{
		Name: "payments", Transport: "stdio", Allow: []string{"pubkey:AAA"}, Audited: true,
		PolicyGated: true, DefaultAllow: false,
		SecretGrants: []SecretGrantExposure{{Secrets: []string{"STRIPE_KEY"}, Peers: []string{"pubkey:AAA"}, Cosigned: false}},
	}}}
	f := Analyze(m)
	got, ok := findingByRule(f, "secrets-no-cosign")
	if !ok {
		t.Fatalf("expected secrets-no-cosign finding, got %+v", f)
	}
	if got.Severity != SevCritical {
		t.Errorf("severity = %q, want critical", got.Severity)
	}
}

func TestAnalyze_SecretsCosigned_NotFlagged(t *testing.T) {
	m := MeshExposure{Backends: []BackendExposure{{
		Name: "payments", Transport: "stdio", Allow: []string{"pubkey:AAA"}, Audited: true,
		PolicyGated:  true,
		SecretGrants: []SecretGrantExposure{{Secrets: []string{"STRIPE_KEY"}, Peers: []string{"pubkey:AAA"}, Cosigned: true}},
	}}}
	if hasRule(Analyze(m), "secrets-no-cosign") {
		t.Error("cosigned secret grant should not be flagged secrets-no-cosign")
	}
}

func TestAnalyze_WildcardAllowFlagged_EmptyAndStar(t *testing.T) {
	empty := MeshExposure{Backends: []BackendExposure{{Name: "a", Transport: "stdio", Allow: nil, Audited: true, PolicyGated: true}}}
	if !hasRule(Analyze(empty), "wildcard-allow") {
		t.Error("empty allow should be flagged wildcard-allow")
	}
	star := MeshExposure{Backends: []BackendExposure{{Name: "b", Transport: "stdio", Allow: []string{"*"}, Audited: true, PolicyGated: true}}}
	if !hasRule(Analyze(star), "wildcard-allow") {
		t.Error("star allow should be flagged wildcard-allow")
	}
}

func TestAnalyze_UnauditedBackend_HighWhenNoLedger(t *testing.T) {
	m := MeshExposure{Backends: []BackendExposure{{Name: "scratch", Transport: "stdio", Allow: []string{"pubkey:X"}, Audited: false, PolicyGated: true}}}
	got, ok := findingByRule(Analyze(m), "unaudited-backend")
	if !ok || got.Severity != SevHigh {
		t.Errorf("expected high unaudited-backend, got %+v ok=%v", got, ok)
	}
}

func TestAnalyze_DefaultAllowPolicy_Flagged(t *testing.T) {
	m := MeshExposure{Backends: []BackendExposure{{Name: "n", Transport: "stdio", Allow: []string{"pubkey:X"}, Audited: true, DefaultAllow: true}}}
	if !hasRule(Analyze(m), "default-allow") {
		t.Error("default-allow policy should be flagged")
	}
}

func TestAnalyze_RemoteEgress_NamesEndpoint(t *testing.T) {
	m := MeshExposure{Backends: []BackendExposure{{
		Name: "gh", Transport: "remote", Allow: []string{"pubkey:X"}, Audited: true, PolicyGated: true,
		RemoteEndpoint: "https://api.github.com",
	}}}
	got, ok := findingByRule(Analyze(m), "remote-egress")
	if !ok {
		t.Fatal("expected remote-egress finding")
	}
	if got.Severity != SevMedium || len(got.Evidence) != 1 || got.Evidence[0] != "https://api.github.com" {
		t.Errorf("remote-egress = %+v, want medium naming the endpoint", got)
	}
}

func TestAnalyze_GroupInAcl_Flagged(t *testing.T) {
	// A group: token in a backend allow is inert at the ACL layer — flagged, not
	// silently expanded (honest ACL model).
	m := MeshExposure{Backends: []BackendExposure{{Name: "n", Transport: "stdio", Allow: []string{"group:oncall"}, Audited: true, PolicyGated: true}}}
	if !hasRule(Analyze(m), "group-in-acl") {
		t.Error("group: token in a backend allow should be flagged group-in-acl")
	}
	// It must NOT be treated as a wildcard or reach anything.
	if hasRule(Analyze(m), "wildcard-allow") {
		t.Error("group: token is not a wildcard")
	}
}

func TestAnalyze_ControlWildcard_Critical(t *testing.T) {
	m := MeshExposure{Control: ControlExposure{Enabled: true, Allow: []string{"**"}}, Backends: []BackendExposure{{Name: "n", Transport: "stdio", Allow: []string{"pubkey:X"}, Audited: true, PolicyGated: true}}}
	got, ok := findingByRule(Analyze(m), "control-wildcard")
	if !ok || got.Severity != SevCritical {
		t.Errorf("expected critical control-wildcard, got %+v ok=%v", got, ok)
	}
}

func TestAnalyze_CleanSurface_NoFindings_GradeA(t *testing.T) {
	m := MeshExposure{
		Gateway: "gw", Control: ControlExposure{Enabled: true, Allow: []string{"pubkey:OP"}},
		Backends: []BackendExposure{{
			Name: "maps", Transport: "stdio", Allow: []string{"pubkey:X"}, Audited: true, PolicyGated: true, DefaultAllow: false,
		}},
	}
	f := Analyze(m)
	if len(f) != 0 {
		t.Fatalf("clean surface should have no findings, got %+v", f)
	}
	if s := ScoreFindings(f); s.Grade != "A" {
		t.Errorf("grade = %q, want A", s.Grade)
	}
}

func TestReachabilityFor_PubkeyExactMatch(t *testing.T) {
	m := MeshExposure{Backends: []BackendExposure{
		{Name: "a", Allow: []string{"pubkey:AAA"}},
		{Name: "b", Allow: []string{"pubkey:BBB"}},
	}}
	r := ReachabilityFor(m, "pubkey:AAA")
	if len(r.Backends) != 1 || r.Backends[0] != "a" {
		t.Errorf("reach = %v, want [a]", r.Backends)
	}
}

func TestReachabilityFor_FQDNGlob(t *testing.T) {
	m := MeshExposure{Backends: []BackendExposure{
		{Name: "a", Allow: []string{"laptop-*.netbird.cloud"}},
		{Name: "b", Allow: []string{"server-*.netbird.cloud"}},
	}}
	r := ReachabilityFor(m, "laptop-3.netbird.cloud")
	if len(r.Backends) != 1 || r.Backends[0] != "a" {
		t.Errorf("reach = %v, want [a]", r.Backends)
	}
}

func TestReachabilityFor_UnlistedIdentity_ReachesNothing(t *testing.T) {
	m := MeshExposure{Backends: []BackendExposure{{Name: "a", Allow: []string{"pubkey:AAA"}}}}
	r := ReachabilityFor(m, "pubkey:ZZZ")
	if len(r.Backends) != 0 {
		t.Errorf("unlisted identity reach = %v, want none", r.Backends)
	}
}

func TestReachabilityFor_EmptyIdentity_DeniedEverywhere(t *testing.T) {
	// Fail-closed parity with acl.allows: an unattributable caller is denied even
	// on an open (empty-allow) backend.
	m := MeshExposure{Backends: []BackendExposure{{Name: "open", Allow: nil}}}
	r := ReachabilityFor(m, "")
	if len(r.Backends) != 0 {
		t.Errorf("empty identity reach = %v, want none (fail closed)", r.Backends)
	}
}

func TestReachabilityFor_ViaWildcard_TrackedSeparately(t *testing.T) {
	m := MeshExposure{Backends: []BackendExposure{
		{Name: "open", Allow: nil}, // any peer
		{Name: "scoped", Allow: []string{"pubkey:X"}},
	}}
	r := ReachabilityFor(m, "pubkey:X")
	if len(r.Backends) != 2 {
		t.Fatalf("reach = %v, want both", r.Backends)
	}
	if len(r.ViaWildcard) != 1 || r.ViaWildcard[0] != "open" {
		t.Errorf("via_wildcard = %v, want [open]", r.ViaWildcard)
	}
}

// The mandated secret-projection test: exposure keys off Grants[].Peers, NOT
// Backend.Allow. The backend is wide open (any peer reaches it) but the grant is
// scoped to one identity, so only that identity can command the secret.
func TestReachabilityFor_SecretKeysOffGrantPeers_NotAllow(t *testing.T) {
	m := MeshExposure{Backends: []BackendExposure{{
		Name: "payments", Transport: "stdio", Allow: []string{"*"}, // Allow admits everyone
		SecretGrants: []SecretGrantExposure{{Secrets: []string{"STRIPE_KEY"}, Peers: []string{"pubkey:ADMIN"}, Cosigned: true}},
	}}}

	admin := ReachabilityFor(m, "pubkey:ADMIN")
	if len(admin.Secrets) != 1 || admin.Secrets[0] != "STRIPE_KEY" {
		t.Errorf("admin secrets = %v, want [STRIPE_KEY]", admin.Secrets)
	}

	laptop := ReachabilityFor(m, "laptop-3.netbird.cloud")
	if len(laptop.Backends) != 1 {
		t.Fatalf("laptop should reach the backend via wildcard, got %v", laptop.Backends)
	}
	if len(laptop.Secrets) != 0 {
		t.Errorf("laptop secrets = %v, want none — grant peers exclude it (keyed off grant, not allow)", laptop.Secrets)
	}
}

func TestScoreFindings_GradeThresholds(t *testing.T) {
	cases := []struct {
		f    []Finding
		want string
	}{
		{nil, "A"},
		{[]Finding{{Severity: SevLow}}, "B"},
		{[]Finding{{Severity: SevMedium}}, "C"},
		{[]Finding{{Severity: SevHigh}}, "D"},
		{[]Finding{{Severity: SevCritical}}, "F"},
		{[]Finding{{Severity: SevLow}, {Severity: SevCritical}}, "F"},
	}
	for i, c := range cases {
		if g := ScoreFindings(c.f).Grade; g != c.want {
			t.Errorf("case %d: grade = %q, want %q", i, g, c.want)
		}
	}
}

func TestBuildReport_DeterministicWithInjectedClock(t *testing.T) {
	m := MeshExposure{Gateway: "gw", Backends: []BackendExposure{{Name: "a", Allow: []string{"pubkey:X"}, Audited: true, PolicyGated: true}}}
	clock := func() string { return "2026-07-22T00:00:00Z" }
	r1 := BuildReport(m, clock)
	r2 := BuildReport(m, clock)
	if r1.Generated != "2026-07-22T00:00:00Z" {
		t.Errorf("generated = %q, want injected clock value", r1.Generated)
	}
	if r1.Kind != ExposureKind || r1.Version != ExposureVersion {
		t.Errorf("report kind/version = %q/%d", r1.Kind, r1.Version)
	}
	if r1.Score.Grade != r2.Score.Grade || len(r1.Findings) != len(r2.Findings) {
		t.Error("BuildReport is not deterministic for identical input")
	}
}

func TestIdentityMatches_ParityWithACLSemantics(t *testing.T) {
	// Mirrors the acl.allows contract: pubkey exact, FQDN glob, no group expansion.
	cases := []struct {
		pattern, pubkey, fqdn string
		want                  bool
	}{
		{"pubkey:AAA", "AAA", "", true},
		{"pubkey:AAA", "BBB", "", false},
		{"laptop-*.netbird.cloud", "", "laptop-3.netbird.cloud", true},
		{"laptop-*.netbird.cloud", "", "server-1.netbird.cloud", false},
		{"group:oncall", "", "laptop-3.netbird.cloud", false}, // no group expansion at ACL layer
	}
	for i, c := range cases {
		if got := identityMatches(c.pattern, c.pubkey, c.fqdn); got != c.want {
			t.Errorf("case %d: identityMatches(%q,%q,%q) = %v, want %v", i, c.pattern, c.pubkey, c.fqdn, got, c.want)
		}
	}
}

func TestAllReach_SkipsWildcardAndGroupSubjects(t *testing.T) {
	m := MeshExposure{Backends: []BackendExposure{
		{Name: "a", Allow: []string{"pubkey:AAA", "*", "group:oncall"}},
	}}
	rs := AllReach(m)
	for _, r := range rs {
		if isWildcard(r.Identity) || strings.HasPrefix(r.Identity, "group:") {
			t.Errorf("AllReach produced a non-identity subject %q", r.Identity)
		}
	}
	if len(rs) != 1 || rs[0].Identity != "pubkey:AAA" {
		t.Errorf("subjects = %+v, want only pubkey:AAA", rs)
	}
}
