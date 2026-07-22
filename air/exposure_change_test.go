package air

import "testing"

func reportWith(m MeshExposure) ExposureReport {
	return BuildReport(m, func() string { return "2026-07-22T00:00:00Z" })
}

func TestDiffReports_NewAndResolvedFindings(t *testing.T) {
	clean := MeshExposure{Backends: []BackendExposure{{Name: "a", Transport: "stdio", Allow: []string{"pubkey:X"}, Audited: true, PolicyGated: true}}}
	// Add a risky secret grant with no cosign — a new critical finding appears.
	risky := MeshExposure{Backends: []BackendExposure{{
		Name: "a", Transport: "stdio", Allow: []string{"pubkey:X"}, Audited: true, PolicyGated: true,
		SecretGrants: []SecretGrantExposure{{Secrets: []string{"KEY"}, Peers: []string{"pubkey:X"}, Cosigned: false}},
	}}}

	d := DiffReports(reportWith(clean), reportWith(risky))
	if !hasRule(d.NewFindings, "secrets-no-cosign") {
		t.Errorf("expected secrets-no-cosign in new findings, got %+v", d.NewFindings)
	}
	if len(d.ResolvedFindings) != 0 {
		t.Errorf("resolved = %+v, want none", d.ResolvedFindings)
	}

	// Reverse: fixing it shows the finding as resolved.
	back := DiffReports(reportWith(risky), reportWith(clean))
	if !hasRule(back.ResolvedFindings, "secrets-no-cosign") {
		t.Errorf("expected secrets-no-cosign resolved, got %+v", back.ResolvedFindings)
	}
}

func TestDiffReports_ReachGainedAndLost(t *testing.T) {
	before := MeshExposure{Backends: []BackendExposure{
		{Name: "a", Allow: []string{"pubkey:X"}},
	}}
	after := MeshExposure{Backends: []BackendExposure{
		{Name: "a", Allow: []string{"pubkey:X"}},
		{Name: "b", Allow: []string{"pubkey:X"}}, // X now reaches b too
	}}
	d := DiffReports(reportWith(before), reportWith(after))
	if len(d.ReachChanges) != 1 {
		t.Fatalf("reach changes = %+v, want 1", d.ReachChanges)
	}
	rc := d.ReachChanges[0]
	if rc.Identity != "pubkey:X" || len(rc.Gained) != 1 || rc.Gained[0] != "b" {
		t.Errorf("reach change = %+v, want pubkey:X gained [b]", rc)
	}
	if len(rc.Lost) != 0 {
		t.Errorf("lost = %v, want none", rc.Lost)
	}
}

func TestDiffReports_Empty_NoDrift(t *testing.T) {
	m := MeshExposure{Backends: []BackendExposure{{Name: "a", Allow: []string{"pubkey:X"}, Audited: true, PolicyGated: true}}}
	d := DiffReports(reportWith(m), reportWith(m))
	if !d.Empty() {
		t.Errorf("identical reports should have no drift, got %+v", d)
	}
	if s := d.Summary(); s != "no drift" {
		t.Errorf("summary = %q, want %q", s, "no drift")
	}
}

func TestExposureDelta_Summary(t *testing.T) {
	d := ExposureDelta{
		NewFindings:      []Finding{{Rule: "x"}, {Rule: "y"}},
		ResolvedFindings: []Finding{{Rule: "z"}},
		ReachChanges:     []ReachChange{{Identity: "pubkey:X"}},
	}
	if got := d.Summary(); got != "+2 findings  -1 resolved  ~1 identity" {
		t.Errorf("summary = %q", got)
	}
}
