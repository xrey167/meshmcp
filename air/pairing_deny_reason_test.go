package air

import (
	"testing"
	"time"
)

func denyTestID(k string) VerifiedIdentity {
	return VerifiedIdentity{PublicKey: k, FQDN: k + ".mesh"}
}

// TestDenyRecordsReasonAndStatusDetail proves the guided-recovery contract: a
// declined requester polling its own status sees "denied" WITH the operator's
// reason, instead of silently vanishing to "none".
func TestDenyRecordsReasonAndStatusDetail(t *testing.T) {
	s, err := OpenPairedStore(t.TempDir() + "/paired.json")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0)
	if _, _, err := s.Request(denyTestID("k1"), "laptop", now); err != nil {
		t.Fatal(err)
	}
	removed, err := s.Deny("k1", "unknown device — ask in #ops", now)
	if err != nil || !removed {
		t.Fatalf("deny: removed=%v err=%v", removed, err)
	}
	st, reason := s.StatusDetail("k1")
	if st != StatusDenied || reason != "unknown device — ask in #ops" {
		t.Fatalf("status=%q reason=%q, want denied with the reason", st, reason)
	}
	// Status (the compat form) reports denied too.
	if s.Status("k1") != StatusDenied {
		t.Fatalf("Status = %q, want denied", s.Status("k1"))
	}

	// Denying an identity with no pending request records nothing.
	if removed, err := s.Deny("ghost", "whatever", now); err != nil || removed {
		t.Fatalf("deny of a non-request: removed=%v err=%v", removed, err)
	}
	if st, _ := s.StatusDetail("ghost"); st != StatusNone {
		t.Fatalf("ghost status = %q, want none", st)
	}

	// A hostile reason is rejected before it can land in the store.
	if _, _, err := s.Request(denyTestID("k2"), "", now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Deny("k2", "bad\x00reason", now); err == nil {
		t.Fatal("control characters in the reason must be rejected")
	}
}

// TestDenialSurvivesReloadAndClearsOnRerequest proves the denial persists
// across a store reload (the requester may poll much later) and that a fresh
// Request clears it — a decline is advisory, never a ban.
func TestDenialSurvivesReloadAndClearsOnRerequest(t *testing.T) {
	path := t.TempDir() + "/paired.json"
	now := time.Unix(1_700_000_000, 0)

	s, err := OpenPairedStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Request(denyTestID("k1"), "", now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Deny("k1", "not now", now); err != nil {
		t.Fatal(err)
	}

	// Reload: the denial (and its reason) survives.
	s2, err := OpenPairedStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if st, reason := s2.StatusDetail("k1"); st != StatusDenied || reason != "not now" {
		t.Fatalf("after reload: status=%q reason=%q", st, reason)
	}

	// A fresh request supersedes the denial and queues again.
	if _, added, err := s2.Request(denyTestID("k1"), "", now.Add(time.Hour)); err != nil || !added {
		t.Fatalf("re-request: added=%v err=%v", added, err)
	}
	if st, _ := s2.StatusDetail("k1"); st != StatusPending {
		t.Fatalf("after re-request: status=%q, want pending", st)
	}
}
