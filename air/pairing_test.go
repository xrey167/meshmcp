package air

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func pairTestNow() time.Time { return time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC) }

func newTestStore(t *testing.T) (*PairedStore, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "paired.json")
	s, err := OpenPairedStore(path)
	if err != nil {
		t.Fatalf("OpenPairedStore: %v", err)
	}
	return s, path
}

// TestRequestQueuesButGrantsNothing proves a pending request records the
// verified identity yet confers no recognition.
func TestRequestQueuesButGrantsNothing(t *testing.T) {
	s, _ := newTestStore(t)
	id := VerifiedIdentity{PublicKey: "peer-key", FQDN: "peer.mesh"}

	req, added, err := s.Request(id, "laptop", pairTestNow())
	if err != nil || !added {
		t.Fatalf("Request added=%v err=%v", added, err)
	}
	if req.PublicKey != "peer-key" || req.FQDN != "peer.mesh" || req.Label != "laptop" {
		t.Fatalf("pending recorded wrong identity: %+v", req)
	}
	// Grants nothing: the peer is not recognized just for asking.
	if s.Recognized("peer-key", "peer.mesh") {
		t.Fatalf("a pending request must NOT confer recognition")
	}
	if s.Status("peer-key") != StatusPending {
		t.Fatalf("status = %q, want pending", s.Status("peer-key"))
	}
	// A re-request is idempotent (no duplicate, added=false).
	if _, added2, _ := s.Request(id, "laptop", pairTestNow()); added2 {
		t.Fatalf("re-request should be idempotent (added=false)")
	}
	if got := s.Pending(); len(got) != 1 {
		t.Fatalf("want 1 pending, got %d", len(got))
	}
}

// TestApproveRecognizesDenyDropsRevokeRemoves walks the full lifecycle.
func TestApproveRecognizesDenyDropsRevokeRemoves(t *testing.T) {
	s, _ := newTestStore(t)
	id := VerifiedIdentity{PublicKey: "k1", FQDN: "one.mesh"}
	if _, _, err := s.Request(id, "", pairTestNow()); err != nil {
		t.Fatalf("Request: %v", err)
	}

	peer, err := s.Approve("k1", "operator.mesh", pairTestNow())
	if err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if peer.Approver != "operator.mesh" || peer.PublicKey != "k1" {
		t.Fatalf("approved peer wrong: %+v", peer)
	}
	if !s.Recognized("k1", "one.mesh") {
		t.Fatalf("approved peer must be recognized")
	}
	if len(s.Pending()) != 0 {
		t.Fatalf("approve should drain the pending set")
	}

	// Revoke removes recognition.
	removed, err := s.Revoke("k1")
	if err != nil || !removed {
		t.Fatalf("Revoke removed=%v err=%v", removed, err)
	}
	if s.Recognized("k1", "one.mesh") {
		t.Fatalf("revoked peer must no longer be recognized")
	}

	// Deny drops a pending request without recognizing it.
	if _, _, err := s.Request(VerifiedIdentity{PublicKey: "k2", FQDN: "two.mesh"}, "", pairTestNow()); err != nil {
		t.Fatalf("Request k2: %v", err)
	}
	denied, err := s.Deny("k2")
	if err != nil || !denied {
		t.Fatalf("Deny removed=%v err=%v", denied, err)
	}
	if s.Recognized("k2", "two.mesh") || s.Status("k2") != StatusNone {
		t.Fatalf("denied peer must be neither recognized nor pending")
	}
}

// TestApproveWithoutPendingFails proves the operator cannot recognize a peer
// nobody asked for.
func TestApproveWithoutPendingFails(t *testing.T) {
	s, _ := newTestStore(t)
	if _, err := s.Approve("ghost", "op", pairTestNow()); !errors.Is(err, ErrNoPendingRequest) {
		t.Fatalf("approve without pending = %v, want ErrNoPendingRequest", err)
	}
}

// TestPersistenceSurvivesReopen proves the store is durable across a restart:
// an approved peer is still recognized and a pending request still queued after
// reopening the same file.
func TestPersistenceSurvivesReopen(t *testing.T) {
	s, path := newTestStore(t)
	if _, _, err := s.Request(VerifiedIdentity{PublicKey: "approved", FQDN: "a.mesh"}, "lbl", pairTestNow()); err != nil {
		t.Fatalf("Request: %v", err)
	}
	if _, err := s.Approve("approved", "op.mesh", pairTestNow()); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if _, _, err := s.Request(VerifiedIdentity{PublicKey: "waiting", FQDN: "w.mesh"}, "", pairTestNow()); err != nil {
		t.Fatalf("Request waiting: %v", err)
	}

	reopened, err := OpenPairedStore(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if !reopened.Recognized("approved", "a.mesh") {
		t.Fatalf("approved peer not durable across reopen")
	}
	if reopened.Status("waiting") != StatusPending {
		t.Fatalf("pending request not durable across reopen")
	}
	// Revoke on the reopened store persists too.
	if _, err := reopened.Revoke("approved"); err != nil {
		t.Fatalf("Revoke on reopen: %v", err)
	}
	final, err := OpenPairedStore(path)
	if err != nil {
		t.Fatalf("second reopen: %v", err)
	}
	if final.Recognized("approved", "a.mesh") {
		t.Fatalf("revocation not durable across reopen")
	}
}

// TestRecognizedFailsClosed proves an empty key is never recognized and the
// match is on the unforgeable key, not the advisory FQDN.
func TestRecognizedFailsClosed(t *testing.T) {
	s, _ := newTestStore(t)
	if _, _, err := s.Request(VerifiedIdentity{PublicKey: "realkey", FQDN: "real.mesh"}, "", pairTestNow()); err != nil {
		t.Fatalf("Request: %v", err)
	}
	if _, err := s.Approve("realkey", "op", pairTestNow()); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if s.Recognized("", "real.mesh") {
		t.Fatalf("empty key must fail closed")
	}
	if s.Recognized("otherkey", "real.mesh") {
		t.Fatalf("a matching FQDN with a different key must NOT be recognized")
	}
}

// TestRequestValidation rejects an unusable or hostile identity/label.
func TestRequestValidation(t *testing.T) {
	s, _ := newTestStore(t)
	cases := []struct {
		name  string
		id    VerifiedIdentity
		label string
	}{
		{"empty key", VerifiedIdentity{FQDN: "x.mesh"}, ""},
		{"control in key", VerifiedIdentity{PublicKey: "k\ney"}, ""},
		{"control in label", VerifiedIdentity{PublicKey: "k"}, "bad\x1blabel"},
		{"long label", VerifiedIdentity{PublicKey: "k"}, strings.Repeat("x", maxPairLabelBytes+1)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, _, err := s.Request(c.id, c.label, pairTestNow()); err == nil {
				t.Fatalf("expected rejection for %s", c.name)
			}
		})
	}
}

// TestPendingBound proves the pending set cannot grow without limit (an
// un-allowed peer population cannot exhaust the store).
func TestPendingBound(t *testing.T) {
	s, _ := newTestStore(t)
	for i := 0; i < DefaultPendingMax; i++ {
		id := VerifiedIdentity{PublicKey: "key-" + strings.Repeat("a", i%3) + itoa(i)}
		if _, _, err := s.Request(id, "", pairTestNow()); err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
	}
	if _, _, err := s.Request(VerifiedIdentity{PublicKey: "one-too-many"}, "", pairTestNow()); err == nil {
		t.Fatalf("expected the pending set to be bounded at %d", DefaultPendingMax)
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}
