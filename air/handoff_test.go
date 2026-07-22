package air

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func testCapsule(now time.Time) ContextCapsule {
	return ContextCapsule{
		Version:     HandoffVersion,
		ID:          "00112233445566778899aabbccddeeff",
		CreatedAt:   now,
		ExpiresAt:   now.Add(30 * time.Minute),
		TargetKey:   "target-wireguard-key",
		Work:        WorkRef{Kind: WorkTask, ID: "task-17"},
		Goal:        "Continue the ACME outage analysis",
		Summary:     "Three suppliers are affected.",
		Cursor:      json.RawMessage(`{"supplier":"ACME","step":3}`),
		Artifacts:   []BlobRef{{Name: "exposure.json", SHA256: "sha256:" + strings.Repeat("a", 64), Bytes: 128, MediaType: "application/json"}},
		MemoryRefs:  []string{"corpus:acme"},
		SecretRefs:  []string{"secret:erp-readonly"},
		Labels:      []string{"supply-risk"},
		Sensitivity: SensitivitySensitive,
	}
}

func TestHandoffSealValidateAndTargetBinding(t *testing.T) {
	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	offer, err := SealHandoff(testCapsule(now))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(offer.ContentHash, "sha256:") || len(offer.ContentHash) != len("sha256:")+64 {
		t.Fatalf("unexpected content hash %q", offer.ContentHash)
	}
	if err := offer.Validate(now.Add(time.Minute), "target-wireguard-key"); err != nil {
		t.Fatalf("valid offer rejected: %v", err)
	}
	if err := offer.Validate(now.Add(time.Minute), "different-key"); err == nil {
		t.Fatal("offer was not bound to the exact destination key")
	}

	tampered := offer
	tampered.Capsule.Goal = "do something else"
	if err := tampered.Validate(now.Add(time.Minute), "target-wireguard-key"); err == nil {
		t.Fatal("tampered capsule passed its content hash")
	}
	if err := offer.Validate(now.Add(31*time.Minute), "target-wireguard-key"); err == nil {
		t.Fatal("expired offer was accepted")
	}
}

func TestHandoffValidationRejectsUnsafeOrOversizedData(t *testing.T) {
	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name string
		mut  func(*ContextCapsule)
	}{
		{"bad id", func(c *ContextCapsule) { c.ID = "../escape" }},
		{"long ttl", func(c *ContextCapsule) { c.ExpiresAt = c.CreatedAt.Add(25 * time.Hour) }},
		{"future created", func(c *ContextCapsule) {
			c.CreatedAt = now.Add(6 * time.Minute)
			c.ExpiresAt = c.CreatedAt.Add(time.Minute)
		}},
		{"group work", func(c *ContextCapsule) { c.Work.Kind = "group" }},
		{"invalid cursor", func(c *ContextCapsule) { c.Cursor = json.RawMessage(`{`) }},
		{"artifact path", func(c *ContextCapsule) { c.Artifacts[0].Name = "../secret" }},
		{"artifact hash", func(c *ContextCapsule) { c.Artifacts[0].SHA256 = "sha256:xyz" }},
		{"control char", func(c *ContextCapsule) { c.Goal = "hello\x1bworld" }},
		{"oversized inline", func(c *ContextCapsule) {
			c.Cursor = json.RawMessage(`"` + strings.Repeat("x", HandoffMaxInlineBytes) + `"`)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := testCapsule(now)
			tc.mut(&c)
			offer, err := SealHandoff(c)
			if err == nil {
				err = offer.Validate(now, c.TargetKey)
			}
			if err == nil {
				t.Fatal("unsafe capsule was accepted")
			}
		})
	}
}

func TestHandoffFramingRoundTripAndBound(t *testing.T) {
	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	offer, err := SealHandoff(testCapsule(now))
	if err != nil {
		t.Fatal(err)
	}
	var wire bytes.Buffer
	if err := WriteHandoff(&wire, offer); err != nil {
		t.Fatal(err)
	}
	var got []HandoffOffer
	if err := ParseHandoffs(&wire, func(o HandoffOffer) { got = append(got, o) }); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ContentHash != offer.ContentHash || got[0].Capsule.ID != offer.Capsule.ID {
		t.Fatalf("round trip mismatch: %#v", got)
	}

	tooLong := strings.Repeat("x", HandoffMaxWireBytes+1) + "\n"
	if err := ParseHandoffs(strings.NewReader(tooLong), func(HandoffOffer) {}); err == nil {
		t.Fatal("oversized wire record was accepted")
	}
}

func TestHandoffApplicationAcknowledgement(t *testing.T) {
	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	offer, err := SealHandoff(testCapsule(now))
	if err != nil {
		t.Fatal(err)
	}
	ack := HandoffAck{Version: HandoffVersion, ID: offer.Capsule.ID, ContentHash: offer.ContentHash, Status: HandoffAckStored}
	var wire bytes.Buffer
	if err := WriteHandoffAck(&wire, ack); err != nil {
		t.Fatal(err)
	}
	got, err := ReadHandoffAck(&wire)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Accepted() || got.ValidateFor(offer) != nil {
		t.Fatalf("valid acknowledgement rejected: %+v", got)
	}

	rejected := HandoffAck{Version: HandoffVersion, ID: offer.Capsule.ID, Status: HandoffAckRejected, Reason: "target_mismatch"}
	if err := rejected.ValidateFor(offer); err != nil || rejected.Accepted() {
		t.Fatalf("valid rejection misclassified: ack=%+v err=%v", rejected, err)
	}
	tampered := ack
	tampered.ContentHash = "sha256:" + strings.Repeat("f", 64)
	if err := tampered.ValidateFor(offer); err == nil {
		t.Fatal("mismatched acknowledgement hash accepted")
	}

	unknown := []byte(`{"version":1,"status":"rejected","reason":"invalid_offer","extra":true}` + "\n")
	if _, err := ReadHandoffAck(bytes.NewReader(unknown)); err == nil {
		t.Fatal("acknowledgement with unknown field accepted")
	}
}

func TestHandoffStateMachineIsStrictAndIdempotent(t *testing.T) {
	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	offer, _ := SealHandoff(testCapsule(now))
	r := HandoffRecord{Offer: offer, SourcePeer: "source.mesh", SourceKey: "source-key", ReceivedAt: now, UpdatedAt: now, State: HandoffOffered}

	if err := r.Transition(HandoffContinued, now.Add(time.Minute), "skip consent"); err == nil {
		t.Fatal("offered handoff jumped directly to continued")
	}
	if err := r.Transition(HandoffAccepted, now.Add(time.Minute), "accepted locally"); err != nil {
		t.Fatal(err)
	}
	updated := r.UpdatedAt
	if err := r.Transition(HandoffAccepted, now.Add(2*time.Minute), "retry"); err != nil {
		t.Fatalf("idempotent transition failed: %v", err)
	}
	if !r.UpdatedAt.Equal(updated) {
		t.Fatal("idempotent transition rewrote the record")
	}
	if err := r.Transition(HandoffContinued, now.Add(3*time.Minute), "skipped dispatch claim"); err == nil {
		t.Fatal("accepted handoff skipped the dispatch claim")
	}
	claimAt := now.Add(3 * time.Minute)
	attempt := HandoffDeliveryAttempt{AgentAddr: "100.64.0.31:9120", AgentKey: "agent-key", Tool: "resume", ClaimedAt: claimAt}
	if err := r.ClaimDelivery(attempt, claimAt); err != nil {
		t.Fatal(err)
	}
	if err := r.AcknowledgeDelivery(now.Add(4 * time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := r.Transition(HandoffDeclined, now.Add(5*time.Minute), "too late"); err == nil {
		t.Fatal("terminal continued handoff was changed")
	}
}

func TestHandoffDispatchingRequiresExplicitRearm(t *testing.T) {
	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	offer, _ := SealHandoff(testCapsule(now))
	r := HandoffRecord{Offer: offer, State: HandoffAccepted, ReceivedAt: now, UpdatedAt: now}
	claimAt := now.Add(time.Minute)
	if err := r.ClaimDelivery(HandoffDeliveryAttempt{AgentAddr: "100.64.0.31:9120", AgentKey: "agent-key", Tool: "resume", ClaimedAt: claimAt}, claimAt); err != nil {
		t.Fatal(err)
	}
	if err := r.Transition(HandoffAccepted, now.Add(2*time.Minute), "retry accept"); err == nil {
		t.Fatal("ordinary accept re-armed an unknown dispatch")
	}
	if err := r.Rearm(now.Add(2*time.Minute), "operator checked receipts and re-armed"); err != nil {
		t.Fatal(err)
	}
	if r.State != HandoffAccepted {
		t.Fatalf("state = %q, want accepted", r.State)
	}
}

func TestHandoffDeliveryAttemptValidation(t *testing.T) {
	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	ack := now.Add(time.Second)
	valid := HandoffDeliveryAttempt{
		AgentAddr: "100.64.0.31:9120", AgentKey: "destination-agent-key", Tool: "resume_analysis",
		ClaimedAt: now, AcknowledgedAt: &ack,
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid delivery attempt rejected: %v", err)
	}
	for name, mutate := range map[string]func(*HandoffDeliveryAttempt){
		"missing address": func(a *HandoffDeliveryAttempt) { a.AgentAddr = "" },
		"missing key":     func(a *HandoffDeliveryAttempt) { a.AgentKey = "" },
		"unselected tool": func(a *HandoffDeliveryAttempt) { a.Tool = "" },
		"zero claim":      func(a *HandoffDeliveryAttempt) { a.ClaimedAt = time.Time{} },
		"early ack": func(a *HandoffDeliveryAttempt) {
			early := now.Add(-time.Second)
			a.AcknowledgedAt = &early
		},
	} {
		t.Run(name, func(t *testing.T) {
			attempt := valid
			mutate(&attempt)
			if err := attempt.Validate(); err == nil {
				t.Fatalf("invalid delivery attempt accepted: %+v", attempt)
			}
		})
	}
}

func TestHandoffEffectiveExpiry(t *testing.T) {
	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	c := testCapsule(now)
	c.ExpiresAt = now.Add(time.Minute)
	offer, _ := SealHandoff(c)
	r := HandoffRecord{Offer: offer, State: HandoffOffered}
	if got := r.EffectiveState(now.Add(2 * time.Minute)); got != HandoffExpired {
		t.Fatalf("effective state = %q, want expired", got)
	}
	if err := r.Transition(HandoffExpired, now.Add(2*time.Minute), "ttl elapsed"); err != nil {
		t.Fatal(err)
	}
	if r.State != HandoffExpired {
		t.Fatalf("persisted state = %q", r.State)
	}
}

func TestNewHandoffID(t *testing.T) {
	a, err := NewHandoffID()
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewHandoffID()
	if err != nil {
		t.Fatal(err)
	}
	if a == b || !validHandoffID(a) || !validHandoffID(b) {
		t.Fatalf("bad random ids %q %q", a, b)
	}
}
