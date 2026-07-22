package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xrey167/meshmcp/air"
	"github.com/xrey167/meshmcp/policy"
	"github.com/xrey167/meshmcp/session"
)

func handoffTestClock(now time.Time) func() time.Time {
	return func() time.Time { return now }
}

func TestParseHandoffInputs(t *testing.T) {
	work, err := parseHandoffWork("task:task-17")
	if err != nil || work.Kind != air.WorkTask || work.ID != "task-17" {
		t.Fatalf("parse work: work=%+v err=%v", work, err)
	}
	for _, bad := range []string{"", "task", ":id", "group:ops"} {
		if _, err := parseHandoffWork(bad); err == nil {
			t.Errorf("invalid work %q accepted", bad)
		}
	}

	artifact, err := parseHandoffArtifact("report.json=sha256:" + strings.Repeat("a", 64))
	if err != nil || artifact.Name != "report.json" || artifact.SHA256 != "sha256:"+strings.Repeat("a", 64) {
		t.Fatalf("parse artifact: artifact=%+v err=%v", artifact, err)
	}
	for _, bad := range []string{"report.json", "../report=sha256:" + strings.Repeat("a", 64), "x=sha256:bad"} {
		if _, err := parseHandoffArtifact(bad); err == nil {
			t.Errorf("invalid artifact %q accepted", bad)
		}
	}

	cursor, err := readHandoffCursor(strings.NewReader(`{"step":3}`))
	if err != nil || string(cursor) != `{"step":3}` {
		t.Fatalf("read cursor: cursor=%s err=%v", cursor, err)
	}
	if _, err := readHandoffCursor(strings.NewReader(`{`)); err == nil {
		t.Fatal("invalid cursor JSON accepted")
	}
	if _, err := readHandoffCursor(strings.NewReader(`"` + strings.Repeat("x", air.HandoffMaxInlineBytes) + `"`)); err == nil {
		t.Fatal("oversized cursor accepted")
	}
}

func TestVerifyHandoffTargetAddressBeforeSendingContext(t *testing.T) {
	resolver := func(ip netip.Addr) (string, error) {
		if ip.String() != "100.64.0.22" {
			t.Fatalf("resolved IP = %s", ip)
		}
		return "destination-key", nil
	}
	if err := verifyHandoffTargetAddress("100.64.0.22:9140", "destination-key", resolver); err != nil {
		t.Fatal(err)
	}
	if err := verifyHandoffTargetAddress("100.64.0.22:9140", "attacker-key", resolver); err == nil {
		t.Fatal("mismatched transport identity accepted")
	}
	if err := verifyHandoffTargetAddress("destination.mesh:9140", "destination-key", resolver); err == nil {
		t.Fatal("unverifiable hostname accepted before sensitive context send")
	}
}

func TestExactPeerDialReverifiesEveryConnection(t *testing.T) {
	var peers []net.Conn
	base := func(context.Context) (net.Conn, error) {
		client, peer := net.Pipe()
		peers = append(peers, peer)
		return client, nil
	}
	keys := []string{"destination-key", "reassigned-key"}
	resolved := 0
	dial := exactPeerDial(base, "destination-key", func(net.Addr) string {
		key := keys[resolved]
		resolved++
		return key
	}, "identity mismatch")

	conn, err := dial(context.Background())
	if err != nil {
		t.Fatalf("first exact-key connection: %v", err)
	}
	_ = conn.Close()
	if _, err := dial(context.Background()); err == nil || !strings.Contains(err.Error(), "identity mismatch") {
		t.Fatalf("reassigned reconnect was not rejected: %v", err)
	}
	for _, peer := range peers {
		_ = peer.Close()
	}
	if resolved != 2 {
		t.Fatalf("identity resolutions = %d, want one per connection", resolved)
	}
}

func TestHandoffReceiverStampsVerifiedSourceAndOnlyStores(t *testing.T) {
	now := time.Date(2026, 7, 22, 20, 0, 0, 0, time.UTC)
	inbox, err := newHandoffInbox(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	offer := testHandoffOffer(t, strings.Repeat("a", 32), now, time.Hour, "do not put this goal in audit")
	offer.Capsule.Cursor = json.RawMessage(`{"tool":"delete_everything","args":{"secret":"inline-context"}}`)
	offer, err = air.SealHandoff(offer.Capsule)
	if err != nil {
		t.Fatal(err)
	}

	var ledger bytes.Buffer
	audit := policy.NewAuditLog(&ledger, func() string { return "T" })
	factory := newHandoffReceiveFactory(inbox, testTargetKey, newRingLimiter(60), audit, func() time.Time { return now })
	backend, err := factory(testSource())
	if err != nil {
		t.Fatal(err)
	}
	if err := air.WriteHandoff(backend, offer); err != nil {
		t.Fatal(err)
	}
	if err := backend.Close(); err != nil {
		t.Fatal(err)
	}

	rec, ok, err := inbox.Get(offer.Capsule.ID)
	if err != nil || !ok {
		t.Fatalf("stored record: ok=%v err=%v", ok, err)
	}
	if rec.SourcePeer != testSource().PeerFQDN || rec.SourceKey != testSource().PeerKey || rec.SourceAddr != testSource().PeerAddr {
		t.Fatalf("source was not stamped from session metadata: %+v", rec)
	}
	if rec.State != air.HandoffOffered {
		t.Fatalf("receive auto-executed or transitioned offer: state=%q", rec.State)
	}

	var auditRec policy.AuditRecord
	if err := json.NewDecoder(bytes.NewReader(ledger.Bytes())).Decode(&auditRec); err != nil {
		t.Fatalf("decode audit: %v", err)
	}
	if auditRec.Decision != "allow" || auditRec.PeerKey != testSource().PeerKey || auditRec.RPCID != offer.Capsule.ID {
		t.Fatalf("unexpected audit record: %+v", auditRec)
	}
	if len(auditRec.Provenance) != 1 || auditRec.Provenance[0] != offer.ContentHash {
		t.Fatalf("audit provenance = %v, want content hash", auditRec.Provenance)
	}
	for _, private := range []string{offer.Capsule.Goal, "delete_everything", "inline-context"} {
		if strings.Contains(auditRec.Reason, private) {
			t.Fatalf("audit reason leaked inline context %q: %q", private, auditRec.Reason)
		}
	}
}

func TestHandoffRateLimitRunsBeforeParsingAndSamplesDenials(t *testing.T) {
	now := time.Date(2026, 7, 22, 20, 0, 0, 0, time.UTC)
	inbox, err := newHandoffInbox(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var ledger bytes.Buffer
	audit := policy.NewAuditLog(&ledger, func() string { return "T" })
	limiter := newRingLimiter(1)
	deniedAuditLimiter := newRingLimiter(1)

	first := receiveHandoffOffer(strings.NewReader("not-json\n"), inbox, testTargetKey, limiter, deniedAuditLimiter, audit, testSource(), func() time.Time { return now })
	if first.Reason != "invalid_offer" {
		t.Fatalf("first malformed offer reason = %q", first.Reason)
	}
	offer := testHandoffOffer(t, strings.Repeat("9", 32), now, time.Hour, "must not be parsed")
	var wire bytes.Buffer
	if err := air.WriteHandoff(&wire, offer); err != nil {
		t.Fatal(err)
	}
	before := wire.Len()
	second := receiveHandoffOffer(&wire, inbox, testTargetKey, limiter, deniedAuditLimiter, audit, testSource(), func() time.Time { return now })
	if second.Reason != "rate_limited" {
		t.Fatalf("second offer reason = %q, want rate_limited", second.Reason)
	}
	if wire.Len() != before {
		t.Fatal("rate-limited offer was read before rejection")
	}
	third := receiveHandoffOffer(&wire, inbox, testTargetKey, limiter, deniedAuditLimiter, audit, testSource(), func() time.Time { return now })
	if third.Reason != "rate_limited" || wire.Len() != before {
		t.Fatalf("repetitive denial parsed input or changed reason: ack=%+v remaining=%d", third, wire.Len())
	}
	if got := bytes.Count(ledger.Bytes(), []byte{'\n'}); got != 2 {
		t.Fatalf("audit records = %d, want malformed decision plus one sampled rate denial", got)
	}
}

func TestHandoffReceiptRefreshesClockAfterBlockingFrameRead(t *testing.T) {
	created := time.Date(2026, 7, 22, 20, 0, 0, 0, time.UTC)
	inbox, err := newHandoffInbox(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	offer := testHandoffOffer(t, strings.Repeat("8", 32), created, time.Minute, "expires while sender stalls")
	var wire bytes.Buffer
	if err := air.WriteHandoff(&wire, offer); err != nil {
		t.Fatal(err)
	}
	clockCalls := 0
	nowf := func() time.Time {
		clockCalls++
		if clockCalls == 1 {
			return created
		}
		return offer.Capsule.ExpiresAt
	}
	ack := receiveHandoffOffer(&wire, inbox, testTargetKey, nil, nil, nil, testSource(), nowf)
	if ack.Reason != "offer_rejected" {
		t.Fatalf("expired delayed offer acknowledgement = %+v", ack)
	}
	if _, found, err := inbox.Get(offer.Capsule.ID); err != nil || found {
		t.Fatalf("offer that expired while reading was stored: found=%v err=%v", found, err)
	}
	if clockCalls < 2 {
		t.Fatalf("receipt clock calls = %d, want a post-frame refresh", clockCalls)
	}
}

func TestOpenHandoffAuditContinuesChainAndRejectsSymlink(t *testing.T) {
	path := filepath.Join(t.TempDir(), "handoff-audit.jsonl")
	first, closeFirst, err := openHandoffAudit(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Append(policy.AuditRecord{Backend: "handoff", Method: "air/handoff/offer", Decision: "allow", Rule: -1}); err != nil {
		t.Fatal(err)
	}
	closeFirst()
	second, closeSecond, err := openHandoffAudit(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := second.Append(policy.AuditRecord{Backend: "handoff", Method: "air/handoff/offer", Decision: "deny", Rule: -1}); err != nil {
		t.Fatal(err)
	}
	closeSecond()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	var one, two policy.AuditRecord
	if err := dec.Decode(&one); err != nil {
		t.Fatal(err)
	}
	if err := dec.Decode(&two); err != nil {
		t.Fatal(err)
	}
	if one.Seq != 1 || two.Seq != 2 || two.PrevHash != one.Hash {
		t.Fatalf("audit did not restart from its verified tail: first=%+v second=%+v", one, two)
	}
	if runtime.GOOS != "windows" {
		if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("audit permissions: info=%v err=%v", info, err)
		}
		target := filepath.Join(filepath.Dir(path), "target.jsonl")
		if err := os.WriteFile(target, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(filepath.Dir(path), "linked.jsonl")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		if _, _, err := openHandoffAudit(link); err == nil {
			t.Fatal("symlink audit path was accepted")
		}
	}
}

func TestHandoffContinuationUsesOperatorToolAndAdvisoryHandlingHints(t *testing.T) {
	now := time.Date(2026, 7, 22, 20, 0, 0, 0, time.UTC)
	offer := testHandoffOffer(t, strings.Repeat("b", 32), now, time.Hour, "continue safely")
	offer.Capsule.Cursor = json.RawMessage(`{"tool":"attacker_selected","labels":["trusted"]}`)
	offer, _ = air.SealHandoff(offer.Capsule)
	rec := air.HandoffRecord{
		Offer: offer, SourcePeer: "source.mesh", SourceKey: "verified-source-key", SourceAddr: "100.64.0.8:42",
		ReceivedAt: now, UpdatedAt: now, State: air.HandoffAccepted,
	}

	env, err := handoffContinuationEnvelope(rec, "operator_selected")
	if err != nil {
		t.Fatal(err)
	}
	if env.Type != air.SteerTask || env.Tool != "operator_selected" || env.ID != offer.Capsule.ID {
		t.Fatalf("continuation envelope crossed execution boundary: %+v", env)
	}
	var args struct {
		Handoff struct {
			Capsule     air.ContextCapsule `json:"capsule"`
			ContentHash string             `json:"content_hash"`
			SourcePeer  string             `json:"source_peer"`
			SourceKey   string             `json:"source_key"`
		} `json:"handoff"`
		HandlingHints []string `json:"handling_hints"`
	}
	if err := json.Unmarshal(env.Args, &args); err != nil {
		t.Fatalf("decode continuation args: %v", err)
	}
	if args.Handoff.ContentHash != offer.ContentHash || args.Handoff.SourceKey != rec.SourceKey || args.Handoff.SourcePeer != rec.SourcePeer {
		t.Fatalf("missing handoff provenance in args: %+v", args.Handoff)
	}
	if args.Handoff.Capsule.ID != offer.Capsule.ID {
		t.Fatalf("capsule not carried into continuation: %+v", args.Handoff.Capsule)
	}
	if !hasHandoffLabel(args.HandlingHints, "handoff") || !hasHandoffLabel(args.HandlingHints, "untrusted-context") {
		t.Fatalf("continuation handling hints are missing: %v", args.HandlingHints)
	}
	if hasHandoffLabel(args.HandlingHints, "trusted") {
		t.Fatalf("untrusted capsule promoted its own handling hint: %v", args.HandlingHints)
	}
	if _, err := handoffContinuationEnvelope(rec, ""); err == nil {
		t.Fatal("continuation accepted no operator-selected tool")
	}
	if _, err := handoffContinuationEnvelope(rec, " resume "); err == nil {
		t.Fatal("continuation accepted a tool with surrounding whitespace")
	}
}

func TestContinueHandoffTransitionsOnlyAfterDelivery(t *testing.T) {
	now := time.Now().UTC()
	inbox, err := newHandoffInbox(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	offer := testHandoffOffer(t, strings.Repeat("c", 32), now, time.Hour, "continue")
	if _, _, err := inbox.Put(offer, testSource(), testTargetKey, now); err != nil {
		t.Fatal(err)
	}
	if _, err := inbox.Transition(offer.Capsule.ID, air.HandoffAccepted, now, "accepted"); err != nil {
		t.Fatal(err)
	}

	deliveryErr := errors.New("agent offline")
	_, err = continueStoredHandoff(context.Background(), inbox, offer.Capsule.ID, "agent:9141", "agent-key", "resume", handoffTestClock(now.Add(time.Minute)),
		func(context.Context, string, steerEnvelope) error { return deliveryErr })
	if !errors.Is(err, deliveryErr) {
		t.Fatalf("delivery error = %v, want %v", err, deliveryErr)
	}
	rec, _, _ := inbox.Get(offer.Capsule.ID)
	if rec.State != air.HandoffDispatching {
		t.Fatalf("failed delivery changed state to %q", rec.State)
	}
	if _, err := inbox.Transition(offer.Capsule.ID, air.HandoffAccepted, now.Add(90*time.Second), "retry accept"); err == nil {
		t.Fatal("ordinary accept re-armed unknown delivery")
	}
	if _, err := inbox.Rearm(offer.Capsule.ID, now.Add(90*time.Second), "operator checked receipts and re-armed"); err != nil {
		t.Fatalf("re-arm unknown delivery: %v", err)
	}

	var delivered steerEnvelope
	rec, err = continueStoredHandoff(context.Background(), inbox, offer.Capsule.ID, "agent:9141", "agent-key", "resume", handoffTestClock(now.Add(2*time.Minute)),
		func(_ context.Context, addr string, env steerEnvelope) error {
			if addr != "agent:9141" {
				t.Fatalf("delivery address = %q", addr)
			}
			delivered = env
			return nil
		})
	if err != nil {
		t.Fatal(err)
	}
	if delivered.Tool != "resume" || rec.State != air.HandoffContinued {
		t.Fatalf("delivery/state = %+v / %q", delivered, rec.State)
	}
	if len(rec.DeliveryAttempts) != 2 {
		t.Fatalf("delivery attempt history = %+v, want failed and acknowledged attempts", rec.DeliveryAttempts)
	}
	if rec.DeliveryAttempts[0].AcknowledgedAt != nil {
		t.Fatalf("unknown first dispatch was marked acknowledged: %+v", rec.DeliveryAttempts[0])
	}
	last := rec.DeliveryAttempts[1]
	if last.AgentAddr != "agent:9141" || last.AgentKey != "agent-key" || last.Tool != "resume" || last.AcknowledgedAt == nil {
		t.Fatalf("acknowledged destination receipt = %+v", last)
	}

	// Continued is terminal; this also proves a continuation is not described
	// as execution success and cannot silently execute twice.
	if _, err := continueStoredHandoff(context.Background(), inbox, offer.Capsule.ID, "agent:9141", "agent-key", "resume", handoffTestClock(now.Add(3*time.Minute)),
		func(context.Context, string, steerEnvelope) error { return nil }); err == nil {
		t.Fatal("continued handoff was delivered twice")
	}
}

func TestContinueHandoffClaimPreventsConcurrentDelivery(t *testing.T) {
	now := time.Now().UTC()
	inbox, err := newHandoffInbox(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	offer := testHandoffOffer(t, strings.Repeat("e", 32), now, time.Hour, "continue once")
	if _, _, err := inbox.Put(offer, testSource(), testTargetKey, now); err != nil {
		t.Fatal(err)
	}
	if _, err := inbox.Transition(offer.Capsule.ID, air.HandoffAccepted, now, "accepted"); err != nil {
		t.Fatal(err)
	}

	started := make(chan struct{})
	release := make(chan struct{})
	firstDone := make(chan error, 1)
	var deliveries atomic.Int32
	go func() {
		_, err := continueStoredHandoff(context.Background(), inbox, offer.Capsule.ID, "agent:9141", "agent-key", "resume", handoffTestClock(now.Add(time.Second)),
			func(context.Context, string, steerEnvelope) error {
				deliveries.Add(1)
				close(started)
				<-release
				return nil
			})
		firstDone <- err
	}()
	<-started
	if _, err := continueStoredHandoff(context.Background(), inbox, offer.Capsule.ID, "agent:9141", "agent-key", "resume", handoffTestClock(now.Add(2*time.Second)),
		func(context.Context, string, steerEnvelope) error {
			deliveries.Add(1)
			return nil
		}); err == nil {
		t.Fatal("concurrent continuation passed an existing dispatch claim")
	}
	close(release)
	if err := <-firstDone; err != nil {
		t.Fatal(err)
	}
	if got := deliveries.Load(); got != 1 {
		t.Fatalf("deliveries = %d, want exactly one", got)
	}
}

func TestContinueHandoffCancellationDuringDeliveryRemainsDispatching(t *testing.T) {
	now := time.Now().UTC()
	inbox, err := newHandoffInbox(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	offer := testHandoffOffer(t, strings.Repeat("f", 32), now, time.Hour, "cancel safely")
	if _, _, err := inbox.Put(offer, testSource(), testTargetKey, now); err != nil {
		t.Fatal(err)
	}
	if _, err := inbox.Transition(offer.Capsule.ID, air.HandoffAccepted, now, "accepted"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	_, err = continueStoredHandoff(ctx, inbox, offer.Capsule.ID, "agent:9141", "agent-key", "resume", handoffTestClock(now.Add(time.Second)),
		func(context.Context, string, steerEnvelope) error {
			cancel()
			return nil
		})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("continuation error = %v, want context cancellation", err)
	}
	rec, _, _ := inbox.Get(offer.Capsule.ID)
	if rec.State != air.HandoffDispatching {
		t.Fatalf("cancelled delivery state = %q, want dispatching", rec.State)
	}
}

func TestContinueHandoffAccountsForExpiryThroughApplicationAck(t *testing.T) {
	created := time.Now().UTC()
	inbox, err := newHandoffInbox(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	offer := testHandoffOffer(t, strings.Repeat("7", 32), created, time.Hour, "expire during acknowledgement")
	if _, _, err := inbox.Put(offer, testSource(), testTargetKey, created); err != nil {
		t.Fatal(err)
	}
	if _, err := inbox.Transition(offer.Capsule.ID, air.HandoffAccepted, created.Add(time.Second), "accepted"); err != nil {
		t.Fatal(err)
	}
	times := []time.Time{created.Add(2 * time.Second), created.Add(3 * time.Second), offer.Capsule.ExpiresAt}
	clockCall := 0
	nowf := func() time.Time {
		when := times[clockCall]
		clockCall++
		return when
	}
	_, err = continueStoredHandoff(context.Background(), inbox, offer.Capsule.ID, "100.64.0.31:9120", "agent-key", "resume", nowf,
		func(context.Context, string, steerEnvelope) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "expiry boundary") {
		t.Fatalf("post-expiry application ACK result = %v", err)
	}
	rec, _, err := inbox.Get(offer.Capsule.ID)
	if err != nil {
		t.Fatal(err)
	}
	if rec.State != air.HandoffDispatching || len(rec.DeliveryAttempts) != 1 || rec.DeliveryAttempts[0].AcknowledgedAt != nil {
		t.Fatalf("post-expiry ACK did not preserve unknown dispatch: %+v", rec)
	}
}

func TestHandoffOfferRequiresDestinationApplicationAck(t *testing.T) {
	now := time.Now().UTC()
	inbox, err := newHandoffInbox(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var ledger bytes.Buffer
	audit := policy.NewAuditLog(&ledger, func() string { return "T" })
	factory := newHandoffReceiveFactory(inbox, testTargetKey, newRingLimiter(60), audit, time.Now)
	srv := session.NewServer(factory, time.Minute, nil)
	dial := func(context.Context) (net.Conn, error) {
		client, server := net.Pipe()
		go srv.Handle(server, testSource())
		return client, nil
	}

	offer := testHandoffOffer(t, strings.Repeat("1", 32), now, time.Hour, "store with ack")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for i := 0; i < 20; i++ {
		if err := sendHandoffOfferWithDial(ctx, dial, offer); err != nil {
			t.Fatalf("positive application ACK iteration %d: %v", i, err)
		}
	}

	rejected := testHandoffOffer(t, strings.Repeat("2", 32), now, time.Hour, "wrong target")
	rejected.Capsule.TargetKey = "another-target-key"
	rejected, err = air.SealHandoff(rejected.Capsule)
	if err != nil {
		t.Fatal(err)
	}
	if err := sendHandoffOfferWithDial(ctx, dial, rejected); err == nil || !strings.Contains(err.Error(), "destination rejected") {
		t.Fatalf("rejected offer result = %v, want application NACK", err)
	}
	if _, found, err := inbox.Get(rejected.Capsule.ID); err != nil || found {
		t.Fatalf("wrong-target offer stored: found=%v err=%v", found, err)
	}
}

func TestHandoffStateFilter(t *testing.T) {
	for _, state := range []string{"offered", "accepted", "dispatching", "declined", "continued", "expired"} {
		if !validHandoffStateFilter(state) {
			t.Errorf("valid state %q rejected", state)
		}
	}
	for _, state := range []string{"", "accept", "unknown", " accepted"} {
		if validHandoffStateFilter(state) {
			t.Errorf("invalid state %q accepted", state)
		}
	}
}

func TestHandoffListRedactsSensitiveGoal(t *testing.T) {
	now := time.Date(2026, 7, 22, 20, 0, 0, 0, time.UTC)
	offer := testHandoffOffer(t, strings.Repeat("d", 32), now, time.Hour, "private outage details")
	offer.Capsule.Sensitivity = air.SensitivitySensitive
	offer, _ = air.SealHandoff(offer.Capsule)
	rec := air.HandoffRecord{Offer: offer}
	if got := handoffListGoal(rec); strings.Contains(got, "private outage details") {
		t.Fatalf("sensitive list row leaked goal: %q", got)
	}
	rec.Offer.Capsule.Sensitivity = air.SensitivityLow
	if got := handoffListGoal(rec); got != "private outage details" {
		t.Fatalf("low-sensitivity goal = %q", got)
	}
}

func TestHandoffRecordViewExposesEffectiveExpiry(t *testing.T) {
	now := time.Now().UTC()
	offer := testHandoffOffer(t, strings.Repeat("3", 32), now, time.Minute, "expire")
	rec := air.HandoffRecord{Offer: offer, State: air.HandoffOffered, ReceivedAt: now, UpdatedAt: now}
	view := newHandoffRecordView(rec, now.Add(2*time.Minute))
	if view.State != air.HandoffOffered || view.EffectiveState != air.HandoffExpired {
		t.Fatalf("record view = persisted %q effective %q", view.State, view.EffectiveState)
	}
}

func hasHandoffLabel(labels []string, want string) bool {
	for _, label := range labels {
		if label == want {
			return true
		}
	}
	return false
}
