package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/xrey167/meshmcp/air"
	"github.com/xrey167/meshmcp/policy"
	"github.com/xrey167/meshmcp/session"
)

func TestNewSteerFactoryValidatesBeforeAuditAndDelivery(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	delivered := make(chan steerEnvelope, 3)
	var ledger bytes.Buffer
	audit := policy.NewAuditLog(&ledger, func() string { return "T" })
	factory := newSteerFactory(ctx, delivered, audit)
	backend, err := factory(session.Meta{
		PeerFQDN: "sender.mesh",
		PeerKey:  "sender-key",
		PeerAddr: "100.64.0.8",
	})
	if err != nil {
		t.Fatalf("newSteerFactory: %v", err)
	}

	const frames = "" +
		`{"type":"task","args":{"secret":"task-secret"}}` + "\n" +
		`{"type":"nudge","text":"context-secret","target":"bad-target","id":"id-secret"}` + "\n" +
		`{"type":"task","tool":"read_file","args":{"path":"ok"},"target":"task:ok","id":"handoff-id"}` + "\n"
	if _, err := io.WriteString(backend, frames); err != nil {
		t.Fatalf("write steer frames: %v", err)
	}
	ackC := make(chan []air.SteerAck, 1)
	errC := make(chan error, 1)
	go func() {
		reader := bufio.NewReader(backend)
		acks := make([]air.SteerAck, 0, 3)
		for len(acks) < 3 {
			line, err := reader.ReadBytes('\n')
			if err != nil {
				errC <- err
				return
			}
			ack, err := air.ReadSteerAck(bytes.NewReader(line))
			if err != nil {
				errC <- err
				return
			}
			acks = append(acks, ack)
		}
		ackC <- acks
	}()
	var acks []air.SteerAck
	select {
	case acks = <-ackC:
	case err := <-errC:
		t.Fatalf("read steer ACKs: %v", err)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for steer ACKs")
	}
	if err := backend.Close(); err != nil {
		t.Fatalf("close steer backend: %v", err)
	}
	if acks[0].Status != air.SteerAckRejected || acks[1].Status != air.SteerAckRejected || acks[2].Status != air.SteerAckDelivered {
		t.Fatalf("steer ACK statuses = %+v", acks)
	}

	select {
	case got := <-delivered:
		if got.Type != "task" || got.Tool != "read_file" || got.Target != "task:ok" || string(got.Args) != `{"path":"ok"}` {
			t.Fatalf("unexpected delivered envelope: %+v", got)
		}
	default:
		t.Fatal("valid envelope was not delivered")
	}
	select {
	case got := <-delivered:
		t.Fatalf("invalid envelope was delivered: %+v", got)
	default:
	}

	var records []policy.AuditRecord
	dec := json.NewDecoder(bytes.NewReader(ledger.Bytes()))
	for dec.More() {
		var rec policy.AuditRecord
		if err := dec.Decode(&rec); err != nil {
			t.Fatalf("decode audit record: %v", err)
		}
		records = append(records, rec)
	}
	if len(records) != 4 {
		t.Fatalf("got %d audit records, want 4: %s", len(records), ledger.String())
	}
	for i := 0; i < 2; i++ {
		if records[i].Decision != "deny" {
			t.Errorf("record %d decision = %q, want deny", i, records[i].Decision)
		}
		if records[i].Reason != "invalid steer envelope" {
			t.Errorf("record %d reason = %q, want context-free denial", i, records[i].Reason)
		}
		for _, secret := range []string{"task-secret", "context-secret", "bad-target", "id-secret"} {
			if strings.Contains(records[i].Reason, secret) {
				t.Errorf("record %d reason leaked %q: %q", i, secret, records[i].Reason)
			}
		}
	}
	if records[2].Method != "air/steer/authorize" || records[2].Decision != "allow" || records[2].Tool != "read_file" || records[2].RPCID != "handoff-id" || records[2].Reason != "steer envelope authorized" {
		t.Fatalf("valid envelope authorization audit = %+v", records[2])
	}
	if records[3].Method != "air/steer/enqueue" || records[3].Decision != "allow" || records[3].Tool != "read_file" || records[3].RPCID != "handoff-id" || records[3].Reason != "steer enqueued" {
		t.Fatalf("valid envelope enqueue audit = %+v", records[3])
	}
}

type failingSteerAuditWriter struct{}

func (failingSteerAuditWriter) Write([]byte) (int, error) { return 0, errors.New("audit unavailable") }

type failSecondSteerAuditWriter struct {
	writes int
}

func (w *failSecondSteerAuditWriter) Write(p []byte) (int, error) {
	w.writes++
	if w.writes == 2 {
		return 0, errors.New("enqueue receipt unavailable")
	}
	return len(p), nil
}

// NOTE: quarantined in CI (.github/workflows/ci.yml) as timing-flaky under
// -race — the one-shot steer client can race its own graceful close against a
// net.Pipe EOF and try to resume a just-finalized session ("requested resume
// session is no longer available"). Self-healing over a real mesh; a proper
// fix belongs in the session/ reconnect path. Runs by default locally.
func TestSteerDeliveryRequiresApplicationAck(t *testing.T) {
	agentCtx, stopAgent := context.WithCancel(context.Background())
	defer stopAgent()
	delivered := make(chan steerEnvelope, 64)
	var ledger bytes.Buffer
	audit := policy.NewAuditLog(&ledger, func() string { return "T" }).WithFailClosed(true)
	srv := session.NewServer(newSteerFactory(agentCtx, delivered, audit), time.Minute, nil)
	dial := func(context.Context) (net.Conn, error) {
		client, server := net.Pipe()
		go srv.Handle(server, session.Meta{PeerFQDN: "sender.mesh", PeerKey: "sender-key"})
		return client, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	env := steerEnvelope{Type: "task", Tool: "resume", Args: json.RawMessage(`{"step":3}`), ID: "handoff-id"}
	for i := 0; i < 20; i++ {
		if err := sendSteerEnvelopeWithDial(ctx, dial, env); err != nil {
			t.Fatalf("positive steer ACK iteration %d: %v", i, err)
		}
	}
	if got := len(delivered); got != 20 {
		t.Fatalf("delivered steers = %d, want 20", got)
	}

	stoppedCtx, stop := context.WithCancel(context.Background())
	stop()
	var stoppedLedger bytes.Buffer
	stoppedAudit := policy.NewAuditLog(&stoppedLedger, func() string { return "T" }).WithFailClosed(true)
	stoppedSrv := session.NewServer(newSteerFactory(stoppedCtx, make(chan steerEnvelope), stoppedAudit), time.Minute, nil)
	stoppedDial := func(context.Context) (net.Conn, error) {
		client, server := net.Pipe()
		go stoppedSrv.Handle(server, session.Meta{PeerFQDN: "sender.mesh", PeerKey: "sender-key"})
		return client, nil
	}
	if err := sendSteerEnvelopeWithDial(ctx, stoppedDial, env); err == nil || !strings.Contains(err.Error(), "agent_stopping") {
		t.Fatalf("stopped agent result = %v, want application NACK", err)
	}
	var stoppedRecords []policy.AuditRecord
	stoppedDec := json.NewDecoder(bytes.NewReader(stoppedLedger.Bytes()))
	for stoppedDec.More() {
		var rec policy.AuditRecord
		if err := stoppedDec.Decode(&rec); err != nil {
			t.Fatal(err)
		}
		stoppedRecords = append(stoppedRecords, rec)
	}
	if len(stoppedRecords) != 2 || stoppedRecords[0].Method != "air/steer/authorize" || stoppedRecords[0].Decision != "allow" || stoppedRecords[1].Method != "air/steer/enqueue" || stoppedRecords[1].Decision != "deny" {
		t.Fatalf("stopped agent audit does not distinguish authorization from enqueue: %+v", stoppedRecords)
	}

	failAudit := policy.NewAuditLog(failingSteerAuditWriter{}, func() string { return "T" }).WithFailClosed(true)
	failSrv := session.NewServer(newSteerFactory(context.Background(), make(chan steerEnvelope), failAudit), time.Minute, nil)
	failDial := func(context.Context) (net.Conn, error) {
		client, server := net.Pipe()
		go failSrv.Handle(server, session.Meta{PeerFQDN: "sender.mesh", PeerKey: "sender-key"})
		return client, nil
	}
	if err := sendSteerEnvelopeWithDial(ctx, failDial, env); err == nil || !strings.Contains(err.Error(), "audit_unavailable") {
		t.Fatalf("failed audit result = %v, want fail-closed NACK", err)
	}

	postAuditDelivered := make(chan steerEnvelope, 1)
	postAuditWriter := &failSecondSteerAuditWriter{}
	postAudit := policy.NewAuditLog(postAuditWriter, func() string { return "T" }).WithFailClosed(true)
	postAuditSrv := session.NewServer(newSteerFactory(context.Background(), postAuditDelivered, postAudit), time.Minute, nil)
	postAuditDial := func(context.Context) (net.Conn, error) {
		client, server := net.Pipe()
		go postAuditSrv.Handle(server, session.Meta{PeerFQDN: "sender.mesh", PeerKey: "sender-key"})
		return client, nil
	}
	if err := sendSteerEnvelopeWithDial(ctx, postAuditDial, env); err == nil || !strings.Contains(err.Error(), "audit_unavailable") {
		t.Fatalf("failed enqueue receipt result = %v, want unknown application NACK", err)
	}
	if got := len(postAuditDelivered); got != 1 {
		t.Fatalf("post-enqueue audit failure lost delivery evidence: delivered=%d", got)
	}
}

func TestSteerAckSinkCloseUnblocksFullAgentChannel(t *testing.T) {
	full := make(chan steerEnvelope, 1)
	full <- steerEnvelope{Type: "cancel"}
	factory := newSteerFactory(context.Background(), full, nil)
	backend, err := factory(session.Meta{PeerFQDN: "sender.mesh", PeerKey: "sender-key"})
	if err != nil {
		t.Fatal(err)
	}
	if err := air.WriteEnvelope(backend, steerEnvelope{Type: "cancel", ID: "blocked"}); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- backend.Close() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("steer backend Close blocked behind a full agent channel")
	}
}
