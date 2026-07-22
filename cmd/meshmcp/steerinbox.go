package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log"
	"sync"

	"github.com/xrey167/meshmcp/air"
	"github.com/xrey167/meshmcp/policy"
	"github.com/xrey167/meshmcp/session"
)

// newSteerFactory returns a session backend factory for an agent's steer inbox:
// each connection's bytes are decoded as newline-delimited steer envelopes and
// delivered to ch (until ctx ends). Its duplex steerAckSink emits an
// application ACK only after validation, fail-closed receipt audit, and agent
// channel delivery. Optionally audits each received steer.
func newSteerFactory(ctx context.Context, ch chan<- steerEnvelope, audit *policy.AuditLog) session.BackendFactory {
	return func(meta session.Meta) (session.Backend, error) {
		pr, pw := io.Pipe()
		d := newSteerAckSink(pw)
		appendAudit := func(env steerEnvelope, method, decision, reason string) error {
			if audit == nil {
				return nil
			}
			return audit.Append(policy.AuditRecord{
				Backend: "agent", Peer: meta.PeerFQDN, PeerKey: meta.PeerKey, PeerAddr: meta.PeerAddr,
				Method: method, Tool: env.Tool, RPCID: env.ID, Decision: decision,
				Reason: reason, Rule: -1,
			})
		}
		go func() {
			responseFailed := false
			err := recvEnvelopes(pr, func(env steerEnvelope) {
				if responseFailed {
					return
				}
				ack := air.SteerAck{Version: air.HandoffVersion, ID: env.ID, Status: air.SteerAckRejected}
				if err := env.Validate(); err != nil {
					log.Printf("invalid steer from %s", meta.PeerFQDN)
					if auditErr := appendAudit(env, "air/steer/authorize", "deny", "invalid steer envelope"); auditErr != nil {
						ack.Reason = "audit_unavailable"
					} else {
						ack.Reason = "invalid_envelope"
					}
					if err := d.enqueue(ack); err != nil {
						responseFailed = true
						_ = pr.CloseWithError(err)
					}
					return
				}
				log.Printf("steer %q from %s", env.Type, meta.PeerFQDN)
				// Phase 1 is a fail-closed authorization receipt. It is deliberately
				// distinct from the phase-2 enqueue receipt, so an allow record can
				// never be mistaken for proof that the agent channel accepted work.
				if err := appendAudit(env, "air/steer/authorize", "allow", "steer envelope authorized"); err != nil {
					ack.Reason = "audit_unavailable"
					if err := d.enqueue(ack); err != nil {
						responseFailed = true
						_ = pr.CloseWithError(err)
					}
					return
				}
				select {
				case ch <- env:
					// Phase 2 is the downstream receipt Handoff operators inspect.
					// If it cannot be committed, delivery is conservatively unknown.
					if err := appendAudit(env, "air/steer/enqueue", "allow", "steer enqueued"); err != nil {
						ack.Reason = "audit_unavailable"
					} else {
						ack.Status = air.SteerAckDelivered
						ack.Reason = ""
					}
				case <-ctx.Done():
					if err := appendAudit(env, "air/steer/enqueue", "deny", "agent stopped before steer enqueue"); err != nil {
						ack.Reason = "audit_unavailable"
					} else {
						ack.Reason = "agent_stopping"
					}
				case <-d.closing:
					if err := appendAudit(env, "air/steer/enqueue", "deny", "connection closed before steer enqueue"); err != nil {
						ack.Reason = "audit_unavailable"
					} else {
						ack.Reason = "connection_closed"
					}
				}
				if err := d.enqueue(ack); err != nil {
					responseFailed = true
					_ = pr.CloseWithError(err)
				}
			})
			if err != nil && !responseFailed {
				reason := "invalid_framing"
				if auditErr := appendAudit(steerEnvelope{}, "air/steer/framing", "deny", "invalid steer framing"); auditErr != nil {
					reason = "audit_unavailable"
				}
				_ = d.enqueue(air.SteerAck{Version: air.HandoffVersion, Status: air.SteerAckRejected, Reason: reason})
			}
			d.finish()
		}()
		return d, nil
	}
}

const steerAckQueueLimit = 64 << 10

// steerAckSink is a duplex backend: inbound lines feed the parser while ACKs
// are queued independently for the server output pump. It supports multiple
// steer frames per logical session without unbounded response buffering.
type steerAckSink struct {
	pw *io.PipeWriter

	mu        sync.Mutex
	cond      *sync.Cond
	out       []byte
	closed    bool
	done      chan struct{}
	closing   chan struct{}
	stopOnce  sync.Once
	closeOnce sync.Once
}

func newSteerAckSink(pw *io.PipeWriter) *steerAckSink {
	d := &steerAckSink{pw: pw, done: make(chan struct{}), closing: make(chan struct{})}
	d.cond = sync.NewCond(&d.mu)
	return d
}

func (d *steerAckSink) Write(p []byte) (int, error) { return d.pw.Write(p) }

func (d *steerAckSink) Read(p []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for len(d.out) == 0 && !d.closed {
		d.cond.Wait()
	}
	if len(d.out) == 0 {
		return 0, io.EOF
	}
	n := copy(p, d.out)
	d.out = append(d.out[:0], d.out[n:]...)
	return n, nil
}

func (d *steerAckSink) Close() error {
	d.closeOnce.Do(func() {
		d.stopOnce.Do(func() { close(d.closing) })
		_ = d.pw.Close()
		<-d.done
		d.mu.Lock()
		d.closed = true
		d.cond.Broadcast()
		d.mu.Unlock()
	})
	return nil
}

func (d *steerAckSink) enqueue(ack air.SteerAck) error {
	var wire bytes.Buffer
	if err := air.WriteSteerAck(&wire, ack); err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return errors.New("steer acknowledgement sink is closed")
	}
	if len(d.out)+wire.Len() > steerAckQueueLimit {
		return errors.New("steer acknowledgement queue is full")
	}
	d.out = append(d.out, wire.Bytes()...)
	d.cond.Signal()
	return nil
}

func (d *steerAckSink) finish() { close(d.done) }

// steerEnvelopeStream sends one envelope, then holds its read half open until
// the agent inbox emits an application ACK bound to that envelope's ID.
type steerEnvelopeStream struct {
	outgoing *bytes.Reader

	mu      sync.Mutex
	ack     bytes.Buffer
	ackDone chan struct{}
	once    sync.Once
}

func newSteerEnvelopeStream(outgoing []byte) *steerEnvelopeStream {
	return &steerEnvelopeStream{outgoing: bytes.NewReader(outgoing), ackDone: make(chan struct{})}
}

func (s *steerEnvelopeStream) Read(p []byte) (int, error) {
	if n, err := s.outgoing.Read(p); n > 0 || err != io.EOF {
		return n, err
	}
	<-s.ackDone
	return 0, io.EOF
}

func (s *steerEnvelopeStream) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ack.Len()+len(p) > air.SteerMaxAckBytes+1 {
		return 0, errors.New("steer acknowledgement exceeds the wire limit")
	}
	n, err := s.ack.Write(p)
	if bytes.IndexByte(s.ack.Bytes(), '\n') >= 0 {
		s.once.Do(func() { close(s.ackDone) })
	}
	return n, err
}

func (s *steerEnvelopeStream) Close() error {
	s.once.Do(func() { close(s.ackDone) })
	return nil
}

func (s *steerEnvelopeStream) acknowledgement() (air.SteerAck, error) {
	s.mu.Lock()
	b := append([]byte(nil), s.ack.Bytes()...)
	s.mu.Unlock()
	return air.ReadSteerAck(bytes.NewReader(b))
}

// recvEnvelopes is the pure newline-delimited envelope parser, carved into the
// air package (air.ParseEnvelopes); this alias keeps the receive path reading
// the same name.
var recvEnvelopes = air.ParseEnvelopes
