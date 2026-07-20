package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"sync"
	"time"

	"github.com/xrey167/meshmcp/pubsub"
	"github.com/xrey167/meshmcp/session"
)

// The pub/sub wire protocol is newline-delimited JSON over the resumable
// session byte stream. A client opens a session and sends a single hello
// frame declaring its role:
//
//	{"role":"pub"}
//	{"role":"sub","topics":["news.*"],"since":0,"backpressure":"drop_oldest"}
//
// A publisher then sends one pubFrame per message and reads one ackFrame per
// message. A subscriber reads an initial ackFrame, then a stream of pubsub
// Event lines, until it disconnects. Because the transport is the session
// layer, a subscriber survives roaming and can resume from its last sequence.

// frameEnvelope is the headroom added above the broker's payload cap when
// sizing the wire-frame scanner, so a maximum-size payload plus its JSON
// envelope (topic, labels, field names) still fits in one frame rather than
// being silently rejected. The broker's MaxPayloadBytes remains the
// authoritative payload limit.
const frameEnvelope = 1 << 16 // 64 KiB

type helloFrame struct {
	Role         string   `json:"role"` // "pub" | "sub"
	Topics       []string `json:"topics,omitempty"`
	Since        uint64   `json:"since,omitempty"`
	Backpressure string   `json:"backpressure,omitempty"`
	// Capability is an optional signed token granting topics beyond the
	// broker's default-deny policy, for the whole session.
	Capability string `json:"capability,omitempty"`
	// Group, if set, joins this subscription to a named consumer group: each
	// matching event goes to exactly one member of the group (load balancing).
	Group string `json:"group,omitempty"`
	// Ack requests at-least-once delivery within the group: delivered events are
	// held in-flight until the subscriber sends an ack frame, and redelivered to
	// another member if this one disconnects first. Requires Group.
	Ack bool `json:"ack,omitempty"`
}

// ackReqFrame is sent by an at-least-once subscriber to release an in-flight
// event (by sequence) once it has been processed.
type ackReqFrame struct {
	Ack uint64 `json:"ack"`
}

type pubFrame struct {
	Topic        string          `json:"topic"`
	Labels       []string        `json:"labels,omitempty"`
	Retain       bool            `json:"retain,omitempty"`
	RetainTTLSec int             `json:"retain_ttl_sec,omitempty"` // retained last-value expires after this many seconds (0 = never)
	RetainDelete bool            `json:"retain_delete,omitempty"`  // clear the topic's retained last-value (tombstone)
	Enc          string          `json:"enc,omitempty"`            // payload encoding hint (e.g. "base64")
	ReplyTo      string          `json:"reply_to,omitempty"`       // request/reply: topic for the reply
	Corr         string          `json:"corr,omitempty"`           // request/reply: correlation id echoed on the reply
	Payload      json.RawMessage `json:"payload,omitempty"`
}

type ackFrame struct {
	OK        bool   `json:"ok"`
	Seq       uint64 `json:"seq,omitempty"`
	Error     string `json:"error,omitempty"`
	Truncated bool   `json:"truncated,omitempty"`
}

// brokerBackend adapts a pubsub.Broker to one session.Backend: a single peer
// session that is either a publisher or a subscriber. Reads carry broker->peer
// bytes (acks / events); writes carry peer->broker bytes (hello / publishes).
type brokerBackend struct {
	broker *pubsub.Broker
	ident  pubsub.Identity

	inR  *io.PipeReader // peer -> broker (fed by Write)
	inW  *io.PipeWriter
	outR *io.PipeReader // broker -> peer (drained by Read)
	outW *io.PipeWriter

	mu  sync.Mutex
	sub *pubsub.Subscription

	closeOnce sync.Once
	done      chan struct{}
}

func newBrokerBackend(b *pubsub.Broker, meta session.Meta) *brokerBackend {
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	bb := &brokerBackend{
		broker: b,
		ident:  pubsub.Identity{Key: meta.PeerKey, FQDN: meta.PeerFQDN, Addr: meta.PeerAddr},
		inR:    inR, inW: inW,
		outR: outR, outW: outW,
		done: make(chan struct{}),
	}
	go bb.serve()
	return bb
}

func (bb *brokerBackend) Write(p []byte) (int, error) { return bb.inW.Write(p) }
func (bb *brokerBackend) Read(p []byte) (int, error)  { return bb.outR.Read(p) }

func (bb *brokerBackend) Close() error {
	bb.closeOnce.Do(func() {
		bb.inW.Close() // unblock the serve scanner / input drain
		// Unblock any in-flight outW.Write: if the transport is backpressured
		// (a slow peer, session send buffer full), serveSub can be parked in a
		// write while we wait on done — closing the read end breaks that so
		// serve() can exit and Close() does not deadlock.
		bb.outR.CloseWithError(io.EOF)
		bb.mu.Lock()
		s := bb.sub
		bb.mu.Unlock()
		if s != nil {
			s.Close()
		}
	})
	<-bb.done // serve() closes outW on exit, signalling EOF to the peer
	return nil
}

// serve reads the hello frame and dispatches to the publisher or subscriber
// loop. It always closes outW on exit so the peer sees a clean EOF.
func (bb *brokerBackend) serve() {
	defer close(bb.done)
	defer bb.outW.Close()

	sc := bufio.NewScanner(bb.inR)
	// Size the frame cap from the broker's authoritative payload limit plus
	// envelope headroom, so a within-cap payload always fits in one frame.
	sc.Buffer(make([]byte, 0, 8192), bb.broker.MaxPayloadBytes()+frameEnvelope)
	if !sc.Scan() {
		return // peer closed before a hello
	}
	var hello helloFrame
	if err := json.Unmarshal(sc.Bytes(), &hello); err != nil {
		bb.writeAck(ackFrame{Error: "invalid hello frame: " + err.Error()})
		return
	}
	switch hello.Role {
	case "sub":
		bb.serveSub(hello, sc)
	case "pub":
		bb.servePub(sc, hello.Capability)
	case "stats":
		// Read-only introspection: reply with a stats snapshot and close. Gated
		// only by the connection ACL (no per-topic authorization needed).
		if line, err := json.Marshal(bb.broker.Stats()); err == nil {
			bb.outW.Write(append(line, '\n'))
		}
	default:
		bb.writeAck(ackFrame{Error: "unknown role " + hello.Role + " (want pub, sub, or stats)"})
	}
}

func (bb *brokerBackend) serveSub(hello helloFrame, sc *bufio.Scanner) {
	bp, err := pubsub.ParseBackpressure(hello.Backpressure)
	if err != nil {
		bb.writeAck(ackFrame{Error: err.Error()})
		return
	}
	sub, err := bb.broker.Subscribe(bb.ident, pubsub.SubOptions{
		Topics:       hello.Topics,
		Since:        hello.Since,
		Backpressure: bp,
		Capability:   hello.Capability,
		Group:        hello.Group,
		Ack:          hello.Ack,
	})
	if err != nil {
		bb.writeAck(ackFrame{Error: err.Error()})
		return
	}
	bb.mu.Lock()
	bb.sub = sub
	bb.mu.Unlock()

	if err := bb.writeAck(ackFrame{OK: true, Truncated: sub.Truncated()}); err != nil {
		sub.Close()
		return
	}
	// Read the peer's input side: at-least-once subscribers send ack frames
	// ({"ack":<seq>}) to release in-flight events; any input also lets a
	// client-initiated close end the subscription promptly.
	go func() {
		for sc.Scan() {
			var af ackReqFrame
			if json.Unmarshal(sc.Bytes(), &af) == nil && af.Ack > 0 {
				bb.broker.Ack(sub, af.Ack)
			}
		}
		sub.Close()
	}()
	// Stream events until the subscription ends (unsubscribe, backpressure
	// disconnect, or broker shutdown).
	for ev := range sub.C() {
		line, err := json.Marshal(ev)
		if err != nil {
			continue
		}
		if _, err := bb.outW.Write(append(line, '\n')); err != nil {
			sub.Close()
			return
		}
	}
}

func (bb *brokerBackend) servePub(sc *bufio.Scanner, capToken string) {
	for sc.Scan() {
		var pf pubFrame
		if err := json.Unmarshal(sc.Bytes(), &pf); err != nil {
			if bb.writeAck(ackFrame{Error: "invalid publish frame: " + err.Error()}) != nil {
				return
			}
			continue
		}
		ev, err := bb.broker.PublishOpts(bb.ident, pf.Topic, pf.Payload, pubsub.PublishOptions{
			Labels:       pf.Labels,
			Capability:   capToken,
			Retain:       pf.Retain,
			RetainTTL:    time.Duration(pf.RetainTTLSec) * time.Second,
			RetainDelete: pf.RetainDelete,
			Encoding:     pf.Enc,
			ReplyTo:      pf.ReplyTo,
			Corr:         pf.Corr,
		})
		if err != nil {
			if bb.writeAck(ackFrame{Error: err.Error()}) != nil {
				return
			}
			continue
		}
		if bb.writeAck(ackFrame{OK: true, Seq: ev.Seq}) != nil {
			return
		}
	}
	// Surface a scanner error (e.g. an over-cap frame → bufio.ErrTooLong) as an
	// explicit ack instead of a silent disconnect, so the publisher learns why.
	if err := sc.Err(); err != nil {
		bb.writeAck(ackFrame{Error: "publish frame rejected: " + err.Error()})
	}
}

func (bb *brokerBackend) writeAck(f ackFrame) error {
	line, _ := json.Marshal(f)
	_, err := bb.outW.Write(append(line, '\n'))
	return err
}

// clientStream is the local end of a pub/sub session for the CLI clients. It
// emits a fixed outbound preamble (hello, optionally followed by one publish
// frame), then feeds every complete inbound line to onLine. After the preamble,
// Read either blocks until finish() (the common case) or, if outR is set,
// streams further outbound frames from it (e.g. at-least-once ack frames) until
// outR reaches EOF.
type clientStream struct {
	mu    sync.Mutex
	out   []byte // remaining preamble bytes
	inbuf []byte // partial inbound line

	onLine func(line []byte)
	outR   io.Reader // optional: further outbound frames streamed after the preamble

	done      chan struct{}
	closeOnce sync.Once
}

func (s *clientStream) Read(p []byte) (int, error) {
	s.mu.Lock()
	if len(s.out) > 0 {
		n := copy(p, s.out)
		s.out = s.out[n:]
		s.mu.Unlock()
		return n, nil
	}
	s.mu.Unlock()
	if s.outR != nil {
		// Stream additional outbound frames (acks) until the writer closes; a
		// closed pipe returns EOF, ending the session like finish() would.
		return s.outR.Read(p)
	}
	<-s.done
	return 0, io.EOF
}

func (s *clientStream) Write(p []byte) (int, error) {
	s.mu.Lock()
	s.inbuf = append(s.inbuf, p...)
	var lines [][]byte
	for {
		i := bytes.IndexByte(s.inbuf, '\n')
		if i < 0 {
			break
		}
		lines = append(lines, append([]byte(nil), s.inbuf[:i]...))
		s.inbuf = s.inbuf[i+1:]
	}
	s.mu.Unlock()
	for _, ln := range lines {
		if len(ln) > 0 {
			s.onLine(ln)
		}
	}
	return len(p), nil
}

// finish ends the stream, unblocking Read so the session closes.
func (s *clientStream) finish() { s.closeOnce.Do(func() { close(s.done) }) }

func (s *clientStream) Close() error {
	s.finish()
	return nil
}
