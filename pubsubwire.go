package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"sync"

	"meshmcp/pubsub"
	"meshmcp/session"
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

// maxFrame bounds a single wire frame so a hostile peer cannot force the
// broker to buffer an unbounded line in memory.
const maxFrame = 1 << 20 // 1 MiB

type helloFrame struct {
	Role         string   `json:"role"` // "pub" | "sub"
	Topics       []string `json:"topics,omitempty"`
	Since        uint64   `json:"since,omitempty"`
	Backpressure string   `json:"backpressure,omitempty"`
}

type pubFrame struct {
	Topic   string          `json:"topic"`
	Labels  []string        `json:"labels,omitempty"`
	Payload json.RawMessage `json:"payload,omitempty"`
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
	logf   func(string, ...any)

	inR  *io.PipeReader // peer -> broker (fed by Write)
	inW  *io.PipeWriter
	outR *io.PipeReader // broker -> peer (drained by Read)
	outW *io.PipeWriter

	mu  sync.Mutex
	sub *pubsub.Subscription

	closeOnce sync.Once
	done      chan struct{}
}

func newBrokerBackend(b *pubsub.Broker, meta session.Meta, logf func(string, ...any)) *brokerBackend {
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	bb := &brokerBackend{
		broker: b,
		ident:  pubsub.Identity{Key: meta.PeerKey, FQDN: meta.PeerFQDN, Addr: meta.PeerAddr},
		logf:   logf,
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
	sc.Buffer(make([]byte, 0, 8192), maxFrame)
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
		bb.servePub(sc)
	default:
		bb.writeAck(ackFrame{Error: "unknown role " + hello.Role + " (want pub or sub)"})
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
	// Drain the peer's input side so a client-initiated close ends the
	// subscription promptly.
	go func() {
		for sc.Scan() {
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

func (bb *brokerBackend) servePub(sc *bufio.Scanner) {
	for sc.Scan() {
		var pf pubFrame
		if err := json.Unmarshal(sc.Bytes(), &pf); err != nil {
			if bb.writeAck(ackFrame{Error: "invalid publish frame: " + err.Error()}) != nil {
				return
			}
			continue
		}
		ev, err := bb.broker.Publish(bb.ident, pf.Topic, pf.Payload, pf.Labels)
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
}

func (bb *brokerBackend) writeAck(f ackFrame) error {
	line, _ := json.Marshal(f)
	_, err := bb.outW.Write(append(line, '\n'))
	return err
}

// clientStream is the local end of a pub/sub session for the CLI clients. It
// emits a fixed outbound preamble (hello, optionally followed by one publish
// frame), then feeds every complete inbound line to onLine. Read blocks after
// the preamble until finish() is called, at which point it returns EOF to end
// the session gracefully.
type clientStream struct {
	mu    sync.Mutex
	out   []byte // remaining preamble bytes
	inbuf []byte // partial inbound line

	onLine func(line []byte)

	done      chan struct{}
	closeOnce sync.Once
}

func newClientStream(preamble []byte, onLine func([]byte)) *clientStream {
	return &clientStream{out: preamble, onLine: onLine, done: make(chan struct{})}
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
