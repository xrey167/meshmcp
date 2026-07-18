package main

import (
	"bufio"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"meshmcp/pubsub"
	"meshmcp/session"
)

func nolog(string, ...any) {}

// readLines drains a brokerBackend's broker->peer side into a channel of
// trimmed JSON lines.
func readLines(t *testing.T, bb *brokerBackend) <-chan string {
	t.Helper()
	ch := make(chan string, 32)
	go func() {
		defer close(ch)
		r := bufio.NewReader(bb)
		for {
			line, err := r.ReadString('\n')
			if s := strings.TrimRight(line, "\n"); s != "" {
				ch <- s
			}
			if err != nil {
				return
			}
		}
	}()
	return ch
}

func nextLine(t *testing.T, ch <-chan string) string {
	t.Helper()
	select {
	case s, ok := <-ch:
		if !ok {
			t.Fatal("stream closed unexpectedly")
		}
		return s
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for a wire line")
		return ""
	}
}

// TestBrokerBackendEndToEnd drives the wire adapter in-process: a subscriber
// session and a publisher session against one broker, exercising hello frames,
// per-publish acks, and event delivery — everything except the mesh transport.
func TestBrokerBackendEndToEnd(t *testing.T) {
	b := pubsub.New(pubsub.Options{Authorizer: pubsub.AllowAll{}})
	defer b.Close()

	sub := newBrokerBackend(b, session.Meta{PeerKey: "s", PeerFQDN: "s.netbird.cloud"}, nolog)
	defer sub.Close()
	subLines := readLines(t, sub)

	hello, _ := json.Marshal(helloFrame{Role: "sub", Topics: []string{"news.*"}})
	if _, err := sub.Write(append(hello, '\n')); err != nil {
		t.Fatal(err)
	}
	// First line is the subscribe ack.
	var ack ackFrame
	if err := json.Unmarshal([]byte(nextLine(t, subLines)), &ack); err != nil || !ack.OK {
		t.Fatalf("bad subscribe ack: %v (%v)", ack, err)
	}

	// Publisher session.
	pub := newBrokerBackend(b, session.Meta{PeerKey: "p", PeerFQDN: "p.netbird.cloud"}, nolog)
	defer pub.Close()
	pubLines := readLines(t, pub)

	ph, _ := json.Marshal(helloFrame{Role: "pub"})
	pf, _ := json.Marshal(pubFrame{Topic: "news.tech", Payload: json.RawMessage(`{"headline":"hi"}`)})
	if _, err := pub.Write(append(append(ph, '\n'), append(pf, '\n')...)); err != nil {
		t.Fatal(err)
	}
	// Publisher gets an ack with a sequence.
	var pack ackFrame
	if err := json.Unmarshal([]byte(nextLine(t, pubLines)), &pack); err != nil || !pack.OK || pack.Seq != 1 {
		t.Fatalf("bad publish ack: %v (%v)", pack, err)
	}

	// Subscriber receives the event, stamped with the publisher's identity.
	var ev pubsub.Event
	if err := json.Unmarshal([]byte(nextLine(t, subLines)), &ev); err != nil {
		t.Fatal(err)
	}
	if ev.Topic != "news.tech" || ev.Publisher != "p" || ev.Seq != 1 {
		t.Fatalf("unexpected delivered event: %+v", ev)
	}
}

// TestBrokerBackendDenied checks a denied publish returns an error ack rather
// than an event.
func TestBrokerBackendDenied(t *testing.T) {
	auth := &pubsub.RuleAuthorizer{} // deny by default
	b := pubsub.New(pubsub.Options{Authorizer: auth})
	defer b.Close()

	pub := newBrokerBackend(b, session.Meta{PeerKey: "p", PeerFQDN: "p.netbird.cloud"}, nolog)
	defer pub.Close()
	lines := readLines(t, pub)

	ph, _ := json.Marshal(helloFrame{Role: "pub"})
	pf, _ := json.Marshal(pubFrame{Topic: "x", Payload: json.RawMessage(`1`)})
	pub.Write(append(append(ph, '\n'), append(pf, '\n')...))

	var ack ackFrame
	json.Unmarshal([]byte(nextLine(t, lines)), &ack)
	if ack.OK || ack.Error == "" {
		t.Fatalf("expected deny ack, got %+v", ack)
	}
}

// TestBrokerBackendCloseUnblocks verifies Close tears the backend down even
// when serve() is parked writing to a peer that has stopped reading (transport
// backpressure). Without closing the read end, Close would deadlock on done.
func TestBrokerBackendCloseUnblocks(t *testing.T) {
	b := pubsub.New(pubsub.Options{Authorizer: pubsub.AllowAll{}, Limits: pubsub.Limits{SubQueue: 2}})
	defer b.Close()

	bb := newBrokerBackend(b, session.Meta{PeerKey: "s", PeerFQDN: "s.netbird.cloud"}, nolog)
	hello, _ := json.Marshal(helloFrame{Role: "sub", Topics: []string{"t"}})
	if _, err := bb.Write(append(hello, '\n')); err != nil {
		t.Fatal(err)
	}
	// Never call bb.Read — the peer is "not reading". Publish enough that
	// serve()'s event loop parks on outW.Write once the pipe backs up.
	for i := 0; i < 50; i++ {
		b.Publish(id2("p"), "t", json.RawMessage(`"x"`), nil)
	}
	done := make(chan struct{})
	go func() { bb.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Close deadlocked while serve() was parked on a blocked write")
	}
}

func id2(k string) pubsub.Identity { return pubsub.Identity{Key: k, FQDN: k + ".netbird.cloud"} }

// TestClientStreamFraming unit-tests the client local stream: it emits the
// preamble, then feeds complete inbound lines (including a split write) to
// onLine, and returns EOF after finish().
func TestClientStreamFraming(t *testing.T) {
	var got []string
	s := &clientStream{out: []byte("hello\n"), done: make(chan struct{})}
	s.onLine = func(line []byte) { got = append(got, string(line)) }

	// Read the preamble.
	buf := make([]byte, 64)
	n, err := s.Read(buf)
	if err != nil || string(buf[:n]) != "hello\n" {
		t.Fatalf("preamble read: %q err=%v", buf[:n], err)
	}
	// Inbound arriving in fragments across the newline boundary.
	s.Write([]byte("li"))
	s.Write([]byte("ne1\nline2\nli"))
	s.Write([]byte("ne3\n"))
	if strings.Join(got, ",") != "line1,line2,line3" {
		t.Fatalf("line framing wrong: %v", got)
	}
	// After finish, Read returns EOF.
	s.finish()
	if _, err := s.Read(buf); err == nil {
		t.Fatal("expected EOF after finish")
	}
}
