package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"meshmcp/policy"
	"meshmcp/pubsub"
	"meshmcp/session"
)

// TestPubsubVerifyCheckpointsCommand checks the CLI verifies signed checkpoints
// end-to-end and rejects a wrong pinned key.
func TestPubsubVerifyCheckpointsCommand(t *testing.T) {
	dir := t.TempDir()
	epath := filepath.Join(dir, "events.jsonl")
	cpath := filepath.Join(dir, "cps.jsonl")
	ef, _ := os.Create(epath)
	cf, _ := os.Create(cpath)
	signer, err := policy.GenerateSigner()
	if err != nil {
		t.Fatal(err)
	}
	cp := policy.NewCheckpointer(signer, cf, 2, func() string { return "t" }, nil)
	el := pubsub.NewEventLog(ef).WithCheckpointer(cp)
	b := pubsub.New(pubsub.Options{Authorizer: pubsub.AllowAll{}, Events: el})
	for i := 0; i < 4; i++ {
		b.Publish(pubsub.Identity{Key: "p"}, "t", nil, nil)
	}
	b.Close()
	el.Flush()
	ef.Close()
	cf.Close()

	if err := cmdPubsubVerify([]string{"--checkpoints", cpath, "--pubkey", signer.PubKeyHex(), epath}); err != nil {
		t.Fatalf("verify with valid checkpoints should pass: %v", err)
	}
	if err := cmdPubsubVerify([]string{"--checkpoints", cpath, "--pubkey", "00", epath}); err == nil {
		t.Fatal("verify with wrong pinned pubkey should fail")
	}
}

// TestDurableCursor checks the subscriber cursor round-trips and that a missing
// or corrupt cursor is treated as "start from the beginning".
func TestDurableCursor(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cursor")
	if _, ok := readCursor(path); ok {
		t.Fatal("missing cursor should not be ok")
	}
	if err := writeCursor(path, 42); err != nil {
		t.Fatal(err)
	}
	if seq, ok := readCursor(path); !ok || seq != 42 {
		t.Fatalf("cursor round-trip: seq=%d ok=%v", seq, ok)
	}
	// Overwrite advances it (atomic replace).
	if err := writeCursor(path, 100); err != nil {
		t.Fatal(err)
	}
	if seq, _ := readCursor(path); seq != 100 {
		t.Fatalf("cursor after overwrite = %d, want 100", seq)
	}
	// A corrupt file reads as not-ok.
	os.WriteFile(path, []byte("not-a-number"), 0o600)
	if _, ok := readCursor(path); ok {
		t.Fatal("corrupt cursor should not be ok")
	}
}

// TestStreamPubSinkCounts checks the streaming publisher tallies per-event acks
// (including across a split write).
func TestStreamPubSinkCounts(t *testing.T) {
	s := &streamPubSink{}
	s.Write([]byte(`{"ok":true,"seq":1}` + "\n" + `{"ok":true,"seq":2}` + "\n"))
	s.Write([]byte(`{"error":"denied by pubsub policy"}`)) // no newline yet
	s.Write([]byte("\n"))
	ok, fail, last := s.counts()
	if ok != 2 || fail != 1 || last != "denied by pubsub policy" {
		t.Fatalf("ok=%d fail=%d last=%q", ok, fail, last)
	}
}

// TestBrokerBackendStreamingPublish verifies many publishes ride one session
// (the streaming producer path) and all reach a subscriber.
func TestBrokerBackendStreamingPublish(t *testing.T) {
	b := pubsub.New(pubsub.Options{Authorizer: pubsub.AllowAll{}})
	defer b.Close()

	sub := newBrokerBackend(b, session.Meta{PeerKey: "s", PeerFQDN: "s.netbird.cloud"})
	defer sub.Close()
	subLines := readLines(t, sub)
	subHello, _ := json.Marshal(helloFrame{Role: "sub", Topics: []string{"feed"}})
	sub.Write(append(subHello, '\n'))
	nextLine(t, subLines) // subscribe ack

	pub := newBrokerBackend(b, session.Meta{PeerKey: "p", PeerFQDN: "p.netbird.cloud"})
	defer pub.Close()
	pubLines := readLines(t, pub)
	ph, _ := json.Marshal(helloFrame{Role: "pub"})
	pub.Write(append(ph, '\n'))
	for i := 0; i < 3; i++ {
		pf, _ := json.Marshal(pubFrame{Topic: "feed", Payload: json.RawMessage(fmt.Sprintf(`%d`, i))})
		pub.Write(append(pf, '\n'))
	}
	for i := 0; i < 3; i++ {
		var ack ackFrame
		json.Unmarshal([]byte(nextLine(t, pubLines)), &ack)
		if !ack.OK || ack.Seq != uint64(i+1) {
			t.Fatalf("publish %d ack: %+v", i, ack)
		}
	}
	for i := 0; i < 3; i++ {
		var ev pubsub.Event
		json.Unmarshal([]byte(nextLine(t, subLines)), &ev)
		if ev.Topic != "feed" || ev.Seq != uint64(i+1) {
			t.Fatalf("delivered event %d: %+v", i, ev)
		}
	}
}

// TestPubsubVerifyCommand checks the `meshmcp pubsub verify` path end-to-end:
// it accepts a valid persisted log and rejects a tampered one.
func TestPubsubVerifyCommand(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	b := pubsub.New(pubsub.Options{Authorizer: pubsub.AllowAll{}, Events: pubsub.NewEventLog(f)})
	for i := 0; i < 3; i++ {
		if _, err := b.Publish(pubsub.Identity{Key: "p"}, "t", nil, nil); err != nil {
			t.Fatal(err)
		}
	}
	b.Close()
	f.Close()

	if err := cmdPubsubVerify([]string{path}); err != nil {
		t.Fatalf("verify of a valid log should pass: %v", err)
	}

	data, _ := os.ReadFile(path)
	if err := os.WriteFile(path, append([]byte("GARBAGE\n"), data...), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := cmdPubsubVerify([]string{path}); err == nil {
		t.Fatal("verify of a tampered log should fail")
	}
}

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

	sub := newBrokerBackend(b, session.Meta{PeerKey: "s", PeerFQDN: "s.netbird.cloud"})
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
	pub := newBrokerBackend(b, session.Meta{PeerKey: "p", PeerFQDN: "p.netbird.cloud"})
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

// TestBrokerBackendStats verifies the stats wire role returns a broker snapshot.
func TestBrokerBackendStats(t *testing.T) {
	b := pubsub.New(pubsub.Options{Authorizer: pubsub.AllowAll{}})
	defer b.Close()
	// A subscription and a couple of publishes so the snapshot is non-trivial.
	s, _ := b.Subscribe(pubsub.Identity{Key: "x"}, pubsub.SubOptions{Topics: []string{"t"}})
	defer s.Close()
	b.Publish(pubsub.Identity{Key: "p"}, "t", nil, nil)
	b.Publish(pubsub.Identity{Key: "p"}, "t", nil, nil)

	q := newBrokerBackend(b, session.Meta{PeerKey: "op", PeerFQDN: "op.netbird.cloud"})
	defer q.Close()
	lines := readLines(t, q)
	hello, _ := json.Marshal(helloFrame{Role: "stats"})
	q.Write(append(hello, '\n'))

	var st pubsub.Stats
	if err := json.Unmarshal([]byte(nextLine(t, lines)), &st); err != nil {
		t.Fatal(err)
	}
	if st.Subscriptions != 1 || st.Sequence != 2 {
		t.Fatalf("unexpected stats: %+v", st)
	}
}

// TestBrokerBackendDenied checks a denied publish returns an error ack rather
// than an event.
func TestBrokerBackendDenied(t *testing.T) {
	auth := &pubsub.RuleAuthorizer{} // deny by default
	b := pubsub.New(pubsub.Options{Authorizer: auth})
	defer b.Close()

	pub := newBrokerBackend(b, session.Meta{PeerKey: "p", PeerFQDN: "p.netbird.cloud"})
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

	bb := newBrokerBackend(b, session.Meta{PeerKey: "s", PeerFQDN: "s.netbird.cloud"})
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
