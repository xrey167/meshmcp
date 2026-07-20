package main

import (
	"bufio"
	"encoding/json"
	"io"
	"testing"
	"time"

	"meshmcp/pubsub"
	"meshmcp/session"
)

// TestWirePublishCarriesOptions verifies the publish wire path (servePub) maps
// every pubFrame facet — retain, TTL, tombstone, reply_to, corr, encoding —
// into the broker's PublishOptions, so a feature added to the frame actually
// reaches the core. The event is captured through a direct subscription.
func TestWirePublishCarriesOptions(t *testing.T) {
	b := pubsub.New(pubsub.Options{Authorizer: pubsub.AllowAll{}})
	defer b.Close()
	sub, err := b.Subscribe(pubsub.Identity{Key: "s"}, pubsub.SubOptions{Topics: []string{"rpc.x"}})
	if err != nil {
		t.Fatal(err)
	}
	defer sub.Close()

	bb := newBrokerBackend(b, session.Meta{PeerKey: "pub", PeerFQDN: "pub.netbird.cloud"})
	defer bb.Close()

	hello, _ := json.Marshal(helloFrame{Role: "pub"})
	f1, _ := json.Marshal(pubFrame{
		Topic: "rpc.x", Retain: true, RetainTTLSec: 60,
		ReplyTo: "_rpc.reply.1", Corr: "c1", Enc: "base64", Payload: json.RawMessage(`"hi"`),
	})
	f2, _ := json.Marshal(pubFrame{Topic: "rpc.x", RetainDelete: true, Payload: json.RawMessage(`null`)})
	// Drain the broker->peer acks so servePub is never parked on an ack write
	// and keeps reading subsequent frames.
	go io.Copy(io.Discard, bb)
	go func() {
		bb.Write(append(hello, '\n'))
		bb.Write(append(f1, '\n'))
		bb.Write(append(f2, '\n'))
	}()

	// First event: all options carried through.
	select {
	case ev := <-sub.C():
		if !ev.Retain || ev.ExpiresAt == "" || ev.ReplyTo != "_rpc.reply.1" || ev.Corr != "c1" || ev.Enc != "base64" {
			t.Fatalf("wire publish dropped options: %+v", ev)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no event via the wire publish path")
	}
	// Second event: the tombstone flag is carried through too.
	select {
	case ev := <-sub.C():
		if !ev.RetainDel {
			t.Fatalf("wire publish dropped retain_delete: %+v", ev)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no tombstone event via the wire publish path")
	}
}

// TestWireSubscribeGroup verifies the subscribe wire path (serveSub) threads the
// consumer-group name into SubOptions: two grouped subscribers register as one
// active group on the broker.
func TestWireSubscribeGroup(t *testing.T) {
	b := pubsub.New(pubsub.Options{Authorizer: pubsub.AllowAll{}})
	defer b.Close()

	join := func(key string) {
		bb := newBrokerBackend(b, session.Meta{PeerKey: key, PeerFQDN: key + ".netbird.cloud"})
		t.Cleanup(func() { bb.Close() })
		hello, _ := json.Marshal(helloFrame{Role: "sub", Topics: []string{"jobs"}, Group: "workers"})
		go bb.Write(append(hello, '\n'))
		// Reading the subscribe ack confirms Subscribe returned, so the group
		// membership is registered before we inspect Stats.
		sc := bufio.NewScanner(bb)
		if !sc.Scan() {
			t.Fatalf("no subscribe ack for %s", key)
		}
		var ack ackFrame
		if json.Unmarshal(sc.Bytes(), &ack) != nil || ack.Error != "" {
			t.Fatalf("grouped subscribe for %s rejected: %q", key, ack.Error)
		}
	}
	join("a")
	join("b")

	st := b.Stats()
	if st.Subscriptions != 2 {
		t.Fatalf("subscriptions=%d, want 2", st.Subscriptions)
	}
	if st.Groups != 1 {
		t.Fatalf("groups=%d, want 1 (both subscribers share one group — proves serveSub passed Group through)", st.Groups)
	}
}
