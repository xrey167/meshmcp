package pubsub

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"meshmcp/policy"
)

// TestEventCheckpoints verifies signed Merkle checkpoints over the event stream:
// a valid stream + key verifies; a wrong key or an altered event set fails.
func TestEventCheckpoints(t *testing.T) {
	signer, err := policy.GenerateSigner()
	if err != nil {
		t.Fatal(err)
	}
	var events, cps bytes.Buffer
	cp := policy.NewCheckpointer(signer, &cps, 2, func() string { return "t" }, nil)
	el := NewEventLog(&events).WithCheckpointer(cp)
	b := New(Options{Authorizer: AllowAll{}, Events: el})
	for i := 0; i < 5; i++ {
		if _, err := b.Publish(id("p"), "t", nil, nil); err != nil {
			t.Fatal(err)
		}
	}
	b.Close()
	el.Flush() // seal the final partial batch (event 5)

	evs, err := LoadEvents(bytes.NewReader(events.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	n, err := VerifyCheckpoints(evs, bytes.NewReader(cps.Bytes()), signer.PubKeyHex())
	if err != nil {
		t.Fatalf("valid checkpoints should verify: %v", err)
	}
	if n != 3 { // checkpoints at 2, 4, and the flushed 5
		t.Fatalf("verified %d checkpoints, want 3", n)
	}

	// Pinning the wrong signer fails.
	if _, err := VerifyCheckpoints(evs, bytes.NewReader(cps.Bytes()), "00"); err == nil {
		t.Fatal("wrong pinned pubkey should fail")
	}

	// Altering an event's hash (valid hex, different value) breaks the Merkle
	// root of the checkpoint covering it.
	tampered := append([]Event(nil), evs...)
	tampered[2].Hash = strings.Repeat("0", len(tampered[2].Hash))
	if _, err := VerifyCheckpoints(tampered, bytes.NewReader(cps.Bytes()), signer.PubKeyHex()); err == nil {
		t.Fatal("altered event set should fail checkpoint verification")
	}
}

// TestVerifyCheckpointsRejectsHostileSpan verifies the coverage-span bound: a
// validly-signed checkpoint whose [FromSeq,ToSeq] span is implausibly large is
// rejected before it can drive a huge allocation (make of ~1e9 leaves) or index
// past the loaded events. Defense-in-depth against a crafted or corrupt file.
func TestVerifyCheckpointsRejectsHostileSpan(t *testing.T) {
	signer, err := policy.GenerateSigner()
	if err != nil {
		t.Fatal(err)
	}
	var cps bytes.Buffer
	cp := policy.NewCheckpointer(signer, &cps, 1000, func() string { return "t" }, nil)
	leaf := strings.Repeat("ab", 32) // 64 hex chars, a valid hash leaf
	cp.Add(1, leaf)
	cp.Flush(1_000_000_000, leaf) // ToSeq far beyond any real event count

	// The checkpoint is legitimately signed, so it passes signature verification;
	// the span bound must then reject it rather than allocating ~1e9 entries.
	if _, err := VerifyCheckpoints([]Event{}, bytes.NewReader(cps.Bytes()), signer.PubKeyHex()); err == nil {
		t.Fatal("hostile coverage span should be rejected, not verified")
	}
}

// TestVerifyCheckpointsEmpty documents the core contract: an empty checkpoints
// stream verifies zero checkpoints without error (the CLI layer treats n==0 as
// "no proof" and errors there, so a --checkpoints file can't silently prove
// nothing).
func TestVerifyCheckpointsEmpty(t *testing.T) {
	n, err := VerifyCheckpoints(nil, strings.NewReader(""), "")
	if err != nil || n != 0 {
		t.Fatalf("empty checkpoints: n=%d err=%v, want 0/nil", n, err)
	}
}

// TestEventLogRoundTrip persists a published stream and reloads it, verifying
// the chain survives the file boundary.
func TestEventLogRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	b := New(Options{Authorizer: AllowAll{}, Events: NewEventLog(&buf)})
	for i := 0; i < 20; i++ {
		body, _ := json.Marshal(i)
		if _, err := b.Publish(id("p"), "t", body, nil); err != nil {
			t.Fatal(err)
		}
	}
	b.Close()

	events, err := LoadEvents(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("LoadEvents: %v", err)
	}
	if len(events) != 20 {
		t.Fatalf("loaded %d events, want 20", len(events))
	}
	if err := VerifyChain(events); err != nil {
		t.Fatalf("persisted chain must verify: %v", err)
	}
	// The persisted stream matches the broker's in-memory retained window.
	if events[19].Seq != 20 {
		t.Fatalf("last persisted seq %d, want 20", events[19].Seq)
	}
}

// TestBrokerResumeFromLog is the durability guarantee: a broker restart
// continues the sequence and hash chain from the persisted log, and --since
// replay works across the restart.
func TestBrokerResumeFromLog(t *testing.T) {
	var buf bytes.Buffer
	b1 := New(Options{Authorizer: AllowAll{}, Events: NewEventLog(&buf), Limits: Limits{Retain: 100}})
	for i := 0; i < 5; i++ {
		b1.Publish(id("p"), "t", nil, nil)
	}
	b1.Close()

	// "Restart": load the persisted stream and seed a fresh broker that keeps
	// appending to the same log.
	seed, err := LoadEvents(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	b2 := New(Options{Authorizer: AllowAll{}, Events: NewEventLog(&buf), Seed: seed, Limits: Limits{Retain: 100}})
	defer b2.Close()

	if b2.Seq() != 5 {
		t.Fatalf("resumed seq %d, want 5", b2.Seq())
	}
	// A subscriber can replay across the restart from the seeded ring.
	sub, err := b2.Subscribe(id("s"), SubOptions{Topics: []string{"t"}, Since: 3})
	if err != nil {
		t.Fatal(err)
	}
	defer sub.Close()
	for _, want := range []uint64{4, 5} {
		if ev := recv(t, sub); ev.Seq != want {
			t.Fatalf("replay seq %d want %d", ev.Seq, want)
		}
	}

	// New publishes continue the same chain; reloading the whole file verifies.
	ev, err := b2.Publish(id("p"), "t", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if ev.Seq != 6 {
		t.Fatalf("post-restart publish seq %d, want 6", ev.Seq)
	}
	all, err := LoadEvents(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("reload after restart: %v", err)
	}
	if len(all) != 6 || all[5].Seq != 6 {
		t.Fatalf("reloaded %d events (last seq %d), want 6/6", len(all), all[5].Seq)
	}
	if err := VerifyChain(all); err != nil {
		t.Fatalf("chain across restart must verify: %v", err)
	}
}

// TestLoadEventsTornTail tolerates a crash mid-append (garbage last line) but
// rejects an interior break.
func TestLoadEventsTornTail(t *testing.T) {
	var buf bytes.Buffer
	b := New(Options{Authorizer: AllowAll{}, Events: NewEventLog(&buf)})
	for i := 0; i < 3; i++ {
		b.Publish(id("p"), "t", nil, nil)
	}
	b.Close()

	// A torn trailing write is tolerated.
	torn := buf.String() + `{"topic":"t","seq":4,"prev`
	events, err := LoadEvents(strings.NewReader(torn))
	if err != nil {
		t.Fatalf("torn tail should be tolerated: %v", err)
	}
	if len(events) != 3 {
		t.Fatalf("loaded %d, want 3", len(events))
	}

	// Garbage BEFORE the end is a corruption/tamper signal.
	interior := "GARBAGE\n" + buf.String()
	if _, err := LoadEvents(strings.NewReader(interior)); err == nil {
		t.Fatal("interior unparseable line should be rejected")
	}
}

// TestLoadEventsTamperRejected verifies an edited persisted event breaks the load.
func TestLoadEventsTamperRejected(t *testing.T) {
	var buf bytes.Buffer
	b := New(Options{Authorizer: AllowAll{}, Events: NewEventLog(&buf)})
	for i := 0; i < 4; i++ {
		body, _ := json.Marshal(i)
		b.Publish(id("p"), "t", body, nil)
	}
	b.Close()

	// Flip a byte in the middle of the stream.
	raw := buf.Bytes()
	tampered := bytes.Replace(raw, []byte(`"payload":0`), []byte(`"payload":9`), 1)
	if bytes.Equal(raw, tampered) {
		t.Fatal("test setup: nothing tampered")
	}
	if _, err := LoadEvents(bytes.NewReader(tampered)); err == nil {
		t.Fatal("tampered event log should fail to load")
	}
}
