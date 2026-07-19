package pubsub

import "testing"

func mkEvents(seqs ...uint64) []Event {
	out := make([]Event, len(seqs))
	for i, s := range seqs {
		out[i] = Event{Seq: s}
	}
	return out
}

func TestRingWrap(t *testing.T) {
	r := newRing(3)
	for i := uint64(1); i <= 5; i++ {
		r.add(Event{Seq: i})
	}
	snap := r.snapshot()
	if len(snap) != 3 || snap[0].Seq != 3 || snap[2].Seq != 5 {
		t.Fatalf("ring wrap wrong: %+v", snap)
	}
}

func TestRingSince(t *testing.T) {
	r := newRing(5)
	for i := uint64(1); i <= 8; i++ { // retains 4..8
		r.add(Event{Seq: i})
	}
	// After 6 → 7,8 with no truncation.
	ev, trunc := r.since(6)
	if trunc || len(ev) != 2 || ev[0].Seq != 7 {
		t.Fatalf("since(6)=%+v trunc=%v", ev, trunc)
	}
	// After 1 → 4..8, truncated (1..3 gone).
	ev, trunc = r.since(1)
	if !trunc || len(ev) != 5 || ev[0].Seq != 4 {
		t.Fatalf("since(1)=%+v trunc=%v", ev, trunc)
	}
	// After the newest → empty, not truncated.
	ev, trunc = r.since(8)
	if trunc || len(ev) != 0 {
		t.Fatalf("since(8)=%+v trunc=%v", ev, trunc)
	}
}

func TestRingZeroRetention(t *testing.T) {
	r := newRing(0)
	r.add(Event{Seq: 1})
	if len(r.snapshot()) != 0 {
		t.Fatal("zero-capacity ring must retain nothing")
	}
	ev, trunc := r.since(0)
	if len(ev) != 0 || trunc {
		t.Fatalf("empty ring since: %+v trunc=%v", ev, trunc)
	}
}

func TestVerifyChainEmpty(t *testing.T) {
	if err := VerifyChain(nil); err != nil {
		t.Fatalf("empty chain should verify: %v", err)
	}
}
