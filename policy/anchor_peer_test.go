package policy

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// witnessStub records posted checkpoints and can be forced down.
type witnessStub struct {
	mu       sync.Mutex
	down     bool
	received []Checkpoint
}

func (w *witnessStub) handler() http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		w.mu.Lock()
		defer w.mu.Unlock()
		if w.down {
			http.Error(rw, "witness down", http.StatusServiceUnavailable)
			return
		}
		var cp Checkpoint
		if err := json.NewDecoder(r.Body).Decode(&cp); err != nil {
			http.Error(rw, err.Error(), http.StatusBadRequest)
			return
		}
		w.received = append(w.received, cp)
		rw.WriteHeader(http.StatusOK)
	})
}

func (w *witnessStub) seqs() []int {
	w.mu.Lock()
	defer w.mu.Unlock()
	var out []int
	for _, cp := range w.received {
		out = append(out, cp.Seq)
	}
	return out
}

func (w *witnessStub) setDown(d bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.down = d
}

// waitFor polls cond until it holds or the deadline passes — delivery is
// asynchronous, so tests observe its effects with a bounded wait.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// waitIdle waits until no deliverer goroutine is active, so a test can flip
// witness state without racing an in-flight drain.
func waitIdle(t *testing.T, p *PeerAnchor) {
	t.Helper()
	waitFor(t, "peer anchor deliverer to go idle", func() bool {
		p.mu.Lock()
		defer p.mu.Unlock()
		return !p.draining
	})
}

// TestPeerAnchorPostsCheckpoint: a healthy witness receives the full signed
// checkpoint after every flush (delivery is asynchronous), and the checkpoint
// lands durably regardless.
func TestPeerAnchorPostsCheckpoint(t *testing.T) {
	stub := &witnessStub{}
	ts := httptest.NewServer(stub.handler())
	defer ts.Close()

	signer := mustSigner(t)
	sink := &bytes.Buffer{}
	cp := NewCheckpointer(signer, sink, 2, func() string { return "T" }, NewPeerAnchor(ts.URL))
	cp.Add(1, testLeafHex(1))
	cp.Add(2, testLeafHex(2))

	waitFor(t, "witness to receive checkpoint 1", func() bool { return len(stub.seqs()) == 1 })
	if got := stub.seqs(); got[0] != 1 {
		t.Fatalf("witness must receive checkpoint 1, got %v", got)
	}
	stub.mu.Lock()
	rec := stub.received[0]
	stub.mu.Unlock()
	if err := VerifyCheckpoint(rec, signer.PubKeyHex()); err != nil {
		t.Fatalf("witnessed checkpoint must be the full signed checkpoint: %v", err)
	}
}

// TestPeerAnchorWitnessDownDoesNotBlock: the checkpoint is durably written
// immediately when the witness is unreachable, the failure surfaces through
// the anchor's error handler, and the queued checkpoint is delivered (in
// order) once the witness recovers.
func TestPeerAnchorWitnessDownDoesNotBlock(t *testing.T) {
	stub := &witnessStub{down: true}
	ts := httptest.NewServer(stub.handler())
	defer ts.Close()

	signer := mustSigner(t)
	sink := &bytes.Buffer{}
	var errMu sync.Mutex
	var errs []error
	pa := NewPeerAnchor(ts.URL).WithErrorHandler(func(err error) {
		errMu.Lock()
		defer errMu.Unlock()
		errs = append(errs, err)
	})
	errCount := func() int {
		errMu.Lock()
		defer errMu.Unlock()
		return len(errs)
	}
	c := NewCheckpointer(signer, sink, 1, func() string { return "T" }, pa)

	c.Add(1, testLeafHex(1)) // witness down: checkpoint 1 queues in the background
	if got := len(parseCheckpoints(t, sink.String())); got != 1 {
		t.Fatalf("checkpoint must be durably written despite the witness being down, got %d", got)
	}
	waitFor(t, "witness failure to surface", func() bool { return errCount() == 1 })
	errMu.Lock()
	firstErr := errs[0]
	errMu.Unlock()
	if !strings.Contains(firstErr.Error(), "queued for retry") {
		t.Fatalf("witness failure must surface via the error handler: %v", firstErr)
	}
	if got := stub.seqs(); len(got) != 0 {
		t.Fatalf("nothing should be witnessed while down, got %v", got)
	}

	waitIdle(t, pa)
	stub.setDown(false)
	c.Add(2, testLeafHex(2)) // recovery: flushes queued 1, then 2, in order
	waitFor(t, "recovery to flush the queue", func() bool { return len(stub.seqs()) == 2 })
	if got := stub.seqs(); got[0] != 1 || got[1] != 2 {
		t.Fatalf("recovery must flush the queue in order, got %v", got)
	}
	waitIdle(t, pa)
	if got := errCount(); got != 1 {
		t.Fatalf("no new errors after recovery, got %d", got)
	}
}

// TestPeerAnchorSlowWitnessDoesNotBlockFlush pins the enforcement-path bound:
// the Checkpointer flush (and thus the audit write that triggered it) must
// return while the witness is still holding the request open. A tarpitting or
// overloaded witness may delay WITNESSING, never a checkpoint or an audited
// call.
func TestPeerAnchorSlowWitnessDoesNotBlockFlush(t *testing.T) {
	release := make(chan struct{})
	received := make(chan Checkpoint, 1)
	ts := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		var cp Checkpoint
		if err := json.NewDecoder(r.Body).Decode(&cp); err != nil {
			http.Error(rw, err.Error(), http.StatusBadRequest)
			return
		}
		<-release // park the request: the witness is up but unboundedly slow
		select {
		case received <- cp:
		default:
		}
		rw.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	signer := mustSigner(t)
	sink := &bytes.Buffer{}
	c := NewCheckpointer(signer, sink, 1, func() string { return "T" }, NewPeerAnchor(ts.URL))

	flushed := make(chan struct{})
	go func() {
		c.Add(1, testLeafHex(1)) // triggers the flush and the witness POST
		close(flushed)
	}()
	select {
	case <-flushed:
		// The flush returned while the witness request is still parked.
	case <-time.After(3 * time.Second):
		t.Fatal("checkpoint flush must not wait on a slow witness")
	}
	if got := len(parseCheckpoints(t, sink.String())); got != 1 {
		t.Fatalf("checkpoint must be durably written while the witness stalls, got %d", got)
	}

	close(release) // witness finally answers; delivery completes in the background
	select {
	case cp := <-received:
		if cp.Seq != 1 {
			t.Fatalf("witness must eventually receive checkpoint 1, got %d", cp.Seq)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("delivery must complete once the witness responds")
	}
}

// TestPeerAnchorQueueOverflowDropsOldest: past the pending cap the oldest
// checkpoint is dropped and the drop is reported synchronously from Anchor —
// never silent.
func TestPeerAnchorQueueOverflowDropsOldest(t *testing.T) {
	stub := &witnessStub{down: true}
	ts := httptest.NewServer(stub.handler())
	defer ts.Close()

	signer := mustSigner(t)
	pa := NewPeerAnchor(ts.URL)
	mk := func(seq int) Checkpoint {
		return signer.sign(Checkpoint{Version: 1, Seq: seq, FromSeq: seq, ToSeq: seq, Count: 1, MerkleRoot: "aa", ChainHead: "bb", Time: "T"})
	}
	for i := 1; i <= peerAnchorMaxPending; i++ {
		if err := pa.Anchor(mk(i)); err != nil {
			t.Fatalf("enqueue below the cap must not error (failures are async): %v", err)
		}
	}
	waitIdle(t, pa) // all background posts have failed; queue is 1..cap
	err := pa.Anchor(mk(peerAnchorMaxPending + 1))
	if err == nil || !strings.Contains(err.Error(), "dropped 1 oldest") {
		t.Fatalf("overflow must report the dropped checkpoint: %v", err)
	}

	// Recovery: adding checkpoint cap+2 overflows once more (dropping seq 2 —
	// reported again, never silent) and then the deliverer flushes the retained
	// window 3..cap+2 in order.
	waitIdle(t, pa)
	stub.setDown(false)
	err = pa.Anchor(mk(peerAnchorMaxPending + 2))
	if err == nil || !strings.Contains(err.Error(), "dropped 1 oldest") {
		t.Fatalf("the drop during recovery must still be reported: %v", err)
	}
	waitFor(t, "retained window to flush", func() bool { return len(stub.seqs()) == peerAnchorMaxPending })
	got := stub.seqs()
	if got[0] != 3 || got[len(got)-1] != peerAnchorMaxPending+2 {
		t.Fatalf("retained window wrong: first %d last %d count %d", got[0], got[len(got)-1], len(got))
	}
	// A subsequent anchor with an empty queue is delivered cleanly.
	waitIdle(t, pa)
	if err := pa.Anchor(mk(peerAnchorMaxPending + 3)); err != nil {
		t.Fatalf("healthy anchor after recovery must be clean: %v", err)
	}
	waitFor(t, "post-recovery anchor to deliver", func() bool { return len(stub.seqs()) == peerAnchorMaxPending+1 })
}

// TestPeerAnchorPostSynchronous: Post (the `audit anchor --url` replay path)
// bypasses the queue and returns the witness's verdict synchronously.
func TestPeerAnchorPostSynchronous(t *testing.T) {
	stub := &witnessStub{down: true}
	ts := httptest.NewServer(stub.handler())
	defer ts.Close()

	signer := mustSigner(t)
	pa := NewPeerAnchor(ts.URL)
	cp := signer.sign(Checkpoint{Version: 1, Seq: 1, FromSeq: 1, ToSeq: 1, Count: 1, MerkleRoot: "aa", ChainHead: "bb", Time: "T"})
	if err := pa.Post(cp); err == nil || !strings.Contains(err.Error(), "witness returned") {
		t.Fatalf("Post against a down witness must return its verdict: %v", err)
	}
	stub.setDown(false)
	if err := pa.Post(cp); err != nil {
		t.Fatalf("Post against a healthy witness must succeed: %v", err)
	}
	if got := stub.seqs(); len(got) != 1 || got[0] != 1 {
		t.Fatalf("Post must deliver synchronously, got %v", got)
	}
}
