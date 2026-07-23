package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// peerAnchorMaxPending bounds the in-memory retry queue. The checkpoints file
// itself is the durable replay source (`meshmcp audit anchor` re-posts every
// checkpoint idempotently), so an overflow drops the oldest pending entry and
// reports it rather than growing without bound.
const peerAnchorMaxPending = 64

// peerAnchorTimeout bounds one witness POST by the background deliverer. It is
// a per-post bound, not a bound on Anchor itself: Anchor only enqueues and
// never waits on the network.
const peerAnchorTimeout = 5 * time.Second

// PeerAnchor publishes each checkpoint to a peer gateway's witness endpoint
// (POST of the full checkpoint JSON to /v1/anchor on the peer's control
// plane). The witness verifies the signature against its pinned signer keys
// and appends the checkpoint to its own append-only, self-linked anchor file —
// so once a checkpoint head is witnessed, an insider who rolls the local log
// and checkpoints back together is still caught at verify time.
//
// Delivery is ASYNCHRONOUS and best-effort. The Checkpointer calls Anchor
// inside the audit write path's critical section (AuditLog.write holds its
// mutex through the checkpoint flush), so a slow or dead witness must never
// stall enforcement: Anchor only appends to a bounded in-order queue and
// returns. A single background deliverer posts queued checkpoints in order,
// one peerAnchorTimeout-bounded POST at a time; on a post failure the queue is
// retained and delivery resumes on the next Anchor call (retry pacing follows
// the checkpoint cadence instead of hot-looping against a down witness).
//
// Post failures surface through WithErrorHandler — Anchor has already returned
// by the time they happen. Anchor's own return value reports only overflow
// drops, which are known at enqueue time. The durable fallback after an outage
// is `meshmcp audit anchor`, which replays the whole checkpoints file (the
// witness dedups by signer, ordinal, and hash).
type PeerAnchor struct {
	URL     string
	Client  *http.Client
	onError func(error)

	mu       sync.Mutex
	pending  []Checkpoint // in-order delivery/retry queue
	draining bool         // a deliverer goroutine is active
}

// NewPeerAnchor builds a PeerAnchor posting to url with a short per-post
// timeout.
func NewPeerAnchor(url string) *PeerAnchor {
	return &PeerAnchor{URL: url, Client: &http.Client{Timeout: peerAnchorTimeout}}
}

// WithErrorHandler surfaces asynchronous delivery failures. Anchor returns
// before the POST happens, so a post error cannot be returned from it; without
// a handler it would be silent, and a silent anchor failure is dangerous (the
// witness is the one control against a key-holding insider).
func (p *PeerAnchor) WithErrorHandler(fn func(error)) *PeerAnchor {
	p.onError = fn
	return p
}

func (p *PeerAnchor) report(err error) {
	if err != nil && p.onError != nil {
		p.onError(err)
	}
}

// Anchor enqueues c for in-order background delivery and returns without
// touching the network. The returned error reports only an overflow drop
// (oldest pending checkpoints displaced by a full queue); delivery failures
// surface via WithErrorHandler.
func (p *PeerAnchor) Anchor(c Checkpoint) error {
	p.mu.Lock()
	p.pending = append(p.pending, c)
	dropped := 0
	for len(p.pending) > peerAnchorMaxPending {
		p.pending = p.pending[1:]
		dropped++
	}
	start := !p.draining
	p.draining = true
	p.mu.Unlock()
	if start {
		go p.drain()
	}
	if dropped > 0 {
		return fmt.Errorf("peer anchor %s: dropped %d oldest pending checkpoint(s) (queue full; replay with 'meshmcp audit anchor')", p.URL, dropped)
	}
	return nil
}

// Post synchronously posts one checkpoint and returns the witness's verdict,
// bypassing the queue. It is the replay path (`meshmcp audit anchor --url`),
// which wants a per-checkpoint error, not background delivery.
func (p *PeerAnchor) Post(c Checkpoint) error { return p.post(c) }

// drain delivers queued checkpoints in order until the queue is empty or a
// post fails. On failure the remaining queue is retained, the failure is
// reported, and the deliverer exits; the next Anchor call restarts it.
func (p *PeerAnchor) drain() {
	for {
		p.mu.Lock()
		if len(p.pending) == 0 {
			p.draining = false
			p.mu.Unlock()
			return
		}
		c := p.pending[0]
		p.mu.Unlock()

		if err := p.post(c); err != nil {
			p.mu.Lock()
			n := len(p.pending)
			p.draining = false
			p.mu.Unlock()
			p.report(fmt.Errorf("peer anchor %s: %d checkpoint(s) queued for retry: %w", p.URL, n, err))
			return
		}

		p.mu.Lock()
		// Pop the delivered checkpoint. An overflow may have dropped it from
		// the head while the POST was in flight; pop only an exact match so an
		// undelivered entry is never discarded.
		if len(p.pending) > 0 && p.pending[0] == c {
			p.pending = p.pending[1:]
		}
		p.mu.Unlock()
	}
}

func (p *PeerAnchor) post(c Checkpoint) error {
	body, err := json.Marshal(c)
	if err != nil {
		return err
	}
	client := p.Client
	if client == nil {
		client = &http.Client{Timeout: peerAnchorTimeout}
	}
	resp, err := client.Post(p.URL, "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("witness returned %d: %s", resp.StatusCode, bytes.TrimSpace(msg))
	}
	return nil
}
