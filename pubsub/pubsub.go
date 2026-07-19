// Package pubsub is meshmcp's identity-native event fabric: a publish/subscribe
// bus where every event is stamped with the publisher's cryptographic mesh
// identity, delivery is authorized per topic by that identity (deny by
// default), data-flow labels contain tainted events at the bus (not just at
// the model), and the whole event stream is hash-chained so it is
// tamper-evident like the audit ledger.
//
// The package is transport-agnostic on purpose. The Broker here is a pure,
// in-memory core with no knowledge of the mesh, the session layer, or the
// wire protocol — that lets every hardening invariant (ordering, exactly-once
// fan-out, bounded buffers, backpressure, rate limits, resource caps, taint
// containment, replay, and the hash chain) be exercised deterministically
// under `go test -race`. The mesh wiring (the broker daemon and the
// `meshmcp publish` / `meshmcp subscribe` clients) lives in the root package
// and drives this core.
//
// Design invariants (mirroring the gateway's, see docs/IDEAS.md):
//   - Deny is the safe default. A publish or a subscribe to a topic the
//     caller's identity is not granted is refused; there is no ambient allow.
//   - Identity is cryptographic, never claimed. An Event.Publisher is the
//     WireGuard key the transport proved, filled in by the caller.
//   - Audit is a control, not best-effort. Every authorization decision is a
//     ledger record when an AuditLog is attached.
//   - Taint is contained below the model. An event carrying a label a
//     subscription is not cleared for is never delivered to it.
package pubsub

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Identity is the cryptographic caller identity for a pub/sub action: the
// WireGuard public key the transport proved, plus the mesh FQDN and remote
// address for audit. Key is the authorization principal; FQDN/Addr are
// descriptive.
type Identity struct {
	Key  string
	FQDN string
	Addr string
}

// Event is one published message. Events form a hash chain exactly like the
// audit ledger: each carries a monotonic Seq, the Hash of the previous event
// (PrevHash), and its own Hash = sha256(json(event with Hash cleared)).
// Because PrevHash is folded into each event's own bytes, editing, reordering,
// or dropping any event breaks every hash after it — detectable via
// VerifyChain without the original stream.
type Event struct {
	Topic     string          `json:"topic"`
	Seq       uint64          `json:"seq"`
	Time      string          `json:"time,omitempty"`
	Publisher string          `json:"publisher,omitempty"`      // WireGuard pubkey
	PubFQDN   string          `json:"publisher_fqdn,omitempty"` // mesh FQDN
	Labels    []string        `json:"labels,omitempty"`         // data-flow labels (e.g. "tainted", "pii")
	Enc       string          `json:"enc,omitempty"`            // payload encoding hint (e.g. "base64" for binary); opaque to the broker
	Origin    string          `json:"origin,omitempty"`         // set when mirrored from another broker (federation); prevents re-mirroring loops
	Payload   json.RawMessage `json:"payload,omitempty"`

	PrevHash string `json:"prev_hash"`
	Hash     string `json:"hash,omitempty"`
}

// chainHash computes an event's hash over its JSON with the Hash field
// cleared. PrevHash is already a field, so it is covered by the hash.
func chainHash(ev Event) (string, error) {
	ev.Hash = ""
	b, err := json.Marshal(ev)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// VerifyChain checks that a slice of events forms an unbroken hash chain:
// sequence numbers strictly increase, each event's PrevHash equals the prior
// event's Hash, and each Hash recomputes. It returns a descriptive error at
// the first break, so an operator can prove the event stream was never
// silently edited. An empty slice verifies vacuously.
func VerifyChain(events []Event) error {
	prev := ""
	var lastSeq uint64
	for i, ev := range events {
		if i > 0 && ev.Seq <= lastSeq {
			return fmt.Errorf("event %d: seq %d not strictly greater than previous %d", i, ev.Seq, lastSeq)
		}
		if ev.PrevHash != prev {
			return fmt.Errorf("event %d (seq %d): prev_hash %q does not chain to %q", i, ev.Seq, ev.PrevHash, prev)
		}
		want, err := chainHash(ev)
		if err != nil {
			return fmt.Errorf("event %d (seq %d): rehash: %w", i, ev.Seq, err)
		}
		if want != ev.Hash {
			return fmt.Errorf("event %d (seq %d): hash %q does not match recomputed %q", i, ev.Seq, ev.Hash, want)
		}
		prev = ev.Hash
		lastSeq = ev.Seq
	}
	return nil
}

// Backpressure selects how the broker treats a subscriber whose delivery
// buffer is full when a new matching event arrives. A full buffer means the
// subscriber is not draining fast enough; the broker never blocks its own
// fan-out loop waiting for one slow reader.
type Backpressure int

const (
	// DropOldest evicts the oldest undelivered event to make room for the new
	// one and increments the subscription's Dropped counter. The subscriber
	// stays connected but sees a gap (surfaced, never silent).
	DropOldest Backpressure = iota
	// Disconnect closes the subscription instead of dropping: the subscriber
	// is expected to reconnect and replay from its last seen sequence. This is
	// the correct choice when gaps are unacceptable.
	Disconnect
)

func (b Backpressure) String() string {
	if b == Disconnect {
		return "disconnect"
	}
	return "drop_oldest"
}

// ParseBackpressure maps a wire/config string to a Backpressure. Unknown
// values are an error rather than a silent default, so a typo fails closed.
func ParseBackpressure(s string) (Backpressure, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "drop_oldest", "drop-oldest", "dropoldest":
		return DropOldest, nil
	case "disconnect", "close":
		return Disconnect, nil
	default:
		return DropOldest, fmt.Errorf("unknown backpressure policy %q (want drop_oldest or disconnect)", s)
	}
}

// Sentinel errors returned by the Broker. Callers (the wire layer) map these
// to protocol responses; deny-class errors are also audited.
var (
	// ErrDenied is returned when the authorizer refuses a publish or subscribe.
	ErrDenied = errors.New("denied by pubsub policy")
	// ErrRateLimited is returned when a publisher exceeds its token bucket.
	ErrRateLimited = errors.New("publish rate limit exceeded")
	// ErrTooMany is returned when a resource cap (subscriptions, topics per
	// subscription) would be exceeded.
	ErrTooMany = errors.New("resource limit exceeded")
	// ErrBadTopic is returned for an empty, oversized, or malformed topic.
	ErrBadTopic = errors.New("invalid topic")
	// ErrPayloadTooLarge is returned when a publish payload exceeds the
	// broker's MaxPayloadBytes. Retention holds full payloads, so this cap
	// (times Retain) bounds the broker's memory.
	ErrPayloadTooLarge = errors.New("payload too large")
	// ErrClosed is returned by broker operations after Close.
	ErrClosed = errors.New("broker closed")
)
