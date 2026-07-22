package air

// Air Handoff is application-level Continuity: it transfers an inert,
// integrity-bound description of work to an exact mesh identity so the
// destination can explicitly continue it in a fresh agent/session. It never
// transfers session transport ownership and never weakens session.CreatorKey.

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"strings"
	"time"
)

const (
	// HandoffVersion is the first Context Capsule wire version.
	HandoffVersion = 1

	// HandoffMaxInlineBytes keeps a capsule small enough for the resumable
	// control channel. Large payloads belong in CAS and travel as BlobRefs.
	HandoffMaxInlineBytes = 256 << 10

	// HandoffMaxWireBytes includes the capsule plus its envelope/hash and JSON
	// framing overhead. ParseHandoffs refuses a longer single record.
	HandoffMaxWireBytes = HandoffMaxInlineBytes + 32<<10

	// HandoffMaxAckBytes bounds the destination's application-level receipt.
	// ACKs carry only status and correlation data, never capsule context.
	HandoffMaxAckBytes = 4 << 10

	// HandoffMaxDeliveryAttempts bounds the durable continuation history. Each
	// attempt is explicit because a timed-out dispatch has an unknown outcome.
	HandoffMaxDeliveryAttempts = 16
)

const (
	maxHandoffTTL        = 24 * time.Hour
	maxHandoffFutureSkew = 5 * time.Minute
	maxHandoffGoal       = 4096
	maxHandoffSummary    = 8192
	maxHandoffCursor     = 128 << 10
	maxHandoffRefs       = 64
	maxHandoffArtifacts  = 32
	maxHandoffNote       = 500
)

// WorkKind describes what a capsule is continuing. It is a descriptive
// reference, not authority and not an executable resume instruction.
type WorkKind string

// Work kinds supported by the v1 capsule.
const (
	WorkAgent    WorkKind = "agent"
	WorkSession  WorkKind = "session"
	WorkTask     WorkKind = "task"
	WorkWorkflow WorkKind = "workflow"
)

// Sensitivity is a routing/consent hint. It never grants access and a
// destination may conservatively add stricter labels.
const (
	SensitivityLow        = "low"
	SensitivityStandard   = "standard"
	SensitivitySensitive  = "sensitive"
	SensitivityRestricted = "restricted"
)

// WorkRef names the application-level work a destination should continue.
// Session references do not confer the right to reattach to that session.
type WorkRef struct {
	Kind WorkKind `json:"kind"`
	ID   string   `json:"id"`
}

// BlobRef points at a content-addressed artifact. The capsule carries no file
// bytes; a receiver fetches the hash through an independently authorized CAS.
type BlobRef struct {
	Name      string `json:"name"`
	SHA256    string `json:"sha256"`
	Bytes     int64  `json:"bytes,omitempty"`
	MediaType string `json:"media_type,omitempty"`
}

// ContextCapsule is the inert work description transferred by Handoff. Raw
// credentials and source-bound capability tokens do not belong here;
// SecretRefs are logical names that must be authorized again at destination.
type ContextCapsule struct {
	Version     int             `json:"version"`
	ID          string          `json:"id"`
	CreatedAt   time.Time       `json:"created_at"`
	ExpiresAt   time.Time       `json:"expires_at"`
	TargetKey   string          `json:"target_key"`
	Work        WorkRef         `json:"work"`
	Goal        string          `json:"goal"`
	Summary     string          `json:"summary,omitempty"`
	Cursor      json.RawMessage `json:"cursor,omitempty"`
	Artifacts   []BlobRef       `json:"artifacts,omitempty"`
	MemoryRefs  []string        `json:"memory_refs,omitempty"`
	SecretRefs  []string        `json:"secret_refs,omitempty"`
	Labels      []string        `json:"labels,omitempty"`
	Sensitivity string          `json:"sensitivity"`
}

// HandoffOffer binds the exact capsule bytes to a stable content hash. The
// verified source identity is deliberately absent: the receiver stamps it from
// the transport into HandoffRecord instead of trusting a sender claim.
type HandoffOffer struct {
	Capsule     ContextCapsule `json:"capsule"`
	ContentHash string         `json:"content_hash"`
}

// HandoffAck is the receiver's application-level answer. Session transport
// completion alone is not proof that an offer passed target validation,
// storage, rate limits, and receipt auditing, so senders require this record.
type HandoffAck struct {
	Version     int    `json:"version"`
	ID          string `json:"id,omitempty"`
	ContentHash string `json:"content_hash,omitempty"`
	Status      string `json:"status"`
	Reason      string `json:"reason,omitempty"`
}

const (
	HandoffAckStored   = "stored"
	HandoffAckReplayed = "replayed"
	HandoffAckRejected = "rejected"
)

// ValidateFor binds a positive ACK to the exact offer. A rejection may omit
// correlation when malformed framing prevented the receiver from decoding it.
func (a HandoffAck) ValidateFor(offer HandoffOffer) error {
	if err := validateHandoffAck(a); err != nil {
		return err
	}
	if a.ID != "" && subtle.ConstantTimeCompare([]byte(a.ID), []byte(offer.Capsule.ID)) != 1 {
		return fmt.Errorf("handoff acknowledgement id mismatch")
	}
	if a.ContentHash != "" && subtle.ConstantTimeCompare([]byte(a.ContentHash), []byte(offer.ContentHash)) != 1 {
		return fmt.Errorf("handoff acknowledgement content hash mismatch")
	}
	if a.Status != HandoffAckRejected && (a.ID == "" || a.ContentHash == "") {
		return fmt.Errorf("positive handoff acknowledgement lacks correlation")
	}
	return nil
}

// Accepted reports whether the destination confirmed durable storage (or an
// identity-bound replay of the same already-stored offer).
func (a HandoffAck) Accepted() bool {
	return a.Status == HandoffAckStored || a.Status == HandoffAckReplayed
}

func validateHandoffAck(a HandoffAck) error {
	if a.Version != HandoffVersion {
		return fmt.Errorf("unsupported handoff acknowledgement version %d", a.Version)
	}
	switch a.Status {
	case HandoffAckStored, HandoffAckReplayed:
		if a.Reason != "" {
			return fmt.Errorf("positive handoff acknowledgement must not carry a rejection reason")
		}
	case HandoffAckRejected:
		if err := boundedToken("acknowledgement reason", a.Reason, 128); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown handoff acknowledgement status %q", a.Status)
	}
	if a.ID != "" && !validHandoffID(a.ID) {
		return fmt.Errorf("handoff acknowledgement id is invalid")
	}
	if a.ContentHash != "" && !validSHA256Ref(a.ContentHash) {
		return fmt.Errorf("handoff acknowledgement content hash is invalid")
	}
	return nil
}

// NewHandoffID returns a 128-bit random, path-safe correlation id.
func NewHandoffID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("handoff id: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// SealHandoff normalizes additive defaults, validates the capsule's static
// shape, and binds it to its canonical JSON bytes. Time and target checks are
// performed by HandoffOffer.Validate at the sending/receiving boundary.
func SealHandoff(c ContextCapsule) (HandoffOffer, error) {
	if c.Version == 0 {
		c.Version = HandoffVersion
	}
	if c.Sensitivity == "" {
		c.Sensitivity = SensitivityStandard
	}
	if err := validateCapsuleShape(c); err != nil {
		return HandoffOffer{}, err
	}
	b, err := json.Marshal(c)
	if err != nil {
		return HandoffOffer{}, fmt.Errorf("handoff capsule: %w", err)
	}
	if len(b) > HandoffMaxInlineBytes {
		return HandoffOffer{}, fmt.Errorf("handoff capsule is %d bytes, over the %d-byte inline limit", len(b), HandoffMaxInlineBytes)
	}
	sum := sha256.Sum256(b)
	return HandoffOffer{Capsule: c, ContentHash: "sha256:" + hex.EncodeToString(sum[:])}, nil
}

// Validate verifies capsule shape, TTL, exact destination binding, and content
// integrity. expectedTargetKey must be the receiver's transport-derived key.
func (o HandoffOffer) Validate(now time.Time, expectedTargetKey string) error {
	if now.IsZero() {
		return fmt.Errorf("handoff validation requires a clock")
	}
	if err := validateCapsuleShape(o.Capsule); err != nil {
		return err
	}
	if expectedTargetKey == "" {
		return fmt.Errorf("handoff validation requires the destination key")
	}
	if subtle.ConstantTimeCompare([]byte(o.Capsule.TargetKey), []byte(expectedTargetKey)) != 1 {
		return fmt.Errorf("handoff target key does not match this destination")
	}
	if o.Capsule.CreatedAt.After(now.Add(maxHandoffFutureSkew)) {
		return fmt.Errorf("handoff was created too far in the future")
	}
	if !now.Before(o.Capsule.ExpiresAt) {
		return fmt.Errorf("handoff has expired")
	}
	sealed, err := SealHandoff(o.Capsule)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare([]byte(sealed.ContentHash), []byte(o.ContentHash)) != 1 {
		return fmt.Errorf("handoff content hash mismatch")
	}
	return nil
}

func validateCapsuleShape(c ContextCapsule) error {
	if c.Version != HandoffVersion {
		return fmt.Errorf("unsupported handoff version %d", c.Version)
	}
	if !validHandoffID(c.ID) {
		return fmt.Errorf("handoff id must be 32 lowercase hexadecimal characters")
	}
	if err := boundedToken("target key", c.TargetKey, 256); err != nil {
		return err
	}
	if c.CreatedAt.IsZero() || c.ExpiresAt.IsZero() {
		return fmt.Errorf("handoff requires created_at and expires_at")
	}
	ttl := c.ExpiresAt.Sub(c.CreatedAt)
	if ttl <= 0 || ttl > maxHandoffTTL {
		return fmt.Errorf("handoff ttl must be greater than zero and at most %s", maxHandoffTTL)
	}
	switch c.Work.Kind {
	case WorkAgent, WorkSession, WorkTask, WorkWorkflow:
	default:
		return fmt.Errorf("unknown handoff work kind %q", c.Work.Kind)
	}
	if err := boundedToken("work id", c.Work.ID, 256); err != nil {
		return err
	}
	if err := boundedHandoffText("goal", c.Goal, maxHandoffGoal, true); err != nil {
		return err
	}
	if err := boundedHandoffText("summary", c.Summary, maxHandoffSummary, false); err != nil {
		return err
	}
	if len(c.Cursor) > maxHandoffCursor {
		return fmt.Errorf("handoff cursor is %d bytes, over the %d-byte limit", len(c.Cursor), maxHandoffCursor)
	}
	if len(c.Cursor) > 0 && !json.Valid(c.Cursor) {
		return fmt.Errorf("handoff cursor must be valid JSON")
	}
	if len(c.Artifacts) > maxHandoffArtifacts {
		return fmt.Errorf("handoff has %d artifacts, over the %d-artifact limit", len(c.Artifacts), maxHandoffArtifacts)
	}
	for i, a := range c.Artifacts {
		if err := validateBlobRef(a); err != nil {
			return fmt.Errorf("handoff artifact %d: %w", i, err)
		}
	}
	if err := validateRefs("memory_refs", c.MemoryRefs); err != nil {
		return err
	}
	if err := validateRefs("secret_refs", c.SecretRefs); err != nil {
		return err
	}
	if err := validateRefs("labels", c.Labels); err != nil {
		return err
	}
	switch c.Sensitivity {
	case SensitivityLow, SensitivityStandard, SensitivitySensitive, SensitivityRestricted:
	default:
		return fmt.Errorf("unknown handoff sensitivity %q", c.Sensitivity)
	}
	b, err := json.Marshal(c)
	if err != nil {
		return fmt.Errorf("handoff capsule: %w", err)
	}
	if len(b) > HandoffMaxInlineBytes {
		return fmt.Errorf("handoff capsule is %d bytes, over the %d-byte inline limit", len(b), HandoffMaxInlineBytes)
	}
	return nil
}

func validHandoffID(id string) bool {
	if len(id) != 32 {
		return false
	}
	for _, r := range id {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return false
		}
	}
	return true
}

func boundedToken(name, s string, max int) error {
	if strings.TrimSpace(s) == "" || s != strings.TrimSpace(s) {
		return fmt.Errorf("handoff %s must be non-empty without surrounding whitespace", name)
	}
	if len(s) > max {
		return fmt.Errorf("handoff %s exceeds %d bytes", name, max)
	}
	if hasControl(s) {
		return fmt.Errorf("handoff %s contains control characters", name)
	}
	return nil
}

func boundedHandoffText(name, s string, max int, required bool) error {
	if required && strings.TrimSpace(s) == "" {
		return fmt.Errorf("handoff requires a %s", name)
	}
	if len(s) > max {
		return fmt.Errorf("handoff %s exceeds %d bytes", name, max)
	}
	if hasControl(s) {
		return fmt.Errorf("handoff %s contains control characters", name)
	}
	return nil
}

func validateRefs(name string, refs []string) error {
	if len(refs) > maxHandoffRefs {
		return fmt.Errorf("handoff %s has %d entries, over the %d-entry limit", name, len(refs), maxHandoffRefs)
	}
	seen := make(map[string]struct{}, len(refs))
	for _, ref := range refs {
		if err := boundedToken(name+" entry", ref, 256); err != nil {
			return err
		}
		if _, ok := seen[ref]; ok {
			return fmt.Errorf("handoff %s contains duplicate %q", name, ref)
		}
		seen[ref] = struct{}{}
	}
	return nil
}

func validateBlobRef(b BlobRef) error {
	if err := boundedToken("artifact name", b.Name, 255); err != nil {
		return err
	}
	if b.Name == "." || b.Name == ".." || strings.ContainsAny(b.Name, `/\`) {
		return fmt.Errorf("artifact name must be a base name")
	}
	if !validSHA256Ref(b.SHA256) {
		return fmt.Errorf("artifact sha256 must be sha256:<64 lowercase hex>")
	}
	if b.Bytes < 0 || b.Bytes > 1<<50 {
		return fmt.Errorf("artifact size is outside the supported range")
	}
	if b.MediaType != "" {
		if len(b.MediaType) > 128 || hasControl(b.MediaType) {
			return fmt.Errorf("artifact media type is invalid")
		}
		if _, _, err := mime.ParseMediaType(b.MediaType); err != nil {
			return fmt.Errorf("artifact media type is invalid")
		}
	}
	return nil
}

func validSHA256Ref(s string) bool {
	if len(s) != len("sha256:")+64 || !strings.HasPrefix(s, "sha256:") {
		return false
	}
	for _, r := range s[len("sha256:"):] {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return false
		}
	}
	return true
}

// WriteHandoff writes one newline-delimited offer.
func WriteHandoff(w io.Writer, offer HandoffOffer) error {
	b, err := json.Marshal(offer)
	if err != nil {
		return err
	}
	if len(b) > HandoffMaxWireBytes {
		return fmt.Errorf("handoff wire record is %d bytes, over the %d-byte limit", len(b), HandoffMaxWireBytes)
	}
	_, err = w.Write(append(b, '\n'))
	return err
}

// ReadHandoff reads exactly the first bounded newline-framed offer and returns
// as soon as that frame is complete, allowing a receiver to answer before the
// duplex session closes.
func ReadHandoff(r io.Reader) (HandoffOffer, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), HandoffMaxWireBytes)
	if !sc.Scan() {
		if err := sc.Err(); err != nil {
			return HandoffOffer{}, err
		}
		return HandoffOffer{}, fmt.Errorf("empty handoff offer")
	}
	line := bytes.TrimSpace(sc.Bytes())
	if len(line) == 0 {
		return HandoffOffer{}, fmt.Errorf("empty handoff offer")
	}
	var offer HandoffOffer
	if err := decodeStrictAirJSON(line, &offer); err != nil {
		return HandoffOffer{}, fmt.Errorf("bad handoff offer: %w", err)
	}
	return offer, nil
}

// ParseHandoffs reads bounded newline-delimited offers. Validation that needs
// the receiver's exact key and clock remains the receiving boundary's job.
func ParseHandoffs(r io.Reader, onOffer func(HandoffOffer)) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), HandoffMaxWireBytes)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var offer HandoffOffer
		if err := decodeStrictAirJSON(line, &offer); err != nil {
			return fmt.Errorf("bad handoff offer: %w", err)
		}
		onOffer(offer)
	}
	return sc.Err()
}

// WriteHandoffAck writes one bounded newline-delimited application receipt.
func WriteHandoffAck(w io.Writer, ack HandoffAck) error {
	if err := validateHandoffAck(ack); err != nil {
		return err
	}
	b, err := json.Marshal(ack)
	if err != nil {
		return err
	}
	if len(b) > HandoffMaxAckBytes {
		return fmt.Errorf("handoff acknowledgement exceeds %d bytes", HandoffMaxAckBytes)
	}
	_, err = w.Write(append(b, '\n'))
	return err
}

// ReadHandoffAck reads one bounded application receipt.
func ReadHandoffAck(r io.Reader) (HandoffAck, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1024), HandoffMaxAckBytes)
	if !sc.Scan() {
		if err := sc.Err(); err != nil {
			return HandoffAck{}, err
		}
		return HandoffAck{}, fmt.Errorf("missing handoff acknowledgement")
	}
	line := bytes.TrimSpace(sc.Bytes())
	var ack HandoffAck
	if len(line) == 0 {
		return ack, fmt.Errorf("empty handoff acknowledgement")
	}
	if err := decodeStrictAirJSON(line, &ack); err != nil {
		return HandoffAck{}, fmt.Errorf("bad handoff acknowledgement: %w", err)
	}
	if err := validateHandoffAck(ack); err != nil {
		return HandoffAck{}, err
	}
	return ack, nil
}

func decodeStrictAirJSON(data []byte, dst any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("multiple JSON values")
		}
		return err
	}
	return nil
}

// HandoffState is the durable consent/delivery state of one offer.
type HandoffState string

const (
	HandoffOffered     HandoffState = "offered"
	HandoffAccepted    HandoffState = "accepted"
	HandoffDispatching HandoffState = "dispatching"
	HandoffDeclined    HandoffState = "declined"
	HandoffContinued   HandoffState = "continued"
	HandoffExpired     HandoffState = "expired"
)

// HandoffRecord is the received offer plus transport-derived source identity
// and its local state. Source fields are never copied from the capsule.
type HandoffRecord struct {
	Offer            HandoffOffer             `json:"offer"`
	SourcePeer       string                   `json:"source_peer,omitempty"`
	SourceKey        string                   `json:"source_key,omitempty"`
	SourceAddr       string                   `json:"source_addr,omitempty"`
	ReceivedAt       time.Time                `json:"received_at"`
	State            HandoffState             `json:"state"`
	UpdatedAt        time.Time                `json:"updated_at"`
	Note             string                   `json:"note,omitempty"`
	DeliveryAttempts []HandoffDeliveryAttempt `json:"delivery_attempts,omitempty"`
}

// HandoffDeliveryAttempt is the durable chain-of-custody receipt for one
// receiver-selected continuation. A nil AcknowledgedAt means delivery may have
// happened but no valid destination application ACK was observed.
type HandoffDeliveryAttempt struct {
	AgentAddr      string     `json:"agent_addr"`
	AgentKey       string     `json:"agent_key"`
	Tool           string     `json:"tool"`
	ClaimedAt      time.Time  `json:"claimed_at"`
	AcknowledgedAt *time.Time `json:"acknowledged_at,omitempty"`
}

// Validate checks the bounded destination receipt independently of the
// capsule. The destination key is transport-derived by the continuation
// sender; neither it nor the selected tool comes from received context.
func (a HandoffDeliveryAttempt) Validate() error {
	if err := boundedToken("delivery agent address", a.AgentAddr, 512); err != nil {
		return err
	}
	if err := boundedToken("delivery agent key", a.AgentKey, 256); err != nil {
		return err
	}
	if strings.TrimSpace(a.Tool) == "" || a.Tool != strings.TrimSpace(a.Tool) {
		return fmt.Errorf("handoff delivery tool must be non-empty without surrounding whitespace")
	}
	if err := boundedHandoffText("delivery tool", a.Tool, 256, true); err != nil {
		return err
	}
	if a.ClaimedAt.IsZero() {
		return fmt.Errorf("handoff delivery attempt requires claimed_at")
	}
	if a.AcknowledgedAt != nil {
		if a.AcknowledgedAt.IsZero() || a.AcknowledgedAt.Before(a.ClaimedAt) {
			return fmt.Errorf("handoff delivery acknowledgement predates its claim")
		}
	}
	return nil
}

// EffectiveState overlays expiry without mutating storage. Both unaccepted and
// accepted-but-not-yet-dispatched offers expire; terminal states stay terminal.
func (r HandoffRecord) EffectiveState(now time.Time) HandoffState {
	if (r.State == HandoffOffered || r.State == HandoffAccepted) && !now.IsZero() && !now.Before(r.Offer.Capsule.ExpiresAt) {
		return HandoffExpired
	}
	return r.State
}

// Transition applies non-delivery lifecycle transitions. Delivery states carry
// mandatory destination receipts and therefore must use ClaimDelivery and
// AcknowledgeDelivery instead of this generic method.
func (r *HandoffRecord) Transition(next HandoffState, now time.Time, note string) error {
	if next == HandoffDispatching || next == HandoffContinued {
		return fmt.Errorf("handoff delivery states require ClaimDelivery or AcknowledgeDelivery")
	}
	return r.transition(next, now, note)
}

func (r *HandoffRecord) transition(next HandoffState, now time.Time, note string) error {
	if r == nil {
		return fmt.Errorf("handoff record is nil")
	}
	if now.IsZero() {
		return fmt.Errorf("handoff transition requires a clock")
	}
	if err := boundedHandoffText("transition note", note, maxHandoffNote, false); err != nil {
		return err
	}
	switch next {
	case HandoffOffered, HandoffAccepted, HandoffDispatching, HandoffDeclined, HandoffContinued, HandoffExpired:
	default:
		return fmt.Errorf("unknown handoff state %q", next)
	}
	effective := r.EffectiveState(now)
	if effective == next {
		if r.State != next { // persist a newly effective expiry
			r.State, r.UpdatedAt, r.Note = next, now, note
		}
		return nil
	}
	if r.State == HandoffDispatching && !now.Before(r.Offer.Capsule.ExpiresAt) {
		return fmt.Errorf("handoff delivery outcome is unknown and the offer has expired")
	}
	if effective != r.State {
		return fmt.Errorf("handoff is %s", effective)
	}
	allowed := false
	switch r.State {
	case HandoffOffered:
		allowed = next == HandoffAccepted || next == HandoffDeclined || next == HandoffExpired
	case HandoffAccepted:
		allowed = next == HandoffDispatching || next == HandoffExpired
	case HandoffDispatching:
		allowed = next == HandoffContinued
	}
	if !allowed {
		return fmt.Errorf("invalid handoff transition %s -> %s", r.State, next)
	}
	r.State, r.UpdatedAt, r.Note = next, now, note
	return nil
}

// ClaimDelivery moves an accepted record to dispatching and appends its exact
// destination receipt as one atomic in-memory mutation.
func (r *HandoffRecord) ClaimDelivery(attempt HandoffDeliveryAttempt, now time.Time) error {
	if r == nil {
		return fmt.Errorf("handoff record is nil")
	}
	if err := attempt.Validate(); err != nil {
		return err
	}
	if !attempt.ClaimedAt.Equal(now) {
		return fmt.Errorf("handoff delivery claim time does not match the transition clock")
	}
	if len(r.DeliveryAttempts) >= HandoffMaxDeliveryAttempts {
		return fmt.Errorf("handoff has reached the %d-attempt delivery limit", HandoffMaxDeliveryAttempts)
	}
	if r.State != HandoffAccepted {
		return fmt.Errorf("handoff must be accepted before delivery (state %s)", r.State)
	}
	if err := r.transition(HandoffDispatching, now, "continuation delivery claimed"); err != nil {
		return err
	}
	r.DeliveryAttempts = append(r.DeliveryAttempts, attempt)
	return nil
}

// AcknowledgeDelivery records the destination application's positive receipt
// and moves the claim to continued. It is not a tool-success receipt.
func (r *HandoffRecord) AcknowledgeDelivery(now time.Time) error {
	if r == nil {
		return fmt.Errorf("handoff record is nil")
	}
	if r.State != HandoffDispatching || len(r.DeliveryAttempts) == 0 {
		return fmt.Errorf("handoff has no claimed delivery to acknowledge (state %s)", r.State)
	}
	last := len(r.DeliveryAttempts) - 1
	if r.DeliveryAttempts[last].AcknowledgedAt != nil {
		return fmt.Errorf("handoff delivery is already acknowledged")
	}
	if err := r.transition(HandoffContinued, now, "destination inbox acknowledged continuation"); err != nil {
		return err
	}
	acknowledgedAt := now
	r.DeliveryAttempts[last].AcknowledgedAt = &acknowledgedAt
	return nil
}

// Rearm moves an unknown-outcome dispatch back to accepted only through an
// explicit, noted operator action. Keeping this separate from Transition makes
// an idempotent retry of ordinary "accept" incapable of executing work twice.
func (r *HandoffRecord) Rearm(now time.Time, note string) error {
	if r == nil {
		return fmt.Errorf("handoff record is nil")
	}
	if now.IsZero() {
		return fmt.Errorf("handoff rearm requires a clock")
	}
	if err := boundedHandoffText("rearm note", note, maxHandoffNote, true); err != nil {
		return err
	}
	if r.State != HandoffDispatching {
		return fmt.Errorf("handoff state %s has no unknown dispatch to re-arm", r.State)
	}
	if len(r.DeliveryAttempts) == 0 || r.DeliveryAttempts[len(r.DeliveryAttempts)-1].AcknowledgedAt != nil {
		return fmt.Errorf("handoff has no pending delivery receipt to re-arm")
	}
	if !now.Before(r.Offer.Capsule.ExpiresAt) {
		return fmt.Errorf("handoff delivery outcome is unknown and the offer has expired")
	}
	r.State, r.UpdatedAt, r.Note = HandoffAccepted, now, note
	return nil
}
