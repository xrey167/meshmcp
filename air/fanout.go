package air

// Fan-out results are the portable outcome of one group action (Spaces v1): a
// `group:<name>` destination resolved to N present members, each then delivered
// through the EXISTING single-target path so every delivery independently
// enters its destination's own ACL/policy and produces its own audit record.
// The envelope therefore carries only per-member truth. There is deliberately
// NO top-level status or counter field: a partially denied fan-out is
// representable only as the per-member list, never as an aggregate verdict
// that could lie. ActionResult's same-recipient invariant is untouched — this
// is a sibling contract, not a loosening.

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

const (
	// FanoutResultSchemaV1 is the first portable group-action result contract.
	FanoutResultSchemaV1 = "air.fanout-result/v1"

	// MaxFanoutMembers bounds one fan-out's member list. It matches the
	// gateway's group-resolution cap: a group that resolves wider is refused
	// loudly up front, never truncated to a silent subset.
	MaxFanoutMembers = 64

	// MaxFanoutReasonBytes bounds a non-delivered member's single-line reason.
	MaxFanoutReasonBytes = 512

	// MaxGroupNameBytes bounds an operator-defined group name everywhere the
	// grammar appears: the config `groups:` map, the `group:<name>` selector,
	// and this envelope's Group field.
	MaxGroupNameBytes = 64

	// MaxGroupPatternBytes bounds one group member pattern everywhere the
	// grammar appears: the config `groups:` map values and this envelope's
	// unmatched-pattern echo. One bound, so a pattern a config accepts can
	// always be echoed back in a result.
	MaxGroupPatternBytes = 256

	maxFanoutSteerFieldBytes = 256
)

// FanoutAction is the group verb the members report on.
type FanoutAction string

const (
	FanoutActionSteer FanoutAction = "steer"
	FanoutActionRing  FanoutAction = "ring"
)

func (a FanoutAction) valid() bool {
	switch a {
	case FanoutActionSteer, FanoutActionRing:
		return true
	default:
		return false
	}
}

// FanoutStatus is one member's terminal outcome. `denied` is reserved for a
// destination's own explicit refusal (e.g. the steer endpoint's 403); a sender
// that cannot distinguish a deny from a network failure must report `failed`,
// leaving the receiver's ledger the authoritative deny record.
type FanoutStatus string

const (
	FanoutDelivered FanoutStatus = "delivered"
	FanoutDenied    FanoutStatus = "denied"
	FanoutSkipped   FanoutStatus = "skipped"
	FanoutFailed    FanoutStatus = "failed"
)

// FanoutRecipient identifies one resolved group member. PublicKey is required:
// members come from the gateway's identity-stamped presence snapshot, so an
// unverified friendly name can never stand alone as a fan-out recipient.
// Service/Address are set by verbs that dial an advertised service (ring).
type FanoutRecipient struct {
	Name      string      `json:"name,omitempty"`
	FQDN      string      `json:"fqdn,omitempty"`
	PublicKey string      `json:"public_key"`
	Service   ServiceKind `json:"service,omitempty"`
	Address   string      `json:"address,omitempty"`
}

// FanoutSteer is the delivered detail for the steer verb: which backend/session
// the member's identity-bound session resolved to, and who the gateway
// attributed the steer to. (Steer confirmations are not ActionReceipts.)
type FanoutSteer struct {
	Backend string `json:"backend"`
	Session string `json:"session"`
	By      string `json:"by,omitempty"`
}

// FanoutMember is one member's outcome. A delivered member carries its verb
// detail and no reason; every non-delivered member carries a bounded,
// single-line reason. Receipt is reserved for future verbs that mint
// ActionReceipts — neither v1 verb does, so it must be nil today.
type FanoutMember struct {
	Recipient FanoutRecipient `json:"recipient"`
	Status    FanoutStatus    `json:"status"`
	Reason    string          `json:"reason,omitempty"`
	Steer     *FanoutSteer    `json:"steer,omitempty"`
	Receipt   *ActionReceipt  `json:"receipt,omitempty"`
	Time      string          `json:"time,omitempty"`
}

// FanoutResult is the whole fan-out: the group name, the verb, one entry per
// resolved member in resolution order, and the configured patterns that
// matched no present member. UnmatchedPatterns is resolution metadata, not an
// aggregate verdict: it echoes a quiet part of the roster so a JSON consumer
// sees it exactly like the human summary does, never a summary of outcomes.
type FanoutResult struct {
	Schema            string         `json:"schema"`
	Group             string         `json:"group"`
	Action            FanoutAction   `json:"action"`
	Members           []FanoutMember `json:"members"`
	UnmatchedPatterns []string       `json:"unmatched_patterns,omitempty"`
}

// ValidateGroupName checks the operator-facing group-name grammar shared by
// the gateway config's `groups:` map, the `group:<name>` destination selector,
// and FanoutResult.Group: a bounded token with no control characters and no
// ":" (which would make the selector and policy `group:` peer patterns
// ambiguous).
func ValidateGroupName(name string) error {
	if name == "" || name != strings.TrimSpace(name) {
		return fmt.Errorf("group name must be non-empty with no surrounding whitespace")
	}
	if len(name) > MaxGroupNameBytes {
		return fmt.Errorf("group name must be at most %d bytes", MaxGroupNameBytes)
	}
	if hasControl(name) {
		return fmt.Errorf("group name must not contain control characters")
	}
	if strings.Contains(name, ":") {
		return fmt.Errorf(`group name must not contain ":"`)
	}
	return nil
}

// ValidateGroupPattern checks one group member pattern with the bound shared
// by the config `groups:` map and this envelope's unmatched echo: non-blank,
// bounded, and single-line control-free (same character rule as every other
// display field), so a loadable config pattern can never invalidate the
// envelope that echoes it back.
func ValidateGroupPattern(p string) error {
	if strings.TrimSpace(p) == "" {
		return fmt.Errorf("group pattern must be non-empty")
	}
	if len(p) > MaxGroupPatternBytes {
		return fmt.Errorf("group pattern must be at most %d bytes", MaxGroupPatternBytes)
	}
	if hasControl(p) {
		return fmt.Errorf("group pattern must not contain control characters")
	}
	return nil
}

// NewFanoutResult constructs and validates one fan-out result. Callers build
// the member list as deliveries complete and construct the envelope once, so
// an invalid outcome shape is rejected before it is rendered anywhere.
// unmatched echoes the configured patterns that matched no present member.
func NewFanoutResult(group string, action FanoutAction, members []FanoutMember, unmatched []string) (FanoutResult, error) {
	r := FanoutResult{
		Schema:            FanoutResultSchemaV1,
		Group:             group,
		Action:            action,
		Members:           append([]FanoutMember(nil), members...),
		UnmatchedPatterns: append([]string(nil), unmatched...),
	}
	if err := r.Validate(); err != nil {
		return FanoutResult{}, err
	}
	return r, nil
}

// Validate checks the envelope: schema, group grammar, verb, a bounded member
// list where every entry tells its own truth, and a bounded total encoding.
func (r FanoutResult) Validate() error {
	if r.Schema != FanoutResultSchemaV1 {
		return fmt.Errorf("fanout result schema must be %q", FanoutResultSchemaV1)
	}
	if err := ValidateGroupName(r.Group); err != nil {
		return fmt.Errorf("fanout result: %w", err)
	}
	if !r.Action.valid() {
		return fmt.Errorf("fanout result action must be %q or %q", FanoutActionSteer, FanoutActionRing)
	}
	if len(r.Members) == 0 || len(r.Members) > MaxFanoutMembers {
		return fmt.Errorf("fanout result must contain between 1 and %d members", MaxFanoutMembers)
	}
	for i, m := range r.Members {
		if err := m.validate(r.Action); err != nil {
			return fmt.Errorf("fanout result member %d: %w", i, err)
		}
	}
	// The unmatched echo shares the group cap: a config may define at most
	// MaxFanoutMembers patterns per group, so no honest roster exceeds it.
	if len(r.UnmatchedPatterns) > MaxFanoutMembers {
		return fmt.Errorf("fanout result must carry at most %d unmatched patterns", MaxFanoutMembers)
	}
	for i, p := range r.UnmatchedPatterns {
		if err := ValidateGroupPattern(p); err != nil {
			return fmt.Errorf("fanout result unmatched pattern %d: %w", i, err)
		}
	}
	encoded, err := json.Marshal(r)
	if err != nil {
		return fmt.Errorf("fanout result does not encode: %w", err)
	}
	if int64(len(encoded)) > MaxActionTotalBytes {
		return fmt.Errorf("fanout result exceeds %d total bytes", MaxActionTotalBytes)
	}
	return nil
}

func (m FanoutMember) validate(action FanoutAction) error {
	if err := m.Recipient.Validate(); err != nil {
		return err
	}
	// Neither v1 verb mints ActionReceipts; the slot exists only so a future
	// receipt-bearing verb does not need a schema break. Reject it now rather
	// than let a steer/ring result carry a receipt it cannot truthfully own.
	if m.Receipt != nil {
		return fmt.Errorf("receipt is reserved for verbs that mint action receipts")
	}
	switch m.Status {
	case FanoutDelivered:
		if m.Reason != "" {
			return fmt.Errorf("delivered member must not carry a reason")
		}
		switch action {
		case FanoutActionSteer:
			if m.Steer == nil {
				return fmt.Errorf("delivered steer member requires steer detail")
			}
			if err := m.Steer.Validate(); err != nil {
				return err
			}
		case FanoutActionRing:
			if m.Steer != nil {
				return fmt.Errorf("ring member must not carry steer detail")
			}
			if m.Recipient.Address == "" {
				return fmt.Errorf("delivered ring member requires the delivered address")
			}
		}
	case FanoutDenied, FanoutSkipped, FanoutFailed:
		if strings.TrimSpace(m.Reason) == "" {
			return fmt.Errorf("%s member requires a reason", m.Status)
		}
		if len(m.Reason) > MaxFanoutReasonBytes {
			return fmt.Errorf("member reason must be at most %d bytes", MaxFanoutReasonBytes)
		}
		if hasControl(m.Reason) {
			return fmt.Errorf("member reason must be a single line without control characters")
		}
		if m.Steer != nil {
			return fmt.Errorf("only a delivered member may carry steer detail")
		}
	default:
		return fmt.Errorf("unknown member status %q", m.Status)
	}
	if m.Time != "" {
		if err := validDisplayText("member time", m.Time, maxActionReceiptTimeBytes); err != nil {
			return err
		}
		if _, err := time.Parse(time.RFC3339Nano, m.Time); err != nil {
			return fmt.Errorf("member time %q is not RFC3339: %w", m.Time, err)
		}
	}
	return nil
}

// Validate checks one recipient's envelope shape. Exported so fan-out senders
// can refuse a tampered roster card at the trust boundary — BEFORE any
// delivery — instead of discovering after the loop that a completed fan-out
// cannot be reported.
func (r FanoutRecipient) Validate() error {
	if r.PublicKey == "" || r.PublicKey != strings.TrimSpace(r.PublicKey) {
		return fmt.Errorf("member requires a transport-stamped public key")
	}
	if err := validDisplayText("member public key", r.PublicKey, maxPresenceIdentityText); err != nil {
		return err
	}
	if err := validDisplayText("member name", r.Name, maxPresenceName); err != nil {
		return err
	}
	if err := validDisplayText("member fqdn", r.FQDN, maxPresenceIdentityText); err != nil {
		return err
	}
	if r.Service != "" && !r.Service.valid() {
		return fmt.Errorf("unknown member service kind %q", r.Service)
	}
	if r.Address != "" {
		if err := validMeshAddress(r.Address); err != nil {
			return fmt.Errorf("member: %w", err)
		}
	}
	return nil
}

// Validate checks one steer detail's envelope shape. Exported so the steer
// sender can vet both its binding snapshot (before any POST) and an untrusted
// 200-body confirmation (falling back to the posted pair) instead of letting
// either invalidate the whole envelope after every delivery ran.
func (s FanoutSteer) Validate() error {
	if strings.TrimSpace(s.Backend) == "" || strings.TrimSpace(s.Session) == "" {
		return fmt.Errorf("steer detail requires backend and session")
	}
	if err := validDisplayText("steer backend", s.Backend, maxFanoutSteerFieldBytes); err != nil {
		return err
	}
	if err := validDisplayText("steer session", s.Session, maxFanoutSteerFieldBytes); err != nil {
		return err
	}
	return validDisplayText("steer by", s.By, maxPresenceIdentityText)
}
