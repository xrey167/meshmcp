package air

// Action receipts are the bounded, portable result of a user-facing Air
// action. They deliberately describe only delivery metadata: the selected
// transport-stamped identity, the service address actually used, payload name
// and size, and the result time. Raw payloads, credentials, capability tokens,
// and arbitrary action parameters never belong in this contract.

import (
	"fmt"
	"strings"
	"time"
)

const (
	// ActionReceiptSchemaV1 is the first portable action-result contract.
	ActionReceiptSchemaV1 = "air.action-receipt/v1"

	// MaxActionPayloadBytes matches the browser relay's bounded upload surface.
	// A receipt emitted by Resolved Send can never claim a larger payload.
	MaxActionPayloadBytes int64 = 8 << 20

	// MaxActionPayloads and MaxActionTotalBytes bound a multi-payload result and
	// its private staging footprint across CLI and assistant surfaces.
	MaxActionPayloads         = 256
	MaxActionTotalBytes int64 = 64 << 20

	// MaxActionPayloadNameBytes bounds the display-only payload name in a
	// receipt. The payload itself is never included.
	MaxActionPayloadNameBytes = 255

	// maxActionReceiptTimeBytes is the longest RFC3339Nano timestamp shape.
	// time.Parse accepts arbitrarily long fractional seconds, so the explicit
	// bound is what keeps externally validated receipts bounded.
	maxActionReceiptTimeBytes = len(time.RFC3339Nano)
)

// ActionKind is the concrete delivery operation represented by a receipt.
type ActionKind string

const (
	ActionPush ActionKind = "push"
	ActionDrop ActionKind = "drop"
)

// ActionStatus is the terminal state represented by a returned receipt. Failed
// deliveries are returned as errors and therefore never receive a misleading
// delivered receipt.
type ActionStatus string

const ActionDelivered ActionStatus = "delivered"

// ActionRecipient records where delivery was attempted. A Presence-resolved
// recipient carries the full transport-stamped identity. A legacy raw
// host:port recipient carries only Service and Address, never a claimed name or
// key. Address is routing metadata; the receiver's ACL/policy remains the
// authority when the connection arrives.
type ActionRecipient struct {
	Name      string      `json:"name,omitempty"`
	FQDN      string      `json:"fqdn,omitempty"`
	PublicKey string      `json:"public_key,omitempty"`
	Service   ServiceKind `json:"service"`
	Address   string      `json:"address"`
}

// Validate checks the bounded recipient metadata. Resolved descriptive fields
// require a transport-stamped public key so a receipt cannot present an
// unverified friendly name as identity. A completely identity-free recipient
// is retained for legacy raw host:port compatibility.
func (r ActionRecipient) Validate() error {
	if r.Service != ServiceInbox {
		return fmt.Errorf("action recipient service must be %q", ServiceInbox)
	}
	if err := validMeshAddress(r.Address); err != nil {
		return fmt.Errorf("action recipient: %w", err)
	}
	if err := validDisplayText("action recipient name", r.Name, maxPresenceName); err != nil {
		return err
	}
	if err := validDisplayText("action recipient fqdn", r.FQDN, maxPresenceIdentityText); err != nil {
		return err
	}
	if err := validDisplayText("action recipient public key", r.PublicKey, maxPresenceIdentityText); err != nil {
		return err
	}
	if r.PublicKey != strings.TrimSpace(r.PublicKey) {
		return fmt.Errorf("action recipient public key must not have surrounding whitespace")
	}
	if r.PublicKey == "" && (r.Name != "" || r.FQDN != "") {
		return fmt.Errorf("action recipient descriptive identity requires a transport-stamped public key")
	}
	return nil
}

// ActionReceipt is returned only after the existing resumable push/drop
// transport reports success. It contains no payload body or executable action
// parameters and is safe to render across CLI, web, and MCP surfaces.
type ActionReceipt struct {
	Schema      string          `json:"schema"`
	Action      ActionKind      `json:"action"`
	Status      ActionStatus    `json:"status"`
	Recipient   ActionRecipient `json:"recipient"`
	PayloadName string          `json:"payload_name"`
	Bytes       int64           `json:"bytes"`
	Time        string          `json:"time"`
}

const ActionResultSchemaV1 = "air.action-result/v1"

// ActionResult is the shared, bounded response envelope used by web, CLI, and
// MCP action surfaces. A browser action has one receipt; a mixed CLI/MCP send
// can have several. Payload bodies, local source paths, credentials, and
// capability material are never represented.
type ActionResult struct {
	Schema    string          `json:"schema"`
	Status    ActionStatus    `json:"status"`
	Recipient ActionRecipient `json:"recipient"`
	Payloads  int             `json:"payloads"`
	Bytes     int64           `json:"bytes"`
	Receipts  []ActionReceipt `json:"receipts"`
}

// NewActionReceipt constructs and validates a delivered receipt. Callers should
// construct it before starting the side effect (to reject bad metadata), return
// it only after delivery succeeds, and never add the payload to the result.
func NewActionReceipt(action ActionKind, recipient ActionRecipient, payloadName string, payloadBytes int64, now time.Time) (ActionReceipt, error) {
	if now.IsZero() {
		return ActionReceipt{}, fmt.Errorf("action receipt time is required")
	}
	r := ActionReceipt{
		Schema:      ActionReceiptSchemaV1,
		Action:      action,
		Status:      ActionDelivered,
		Recipient:   recipient,
		PayloadName: payloadName,
		Bytes:       payloadBytes,
		Time:        now.UTC().Format(time.RFC3339Nano),
	}
	if err := r.Validate(); err != nil {
		return ActionReceipt{}, err
	}
	return r, nil
}

// NewActionResult constructs one portable result from receipts that were
// validated before delivery. Callers still return it only after the transport
// confirms success.
func NewActionResult(recipient ActionRecipient, receipts []ActionReceipt) (ActionResult, error) {
	result := ActionResult{
		Schema:    ActionResultSchemaV1,
		Status:    ActionDelivered,
		Recipient: recipient,
		Payloads:  len(receipts),
		Receipts:  append([]ActionReceipt(nil), receipts...),
	}
	for i, receipt := range receipts {
		if err := receipt.Validate(); err != nil {
			return ActionResult{}, fmt.Errorf("action result receipt %d: %w", i, err)
		}
		if receipt.Recipient != recipient {
			return ActionResult{}, fmt.Errorf("action result receipt %d has a different recipient", i)
		}
		if receipt.Bytes > MaxActionTotalBytes-result.Bytes {
			return ActionResult{}, fmt.Errorf("action result exceeds %d total bytes", MaxActionTotalBytes)
		}
		result.Bytes += receipt.Bytes
	}
	if err := result.Validate(); err != nil {
		return ActionResult{}, err
	}
	return result, nil
}

// Validate checks every receipt field and keeps its total shape bounded.
func (r ActionReceipt) Validate() error {
	if r.Schema != ActionReceiptSchemaV1 {
		return fmt.Errorf("action receipt schema must be %q", ActionReceiptSchemaV1)
	}
	switch r.Action {
	case ActionPush, ActionDrop:
	default:
		return fmt.Errorf("unknown action %q", r.Action)
	}
	if r.Status != ActionDelivered {
		return fmt.Errorf("unknown action status %q", r.Status)
	}
	if err := r.Recipient.Validate(); err != nil {
		return err
	}
	if strings.TrimSpace(r.PayloadName) == "" {
		return fmt.Errorf("action payload name is required")
	}
	if err := validDisplayText("action payload name", r.PayloadName, MaxActionPayloadNameBytes); err != nil {
		return err
	}
	if r.Bytes < 0 || r.Bytes > MaxActionPayloadBytes {
		return fmt.Errorf("action payload bytes must be between 0 and %d", MaxActionPayloadBytes)
	}
	if err := validDisplayText("action receipt time", r.Time, maxActionReceiptTimeBytes); err != nil {
		return err
	}
	if _, err := time.Parse(time.RFC3339Nano, r.Time); err != nil {
		return fmt.Errorf("action receipt time %q is not RFC3339: %w", r.Time, err)
	}
	return nil
}

// Validate checks the envelope totals and proves every enclosed receipt refers
// to the same selected recipient. This prevents a presentation layer from
// accidentally combining deliveries to different identities into one result.
func (r ActionResult) Validate() error {
	if r.Schema != ActionResultSchemaV1 {
		return fmt.Errorf("action result schema must be %q", ActionResultSchemaV1)
	}
	if r.Status != ActionDelivered {
		return fmt.Errorf("unknown action result status %q", r.Status)
	}
	if err := r.Recipient.Validate(); err != nil {
		return err
	}
	if len(r.Receipts) == 0 || len(r.Receipts) > MaxActionPayloads {
		return fmt.Errorf("action result must contain between 1 and %d receipts", MaxActionPayloads)
	}
	if r.Payloads != len(r.Receipts) {
		return fmt.Errorf("action result payload count %d does not match %d receipts", r.Payloads, len(r.Receipts))
	}
	var total int64
	for i, receipt := range r.Receipts {
		if err := receipt.Validate(); err != nil {
			return fmt.Errorf("action result receipt %d: %w", i, err)
		}
		if receipt.Recipient != r.Recipient {
			return fmt.Errorf("action result receipt %d has a different recipient", i)
		}
		if receipt.Bytes > MaxActionTotalBytes-total {
			return fmt.Errorf("action result exceeds %d total bytes", MaxActionTotalBytes)
		}
		total += receipt.Bytes
	}
	if r.Bytes != total {
		return fmt.Errorf("action result byte count %d does not match receipt total %d", r.Bytes, total)
	}
	return nil
}
