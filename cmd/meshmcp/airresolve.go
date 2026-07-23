package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/xrey167/meshmcp/air"
)

// airActionError carries the HTTP status appropriate for an Air action request.
// Resolution mistakes are 400s; an unavailable/malformed control dependency is
// a 502/503. Keeping the distinction here lets push and drop report identical,
// useful errors without duplicating transport policy in each handler.
type airActionError struct {
	status int
	text   string
}

func (e *airActionError) Error() string { return e.text }

func newAirActionError(status int, format string, args ...any) error {
	return &airActionError{status: status, text: fmt.Sprintf(format, args...)}
}

func airActionStatus(err error) int {
	if e, ok := err.(*airActionError); ok {
		return e.status
	}
	return http.StatusInternalServerError
}

// resolveActionRecipient chooses exactly one addressing mode. A legacy target
// is validated and used directly. A logical `to` selector is resolved from a
// fresh, browser-attributed Presence read immediately before delivery. The
// result is routing metadata only: connecting to it still crosses the receiver's
// existing mesh ACL/policy/audit boundary.
func (d airServeDeps) resolveActionRecipient(r *http.Request, to, target string) (air.ActionRecipient, error) {
	target = strings.TrimSpace(target)
	toProvided := to != ""
	switch {
	case toProvided && target != "":
		return air.ActionRecipient{}, newAirActionError(http.StatusBadRequest, "give either to or target, not both")
	case !toProvided && target == "":
		return air.ActionRecipient{}, newAirActionError(http.StatusBadRequest, "to or target is required")
	case target != "":
		if !validMeshTarget(target) {
			return air.ActionRecipient{}, newAirActionError(http.StatusBadRequest, "target must be a mesh host:port with port 1..65535")
		}
		recipient := air.ActionRecipient{Service: air.ServiceInbox, Address: target}
		if err := recipient.Validate(); err != nil {
			return air.ActionRecipient{}, newAirActionError(http.StatusBadRequest, "%v", err)
		}
		return recipient, nil
	default:
		return d.resolveInboxRecipient(r, to)
	}
}

// resolveInboxRecipient fetches the gateway's transport-stamped Presence view
// for every logical action. It does not cache addresses: a short-lived card can
// expire or move, and the action should use the freshest gateway observation.
func (d airServeDeps) resolveInboxRecipient(r *http.Request, selector string) (air.ActionRecipient, error) {
	if err := air.ValidatePresenceSelector(selector); err != nil {
		return air.ActionRecipient{}, newAirActionError(http.StatusBadRequest, "resolve recipient: %v", err)
	}
	if d.controlBase == "" || d.controlHC == nil {
		return air.ActionRecipient{}, newAirActionError(http.StatusServiceUnavailable, "logical recipients require a configured Air control endpoint")
	}
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, d.controlBase+"/v1/presence", nil)
	if err != nil {
		return air.ActionRecipient{}, newAirActionError(http.StatusBadGateway, "presence lookup: %v", err)
	}
	// Preserve the existing relay-attestation chain: the control endpoint sees
	// which browser selected the recipient, while still trusting only the
	// explicitly allow-listed relay to make that attribution.
	d.attest(req, r)
	resp, err := d.controlHC.Do(req)
	if err != nil {
		return air.ActionRecipient{}, newAirActionError(http.StatusBadGateway, "presence lookup: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		status := http.StatusBadGateway
		if resp.StatusCode == http.StatusForbidden {
			status = http.StatusForbidden
		}
		return air.ActionRecipient{}, newAirActionError(status, "presence lookup: %v", readPresenceHTTPError(resp))
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxPresenceListBytes+1))
	if err != nil {
		return air.ActionRecipient{}, newAirActionError(http.StatusBadGateway, "presence lookup: %v", err)
	}
	if len(body) > maxPresenceListBytes {
		return air.ActionRecipient{}, newAirActionError(http.StatusBadGateway, "presence lookup response is too large")
	}
	var out presenceResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return air.ActionRecipient{}, newAirActionError(http.StatusBadGateway, "presence lookup returned invalid JSON")
	}
	resolved, err := air.ResolvePresence(out.Presence, selector, air.ServiceInbox)
	if err != nil {
		return air.ActionRecipient{}, newAirActionError(http.StatusBadRequest, "resolve recipient: %v", err)
	}
	if !airServiceHasCapability(resolved.Service, air.InboxCompletionCapabilityV1) {
		return air.ActionRecipient{}, newAirActionError(http.StatusConflict,
			"resolve recipient: inbox does not advertise receiver-confirmed delivery (%s)", air.InboxCompletionCapabilityV1)
	}
	// A real gateway always stamps a full WireGuard key. Refuse malformed relay
	// data instead of returning a receipt that presents a friendly name as proof.
	if resolved.Node.PublicKey == "" {
		return air.ActionRecipient{}, newAirActionError(http.StatusBadGateway, "presence lookup returned an unstamped recipient")
	}
	recipient := air.ActionRecipient{
		Name:      resolved.Node.Name,
		FQDN:      resolved.Node.FQDN,
		PublicKey: resolved.Node.PublicKey,
		Service:   air.ServiceInbox,
		Address:   resolved.Service.Address,
	}
	if err := recipient.Validate(); err != nil {
		return air.ActionRecipient{}, newAirActionError(http.StatusBadGateway, "presence lookup returned an invalid recipient: %v", err)
	}
	return recipient, nil
}
