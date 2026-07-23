package main

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/netbirdio/netbird/client/embed"

	"github.com/xrey167/meshmcp/air"
)

// airPresenceSource is the I/O boundary for logical Air targets. Keeping the
// lookup behind this small function type lets resolution semantics be tested
// without joining a mesh, while production still reads the gateway's verified,
// TTL-pruned Presence list immediately before an action.
type airPresenceSource func(context.Context) ([]air.Presence, error)

// resolveAirTarget preserves an explicit host:port exactly. Otherwise it
// resolves a Nearby selector to the requested service through the configured
// Air control endpoint. There is deliberately no fallback: an unavailable
// control endpoint, an ambiguous selector, a missing service, or a malformed
// advertised address all fail closed before the sender dials anything.
func resolveAirTarget(ctx context.Context, target, control string, kind air.ServiceKind, source airPresenceSource) (string, error) {
	target = strings.TrimSpace(target)
	if airTargetAddressValid(target) {
		return target, nil
	}
	if target == "" {
		return "", fmt.Errorf("target is required")
	}
	if strings.TrimSpace(control) == "" {
		return "", fmt.Errorf("target %q is not a valid host:port; pass --control <gateway-host:port> to resolve a Nearby name, FQDN, or full public key", target)
	}
	if !airTargetAddressValid(strings.TrimSpace(control)) {
		return "", fmt.Errorf("--control %q is not a valid host:port", control)
	}
	if source == nil {
		return "", fmt.Errorf("resolve %q: Air control resolver is unavailable", target)
	}

	cards, err := source(ctx)
	if err != nil {
		return "", fmt.Errorf("resolve %q via Air control %s: %w", target, control, err)
	}
	resolved, err := air.ResolvePresence(cards, target, kind)
	if err != nil {
		return "", fmt.Errorf("resolve %q as service %q via Air control %s: %w", target, kind, control, err)
	}
	address := strings.TrimSpace(resolved.Service.Address)
	if !airTargetAddressValid(address) {
		return "", fmt.Errorf("resolve %q as service %q: Nearby advertised invalid address %q", target, kind, resolved.Service.Address)
	}
	return address, nil
}

// resolveAirTargetOverMesh supplies the production Presence source. The
// control request is made only for logical targets; raw host:port callers keep
// their existing direct path and do not depend on control availability.
func resolveAirTargetOverMesh(ctx context.Context, client *embed.Client, target, control string, kind air.ServiceKind) (string, error) {
	source := func(ctx context.Context) ([]air.Presence, error) {
		out, err := fetchPresence(ctx, meshDialHTTP(client, strings.TrimSpace(control)))
		if err != nil {
			return nil, err
		}
		return out.Presence, nil
	}
	return resolveAirTarget(ctx, target, control, kind, source)
}

func airTargetAddressValid(target string) bool {
	host, portText, err := net.SplitHostPort(target)
	if err != nil || strings.TrimSpace(host) == "" || portText == "" {
		return false
	}
	port, err := strconv.Atoi(portText)
	return err == nil && port > 0 && port <= 65535
}

// parseGroupSelector detects the reserved `group:<name>` DESTINATION selector
// BEFORE any presence resolution, so a presence card literally named "group:x"
// can never shadow the fan-out grammar (the air package additionally rejects
// the prefix inside every single-target resolver — fail closed at both
// layers). ok reports group syntax; err reports group syntax with a malformed
// name. A non-group selector returns ("", false, nil) untouched.
func parseGroupSelector(s string) (name string, ok bool, err error) {
	name, ok = strings.CutPrefix(strings.TrimSpace(s), "group:")
	if !ok {
		return "", false, nil
	}
	if err := air.ValidateGroupName(name); err != nil {
		return "", true, fmt.Errorf("bad group selector %q: %w", strings.TrimSpace(s), err)
	}
	return name, true, nil
}

// airGroupSource is the injectable roster lookup behind group fan-out targets,
// mirroring airPresenceSource: production fetches GET /v1/groups over the
// mesh; tests inject rosters directly.
type airGroupSource func(ctx context.Context, group string) (airGroupMembers, error)

// groupMember is one resolved fan-out destination: the member's identity-
// stamped card plus either the service address to dial or the reason it is
// skipped. A skip is per-member truth — it never aborts the other members.
type groupMember struct {
	Presence   air.Presence
	Address    string
	SkipReason string
}

// resolveAirGroupMembers resolves `group:<name>` to per-member delivery
// addresses for one service kind. Hard failures — missing/invalid control,
// unavailable resolver, unknown group, zero present members, an over-wide
// roster, a member card without a clean transport-stamped identity — happen
// BEFORE any delivery; a member missing the service or advertising an invalid
// address becomes a skip entry while the rest proceed.
func resolveAirGroupMembers(ctx context.Context, group, control string, kind air.ServiceKind, source airGroupSource) ([]groupMember, []string, error) {
	if strings.TrimSpace(control) == "" {
		return nil, nil, fmt.Errorf("group %q requires --control <gateway-host:port> to resolve members", group)
	}
	if !airTargetAddressValid(strings.TrimSpace(control)) {
		return nil, nil, fmt.Errorf("--control %q is not a valid host:port", control)
	}
	if source == nil {
		return nil, nil, fmt.Errorf("resolve group %q: Air control resolver is unavailable", group)
	}
	roster, err := source(ctx, group)
	if err != nil {
		return nil, nil, fmt.Errorf("resolve group %q via Air control %s: %w", group, control, err)
	}
	if len(roster.Members) == 0 {
		return nil, nil, emptyGroupError(group, roster.UnmatchedPatterns)
	}
	// The envelope bound is enforced BEFORE any delivery, whatever the source:
	// an over-wide roster is refused loudly up front — never delivered to in
	// full and then found unreportable by envelope validation after the loop.
	if len(roster.Members) > maxGroupMembers {
		return nil, nil, &oversizeGroupError{name: group, n: len(roster.Members)}
	}
	members := make([]groupMember, 0, len(roster.Members))
	for _, card := range roster.Members {
		// Every entry — delivered, failed, or skipped — must be representable
		// in the result envelope, so a card whose identity fields cannot be
		// carried there is a hard pre-delivery error, not a late collapse.
		if err := (air.FanoutRecipient{Name: card.Name, FQDN: card.FQDN, PublicKey: card.PublicKey}).Validate(); err != nil {
			return nil, nil, fmt.Errorf("group %q: bad member card: %w", group, err)
		}
		m := groupMember{Presence: card}
		svc, ok := presenceService(card, kind)
		address := strings.TrimSpace(svc.Address)
		switch {
		case !ok:
			m.SkipReason = fmt.Sprintf("no %q service advertised", kind)
		case !airTargetAddressValid(address) || envelopeUnsafeAddress(card, kind, address):
			m.SkipReason = "invalid advertised address"
		default:
			m.Address = address
		}
		members = append(members, m)
	}
	return members, roster.UnmatchedPatterns, nil
}

// envelopeUnsafeAddress reports an advertised address that parses as host:port
// but could not ride in a FanoutRecipient (over-long or control characters) —
// skipped per member BEFORE dialing, so it can never invalidate the whole
// result envelope after deliveries ran.
func envelopeUnsafeAddress(card air.Presence, kind air.ServiceKind, address string) bool {
	rec := air.FanoutRecipient{
		Name: card.Name, FQDN: card.FQDN, PublicKey: card.PublicKey,
		Service: kind, Address: address,
	}
	return rec.Validate() != nil
}

// presenceService selects one advertised service by kind from a member card.
func presenceService(card air.Presence, kind air.ServiceKind) (air.Service, bool) {
	for _, svc := range card.Services {
		if svc.Kind == kind {
			return svc, true
		}
	}
	return air.Service{}, false
}
