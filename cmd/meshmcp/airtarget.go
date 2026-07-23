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
