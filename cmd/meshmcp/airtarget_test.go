package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/xrey167/meshmcp/air"
)

func TestResolveAirTargetRawAddressBypassesPresence(t *testing.T) {
	called := false
	source := func(context.Context) ([]air.Presence, error) {
		called = true
		return nil, errors.New("should not be called")
	}

	got, err := resolveAirTarget(context.Background(), "100.64.0.8:9110", "", air.ServiceInbox, source)
	if err != nil {
		t.Fatalf("resolve raw target: %v", err)
	}
	if got != "100.64.0.8:9110" {
		t.Fatalf("raw target = %q, want unchanged address", got)
	}
	if called {
		t.Fatal("raw target unexpectedly consulted Presence")
	}
}

func TestResolveAirTargetVerifiedSelectors(t *testing.T) {
	cards := []air.Presence{{
		Name:      "Analyst",
		FQDN:      "analyst.mesh.internal",
		PublicKey: "analyst-full-public-key",
		Services: []air.Service{{
			Kind:    air.ServiceInbox,
			Address: "100.64.0.8:9110",
		}},
	}}

	for _, selector := range []string{"Analyst", "ANALYST.MESH.INTERNAL", "analyst-full-public-key"} {
		t.Run(selector, func(t *testing.T) {
			calls := 0
			source := func(context.Context) ([]air.Presence, error) {
				calls++
				return cards, nil
			}
			got, err := resolveAirTarget(context.Background(), selector, "100.64.0.1:9443", air.ServiceInbox, source)
			if err != nil {
				t.Fatalf("resolve %q: %v", selector, err)
			}
			if got != "100.64.0.8:9110" {
				t.Fatalf("resolve %q = %q", selector, got)
			}
			if calls != 1 {
				t.Fatalf("Presence calls = %d, want 1", calls)
			}
		})
	}
}

func TestResolveAirTargetSelectsRequestedService(t *testing.T) {
	cards := []air.Presence{{
		Name: "Studio", FQDN: "studio.mesh", PublicKey: "studio-key",
		Services: []air.Service{
			{Kind: air.ServiceInbox, Address: "100.64.0.8:9110"},
			{Kind: air.ServiceRing, Address: "100.64.0.8:9120"},
			{Kind: air.ServiceCast, Address: "100.64.0.8:9130"},
			{Kind: air.ServiceScreen, Address: "100.64.0.8:9140"},
		},
	}}
	source := func(context.Context) ([]air.Presence, error) { return cards, nil }

	for _, tc := range []struct {
		kind air.ServiceKind
		want string
	}{
		{air.ServiceInbox, "100.64.0.8:9110"},
		{air.ServiceRing, "100.64.0.8:9120"},
		{air.ServiceCast, "100.64.0.8:9130"},
		{air.ServiceScreen, "100.64.0.8:9140"},
	} {
		t.Run(string(tc.kind), func(t *testing.T) {
			got, err := resolveAirTarget(context.Background(), "Studio", "100.64.0.1:9443", tc.kind, source)
			if err != nil {
				t.Fatalf("resolve %s: %v", tc.kind, err)
			}
			if got != tc.want {
				t.Fatalf("resolve %s = %q, want %q", tc.kind, got, tc.want)
			}
		})
	}
}

func TestResolveAirTargetAmbiguousNameFailsClosed(t *testing.T) {
	source := func(context.Context) ([]air.Presence, error) {
		return []air.Presence{
			{Name: "Analyst", FQDN: "one.mesh", PublicKey: "key-one", Services: []air.Service{{Kind: air.ServiceRing, Address: "100.64.0.8:9122"}}},
			{Name: "analyst", FQDN: "two.mesh", PublicKey: "key-two", Services: []air.Service{{Kind: air.ServiceRing, Address: "100.64.0.9:9122"}}},
		}, nil
	}

	_, err := resolveAirTarget(context.Background(), "analyst", "100.64.0.1:9443", air.ServiceRing, source)
	if err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("ambiguous resolve error = %v", err)
	}
}

func TestResolveAirTargetMissingServiceFailsClosed(t *testing.T) {
	source := func(context.Context) ([]air.Presence, error) {
		return []air.Presence{{
			Name: "Analyst", FQDN: "analyst.mesh", PublicKey: "key-analyst",
			Services: []air.Service{{Kind: air.ServiceInbox, Address: "100.64.0.8:9110"}},
		}}, nil
	}

	_, err := resolveAirTarget(context.Background(), "Analyst", "100.64.0.1:9443", air.ServiceScreen, source)
	if err == nil || !strings.Contains(err.Error(), `does not advertise service "screen"`) {
		t.Fatalf("missing-service error = %v", err)
	}
}

func TestResolveAirTargetUnavailableControlFailsClosed(t *testing.T) {
	unavailable := errors.New("control endpoint unavailable")
	source := func(context.Context) ([]air.Presence, error) { return nil, unavailable }

	_, err := resolveAirTarget(context.Background(), "Analyst", "100.64.0.1:9443", air.ServiceInbox, source)
	if err == nil || !errors.Is(err, unavailable) || !strings.Contains(err.Error(), "Air control") {
		t.Fatalf("unavailable-control error = %v", err)
	}
}

func TestResolveAirTargetInvalidControlFailsBeforeLookup(t *testing.T) {
	called := false
	source := func(context.Context) ([]air.Presence, error) {
		called = true
		return nil, nil
	}

	_, err := resolveAirTarget(context.Background(), "Analyst", "not-a-host-port", air.ServiceInbox, source)
	if err == nil || !strings.Contains(err.Error(), "--control") || !strings.Contains(err.Error(), "valid host:port") {
		t.Fatalf("invalid-control error = %v", err)
	}
	if called {
		t.Fatal("invalid control unexpectedly consulted Presence")
	}
}

func TestResolveAirTargetInvalidAdvertisedAddressFailsClosed(t *testing.T) {
	source := func(context.Context) ([]air.Presence, error) {
		return []air.Presence{{
			Name: "Analyst", FQDN: "analyst.mesh", PublicKey: "key-analyst",
			Services: []air.Service{{Kind: air.ServiceInbox, Address: "not-a-host-port"}},
		}}, nil
	}

	_, err := resolveAirTarget(context.Background(), "Analyst", "100.64.0.1:9443", air.ServiceInbox, source)
	if err == nil || !strings.Contains(err.Error(), "advertised invalid address") {
		t.Fatalf("invalid-advertised-address error = %v", err)
	}
}

func TestResolveAirTargetMissingPresenceFailsClosed(t *testing.T) {
	source := func(context.Context) ([]air.Presence, error) { return []air.Presence{}, nil }

	_, err := resolveAirTarget(context.Background(), "Departed Agent", "100.64.0.1:9443", air.ServiceInbox, source)
	if err == nil || !strings.Contains(err.Error(), "no nearby node matches") {
		t.Fatalf("missing-presence error = %v", err)
	}
}

func TestResolveAirTargetLogicalNameRequiresControl(t *testing.T) {
	_, err := resolveAirTarget(context.Background(), "Analyst", "", air.ServiceInbox, nil)
	if err == nil || !strings.Contains(err.Error(), "--control") {
		t.Fatalf("missing-control error = %v", err)
	}
}
