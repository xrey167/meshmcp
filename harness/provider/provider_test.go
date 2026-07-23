package provider

import (
	"context"
	"testing"
)

func TestMockInvoke(t *testing.T) {
	m := NewMock("mock", "gpt-medium")
	c, err := m.Invoke(context.Background(), Prompt{User: "hello world"})
	if err != nil {
		t.Fatalf("invoke: %v", err)
	}
	if c.Provider != "mock" || c.TokensOut == 0 {
		t.Fatalf("unexpected completion: %+v", c)
	}
}

func TestMockReplyOverride(t *testing.T) {
	m := NewMock("m", "c")
	m.Reply = func(in Prompt) string { return "scripted:" + in.User }
	c, _ := m.Invoke(context.Background(), Prompt{User: "x"})
	if c.Text != "scripted:x" {
		t.Fatalf("reply override not used: %q", c.Text)
	}
}

// stubbedUnavailable is a provider that is never available (models an outage).
type stubbedUnavailable struct{ *Mock }

func (s stubbedUnavailable) Available(context.Context) bool { return false }

func TestRegistryFallback(t *testing.T) {
	reg := NewRegistry()
	reg.Register(stubbedUnavailable{NewMock("down", "gpt-medium")})
	reg.Register(NewMock("up", "gpt-medium"))

	p, err := reg.Resolve(context.Background(), "gpt-medium")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if p.Name() != "up" {
		t.Fatalf("fallback chain should skip the unavailable provider, got %q", p.Name())
	}
}

func TestRegistryUnknownClass(t *testing.T) {
	reg := NewRegistry()
	if _, err := reg.Resolve(context.Background(), "nope"); err == nil {
		t.Fatal("unknown class should error, not silently no-op")
	}
}

func TestRegistryOrderPreference(t *testing.T) {
	reg := NewRegistry()
	reg.Register(NewMock("gemini", "c"))
	reg.Register(NewMock("claude", "c"))
	reg.SetOrder([]string{"claude", "gemini"})
	p, err := reg.Resolve(context.Background(), "c")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if p.Name() != "claude" {
		t.Fatalf("order preference should pick claude first, got %q", p.Name())
	}
}
