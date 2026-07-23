// Package provider adapts external model CLIs/APIs behind one uniform Provider
// interface, so the harness routes work across Claude / GPT / Gemini / local
// models by MODEL CLASS rather than by a hard-coded provider. The class →
// provider indirection (Registry) is what makes routing provider-agnostic and
// lets a fallback chain react to rate limits and outages.
//
// A provider never receives a raw API key through a prompt or config: it
// requests its key by reference name from a KeySource (satisfied by
// secrets.Store), which the harness backs with the identity-scoped secrets
// broker. The harness DRIVES providers; it is not itself an inference engine.
package provider

import "context"

// Prompt is a uniform invocation request.
type Prompt struct {
	System    string   // system instruction
	User      string   // the task/user text
	Files     []string // context file paths (read by the adapter/CLI)
	MaxTokens int      // 0 = provider default
}

// Completion is a uniform, non-streamed result.
type Completion struct {
	Text      string
	TokensIn  int
	TokensOut int
	Provider  string
}

// Delta is one streamed chunk.
type Delta struct {
	Text string
	Done bool
	Err  error
}

// ModelCaps is a provider's capability metadata (from a models.dev-backed cache
// in production; static for the built-in adapters).
type ModelCaps struct {
	Name    string
	Class   string
	Context int  // context window in tokens
	Vision  bool // accepts images/PDF/diagrams
	MaxOut  int
}

// Provider adapts one external model/CLI/MCP behind a uniform call.
type Provider interface {
	Name() string
	// Class is the model class this provider satisfies (e.g. "gpt-medium").
	Class() string
	Capabilities() ModelCaps
	// Available reports whether the provider can be invoked right now (binary
	// present, not rate-limited). The fallback chain consults it before Invoke.
	Available(ctx context.Context) bool
	Invoke(ctx context.Context, in Prompt) (Completion, error)
	Stream(ctx context.Context, in Prompt) (<-chan Delta, error)
}

// KeySource resolves a secret reference name to its value. secrets.Store
// satisfies it (Get(name) (string, bool)); the harness backs it with the
// identity-scoped broker so a worker's provider key is never embedded in a
// prompt or config.
type KeySource interface {
	Get(name string) (string, bool)
}
