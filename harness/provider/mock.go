package provider

import (
	"context"
	"fmt"
	"strings"
)

// Mock is a deterministic in-process Provider. It performs no inference: it
// echoes a structured, reproducible completion derived from the prompt, so the
// harness pipeline, scheduler, loops, and audit chain can be exercised end to
// end without a live model or network. It is the default provider for tests and
// for a headless run with no configured providers.
type Mock struct {
	name  string
	class string
	// Reply, when set, overrides the default echo — a test can script a
	// provider's answer (e.g. to make a verify gate pass).
	Reply func(in Prompt) string
	caps  ModelCaps
}

// NewMock builds a mock provider for a class.
func NewMock(name, class string) *Mock {
	return &Mock{
		name:  name,
		class: class,
		caps:  ModelCaps{Name: name, Class: class, Context: 200_000, Vision: true, MaxOut: 8192},
	}
}

func (m *Mock) Name() string                       { return m.name }
func (m *Mock) Class() string                      { return m.class }
func (m *Mock) Capabilities() ModelCaps            { return m.caps }
func (m *Mock) Available(ctx context.Context) bool { return true }

// Invoke returns a deterministic completion. Token counts are derived from the
// input/output length so budget accounting is exercised realistically.
func (m *Mock) Invoke(ctx context.Context, in Prompt) (Completion, error) {
	select {
	case <-ctx.Done():
		return Completion{}, ctx.Err()
	default:
	}
	var text string
	if m.Reply != nil {
		text = m.Reply(in)
	} else {
		text = m.echo(in)
	}
	return Completion{
		Text:      text,
		TokensIn:  estimateTokens(in.System) + estimateTokens(in.User),
		TokensOut: estimateTokens(text),
		Provider:  m.name,
	}, nil
}

// Stream chunks Invoke's completion into deltas.
func (m *Mock) Stream(ctx context.Context, in Prompt) (<-chan Delta, error) {
	c, err := m.Invoke(ctx, in)
	if err != nil {
		return nil, err
	}
	ch := make(chan Delta, 2)
	ch <- Delta{Text: c.Text}
	ch <- Delta{Done: true}
	close(ch)
	return ch, nil
}

func (m *Mock) echo(in Prompt) string {
	var b strings.Builder
	fmt.Fprintf(&b, "[%s/%s] ", m.name, m.class)
	user := strings.TrimSpace(in.User)
	if len(user) > 240 {
		user = user[:240] + "…"
	}
	b.WriteString(user)
	if len(in.Files) > 0 {
		fmt.Fprintf(&b, " (over %d file(s))", len(in.Files))
	}
	return b.String()
}

// estimateTokens is a cheap 4-chars-per-token estimate, enough for budget tests.
func estimateTokens(s string) int {
	if s == "" {
		return 0
	}
	return (len(s) + 3) / 4
}
