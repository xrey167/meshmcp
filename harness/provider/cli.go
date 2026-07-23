package provider

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// CLI is a generic adapter that drives an external model CLI (Claude Code,
// Codex/GPT, Gemini) as a subprocess. It is the concrete mechanism behind the
// claude/codex/gemini/local adapters: the harness does not embed an inference
// engine, it invokes the provider's own CLI.
//
// The API key is fetched by reference name from a KeySource at invoke time and
// passed to the child ONLY through its environment — never logged, never placed
// in the prompt. When the binary is absent the adapter reports Available=false
// so the fallback chain moves on rather than failing the run.
type CLI struct {
	name   string
	class  string
	bin    string   // executable name (looked up on PATH)
	args   []string // fixed args before the prompt (e.g. ["-p"] for print mode)
	keyRef string   // secret reference name, e.g. "provider/claude/api_key"
	keyEnv string   // env var the CLI reads the key from, e.g. "ANTHROPIC_API_KEY"
	keys   KeySource
	caps   ModelCaps
}

// CLIConfig configures a CLI adapter.
type CLIConfig struct {
	Name   string
	Class  string
	Bin    string
	Args   []string
	KeyRef string
	KeyEnv string
	Caps   ModelCaps
}

// NewCLI builds a CLI adapter. keys may be nil (then the adapter relies on the
// ambient environment already holding the key — used for local models with no
// key). In production keys is the identity-scoped secrets broker.
func NewCLI(cfg CLIConfig, keys KeySource) *CLI {
	caps := cfg.Caps
	if caps.Name == "" {
		caps.Name = cfg.Name
	}
	if caps.Class == "" {
		caps.Class = cfg.Class
	}
	return &CLI{
		name:   cfg.Name,
		class:  cfg.Class,
		bin:    cfg.Bin,
		args:   cfg.Args,
		keyRef: cfg.KeyRef,
		keyEnv: cfg.KeyEnv,
		keys:   keys,
		caps:   caps,
	}
}

func (c *CLI) Name() string            { return c.name }
func (c *CLI) Class() string           { return c.class }
func (c *CLI) Capabilities() ModelCaps { return c.caps }

// Available reports whether the CLI binary is on PATH. A missing key does not
// make the provider unavailable here — the key is checked at Invoke so a
// misconfigured key surfaces as an explicit, audited error rather than a silent
// skip that hides the misconfiguration.
func (c *CLI) Available(ctx context.Context) bool {
	if c.bin == "" {
		return false
	}
	_, err := exec.LookPath(c.bin)
	return err == nil
}

// Invoke runs the CLI once with the prompt on stdin and returns its stdout.
func (c *CLI) Invoke(ctx context.Context, in Prompt) (Completion, error) {
	env := os.Environ()
	if c.keyEnv != "" && c.keyRef != "" && c.keys != nil {
		val, ok := c.keys.Get(c.keyRef)
		if !ok {
			return Completion{}, fmt.Errorf("provider %s: secret %q not available from the broker", c.name, c.keyRef)
		}
		env = append(env, c.keyEnv+"="+val)
	}
	prompt := in.User
	if in.System != "" {
		prompt = in.System + "\n\n" + in.User
	}
	cmd := exec.CommandContext(ctx, c.bin, c.args...)
	cmd.Env = env
	cmd.Stdin = strings.NewReader(prompt)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		return Completion{}, fmt.Errorf("provider %s: %w: %s", c.name, err, strings.TrimSpace(errb.String()))
	}
	text := out.String()
	return Completion{
		Text:      text,
		TokensIn:  estimateTokens(prompt),
		TokensOut: estimateTokens(text),
		Provider:  c.name,
	}, nil
}

// Stream runs Invoke and delivers the whole output as one delta (the built-in
// CLIs are used in print mode; per-token streaming would require the CLI's
// stream protocol).
func (c *CLI) Stream(ctx context.Context, in Prompt) (<-chan Delta, error) {
	comp, err := c.Invoke(ctx, in)
	if err != nil {
		return nil, err
	}
	ch := make(chan Delta, 2)
	ch <- Delta{Text: comp.Text}
	ch <- Delta{Done: true}
	close(ch)
	return ch, nil
}
