package provider

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"runtime"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/xrey167/meshmcp/mcp"
)

// mapKeys is a fixed KeySource for tests.
type mapKeys map[string]string

func (m mapKeys) Get(name string) (string, bool) { v, ok := m[name]; return v, ok }

// serveErroringModel serves an MCP model whose "complete" tool returns IsError.
func serveErroringModel(t *testing.T) func(ctx context.Context) (net.Conn, error) {
	t.Helper()
	return func(ctx context.Context) (net.Conn, error) {
		c1, c2 := net.Pipe()
		s := mcp.New("bad-model", "0.1.0")
		s.AddTool(mcp.Tool{
			Name:        "complete",
			InputSchema: map[string]any{"type": "object"},
			Handler: func(ctx context.Context, args json.RawMessage) (mcp.ToolResult, error) {
				return mcp.ToolResult{Content: []mcp.Content{mcp.Text("model overloaded")}, IsError: true}, nil
			},
		})
		go func() { _ = s.Serve(context.Background(), c1, c1) }()
		return c2, nil
	}
}

// TestMCPProviderDialError asserts a failing dial surfaces as an explicit error
// (never a panic or silent empty completion).
func TestMCPProviderDialError(t *testing.T) {
	p := NewMCPProvider(MCPConfig{Name: "r", Class: "c", Dial: func(ctx context.Context) (net.Conn, error) {
		return nil, errors.New("dial refused")
	}})
	if _, err := p.Invoke(context.Background(), Prompt{User: "hi"}); err == nil {
		t.Fatal("a failing dial must return an error")
	}
}

// TestMCPProviderRemoteError asserts an is-error result from the remote tool is
// surfaced as an error.
func TestMCPProviderRemoteError(t *testing.T) {
	dial := serveErroringModel(t)
	p := NewMCPProvider(MCPConfig{Name: "r", Class: "c", Dial: dial})
	if _, err := p.Invoke(context.Background(), Prompt{User: "hi"}); err == nil {
		t.Fatal("a remote is-error result must surface as an error")
	}
}

// TestMCPProviderNilConn is the regression for a dialer that returns (nil, nil):
// it must be a clean error, never a nil-pointer panic in the mcp client.
func TestMCPProviderNilConn(t *testing.T) {
	p := NewMCPProvider(MCPConfig{Name: "r", Class: "c", Dial: func(ctx context.Context) (net.Conn, error) {
		return nil, nil
	}})
	if _, err := p.Invoke(context.Background(), Prompt{User: "hi"}); err == nil {
		t.Fatal("a nil connection from the dialer must return an error, not panic")
	}
}

// TestStripEnvKey asserts every occurrence of a key var is removed, so no ambient
// copy can survive to shadow the broker-resolved secret.
func TestStripEnvKey(t *testing.T) {
	env := []string{"A=1", "KEY=old", "B=2", "KEY=older"}
	got := stripEnvKey(env, "KEY")
	for _, kv := range got {
		if strings.HasPrefix(kv, "KEY=") {
			t.Fatalf("stripEnvKey left a KEY entry: %v", got)
		}
	}
	if len(got) != 2 {
		t.Fatalf("expected the 2 non-KEY entries to remain, got %v", got)
	}
	// The caller's slice must not be mutated.
	if env[1] != "KEY=old" {
		t.Fatalf("stripEnvKey mutated the caller's slice: %v", env)
	}
}

// TestCappedBufferTruncates asserts the buffer caps captured bytes and never
// reports a short write (which would block the child process).
func TestCappedBufferTruncates(t *testing.T) {
	c := &cappedBuffer{cap: 10}
	n, err := c.Write([]byte("0123456789ABCDEF"))
	if err != nil || n != 16 {
		t.Fatalf("Write must accept the whole slice (n=%d err=%v)", n, err)
	}
	if c.buf.Len() != 10 {
		t.Fatalf("buffer must cap at 10 bytes, got %d", c.buf.Len())
	}
	if !c.truncated {
		t.Fatal("truncated flag must be set once the cap is exceeded")
	}
}

// TestCLIPassesBrokerKeyToChild asserts the broker-resolved secret reaches the
// child through its environment (secrets-by-reference wiring intact).
func TestCLIPassesBrokerKeyToChild(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses a POSIX shell")
	}
	cli := NewCLI(CLIConfig{
		Name: "c", Class: "cls", Bin: "sh",
		Args:   []string{"-c", `printf %s "$HARNESS_TEST_KEY"`},
		KeyRef: "ref", KeyEnv: "HARNESS_TEST_KEY",
	}, mapKeys{"ref": "brokered-secret"})
	comp, err := cli.Invoke(context.Background(), Prompt{User: "ignored"})
	if err != nil {
		t.Fatalf("invoke: %v", err)
	}
	if strings.TrimSpace(comp.Text) != "brokered-secret" {
		t.Fatalf("child must receive the brokered secret, got %q", comp.Text)
	}
}

// TestMockEchoRuneSafe asserts the mock's echo truncation stays valid UTF-8.
func TestMockEchoRuneSafe(t *testing.T) {
	long := strings.Repeat("é", 300) // >240 bytes of multi-byte runes
	comp, err := NewMock("m", "c").Invoke(context.Background(), Prompt{User: long})
	if err != nil {
		t.Fatalf("invoke: %v", err)
	}
	if !utf8.ValidString(comp.Text) {
		t.Fatal("mock echo must stay valid UTF-8 after truncation")
	}
}

// TestRegistryClasses reports registered classes and Resolve honors a partial
// order preference.
func TestRegistryClasses(t *testing.T) {
	reg := NewRegistry()
	reg.Register(NewMock("a", "cls"))
	reg.Register(NewMock("b", "cls"))
	reg.SetOrder([]string{"b"}) // b preferred; a unlisted
	p, err := reg.Resolve(context.Background(), "cls")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if p.Name() != "b" {
		t.Fatalf("partial order should prefer b, got %q", p.Name())
	}
	if got := reg.Classes(); len(got) != 1 || got[0] != "cls" {
		t.Fatalf("classes = %v", got)
	}
}

// TestMockStreamDelivers asserts the mock's Stream yields the completion then done.
func TestMockStreamDelivers(t *testing.T) {
	m := NewMock("m", "c")
	ch, err := m.Stream(context.Background(), Prompt{User: "x"})
	if err != nil {
		t.Fatalf("stream: %v", err)
	}
	var text string
	var done bool
	for d := range ch {
		if d.Text != "" {
			text = d.Text
		}
		if d.Done {
			done = true
		}
	}
	if text == "" || !done {
		t.Fatalf("stream should deliver text then done: text=%q done=%v", text, done)
	}
}
