package policy

import (
	"bufio"
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestRedactorBasic(t *testing.T) {
	r := &Redactor{}
	r.Add([]byte("sk-LIVE-abcdef123456"))
	got := r.Redact([]byte(`{"echo":"your key is sk-LIVE-abcdef123456 ok"}`))
	if bytes.Contains(got, []byte("sk-LIVE-abcdef123456")) {
		t.Fatalf("secret not redacted: %s", got)
	}
	if !bytes.Contains(got, redactPlaceholder) {
		t.Fatalf("placeholder missing: %s", got)
	}
}

func TestRedactorMultipleAndUnicode(t *testing.T) {
	r := &Redactor{}
	r.Add([]byte("AKIA1234567890"), []byte("пароль-секрет-1234"))
	in := []byte(`{"a":"AKIA1234567890","b":"пароль-секрет-1234","c":"safe"}`)
	got := r.Redact(in)
	if bytes.Contains(got, []byte("AKIA1234567890")) || bytes.Contains(got, []byte("пароль-секрет-1234")) {
		t.Fatalf("multi/unicode secret leaked: %s", got)
	}
	if !bytes.Contains(got, []byte("safe")) {
		t.Fatalf("non-secret content should survive: %s", got)
	}
}

func TestRedactorIgnoresShortAndNoMatch(t *testing.T) {
	r := &Redactor{}
	r.Add([]byte("ab")) // shorter than redactMinLen → ignored (avoids over-match)
	if r.active() {
		t.Fatal("a too-short value must not activate the redactor")
	}
	r.Add([]byte("longenough-secret"))
	in := []byte(`{"nothing":"to see"}`)
	if got := r.Redact(in); !bytes.Equal(got, in) {
		t.Fatalf("no-match input should pass through unchanged, got %s", got)
	}
}

func TestRedactorNilSafe(t *testing.T) {
	var r *Redactor
	in := []byte("hello")
	if got := r.Redact(in); !bytes.Equal(got, in) || r.active() {
		t.Fatal("nil redactor must be a safe no-op")
	}
}

// echoSecretResolver injects a fixed secret in place of the {{secret}} marker
// and reports it as injected, so the filter can redact it from responses.
type echoSecretResolver struct{ value string }

func (m echoSecretResolver) Resolve(_ Caller, _ string, line []byte, _ map[string]bool) ([]byte, [][]byte, bool, string) {
	if !bytes.Contains(line, []byte("{{secret}}")) {
		return line, nil, true, ""
	}
	out := bytes.ReplaceAll(line, []byte("{{secret}}"), []byte(m.value))
	return out, [][]byte{[]byte(m.value)}, true, ""
}

// TestFilterRedactsEchoedSecret is the Phase-8 end-to-end: a backend that echoes
// an injected secret in its response must not deliver that value to the agent.
func TestFilterRedactsEchoedSecret(t *testing.T) {
	const secret = "sk-LIVE-supersecret-0987654321"
	backend := newRecEchoBackend()
	pol := &Policy{DefaultAllow: false, Rules: []Rule{{Peers: []string{"*"}, Tools: []string{"charge"}, Allow: true}}}
	f := NewFilter(backend, Caller{Backend: "pay", Peer: "p"}, pol,
		NewAuditLog(&bytes.Buffer{}, func() string { return "T" }), nil)
	f.SetSecretResolver(echoSecretResolver{value: secret})

	replies := make(chan string, 4)
	go func() {
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 64*1024), 1<<20)
		for sc.Scan() {
			if l := strings.TrimSpace(sc.Text()); l != "" {
				replies <- l
			}
		}
		close(replies)
	}()

	// The client sends a reference; the resolver injects the real secret toward
	// the backend, which echoes it back.
	f.Write([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"charge","arguments":{"key":"{{secret}}"}}}` + "\n"))

	select {
	case r := <-replies:
		if strings.Contains(r, secret) {
			t.Fatalf("injected secret was echoed to the agent (not redacted): %s", r)
		}
		if !strings.Contains(r, "redacted-secret") {
			t.Fatalf("expected the response to carry the redaction placeholder: %s", r)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for the echoed reply")
	}

	// The backend really did receive the injected secret (proving the redaction
	// happened on the RESPONSE side, not by failing to inject).
	if got := backend.recorded(); !strings.Contains(got, secret) {
		t.Fatalf("backend should have received the injected secret: %s", got)
	}
}

// newRecEchoBackend returns a recBackend variant whose tools/call reply echoes
// the arguments it received.
func newRecEchoBackend() *recEchoBackend {
	b := &recEchoBackend{recBackend: newRecBackend()}
	return b
}

type recEchoBackend struct{ *recBackend }

func (b *recEchoBackend) Write(p []byte) (int, error) {
	line := strings.TrimSpace(string(p))
	if line != "" {
		b.mu.Lock()
		b.got = append(b.got, line)
		b.mu.Unlock()
	}
	var m rpcPeek
	if json.Unmarshal([]byte(line), &m) == nil && len(m.ID) != 0 && m.Method == "tools/call" {
		reply := `{"jsonrpc":"2.0","id":` + string(m.ID) + `,"result":{"echo":` + string(m.Params.Arguments) + `}}` + "\n"
		go func() { _, _ = b.toCallerW.Write([]byte(reply)) }()
	}
	return len(p), nil
}
