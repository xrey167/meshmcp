package secrets

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/xrey167/meshmcp/policy"
)

// recordingBackend is an in-process MCP-ish server: it records every line it
// receives (so the test can inspect what actually reached the backend) and
// replies to any request with {"ok":true}.
type recordingBackend struct {
	inR  *io.PipeReader
	inW  *io.PipeWriter
	outR *io.PipeReader
	outW *io.PipeWriter
	got  *bytes.Buffer
}

func newRecordingBackend() *recordingBackend {
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	b := &recordingBackend{inR: inR, inW: inW, outR: outR, outW: outW, got: &bytes.Buffer{}}
	go func() {
		sc := bufio.NewScanner(inR)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" {
				continue
			}
			b.got.WriteString(line + "\n")
			var m struct {
				ID json.RawMessage `json:"id"`
			}
			_ = json.Unmarshal([]byte(line), &m)
			if len(m.ID) > 0 {
				b.outW.Write([]byte(`{"jsonrpc":"2.0","id":` + string(m.ID) + `,"result":{"ok":true}}` + "\n"))
			}
		}
		b.outW.Close()
	}()
	return b
}

func (b *recordingBackend) Read(p []byte) (int, error)  { return b.outR.Read(p) }
func (b *recordingBackend) Write(p []byte) (int, error) { return b.inW.Write(p) }
func (b *recordingBackend) Close() error                { b.inW.Close(); b.outW.Close(); return nil }

// TestFilterInjectsSecretToBackendOnly is the end-to-end proof: a granted
// caller's {{secret:...}} reference is resolved and reaches the backend, while
// the trace records only the reference — the raw value never appears in the
// trace. An ungranted caller is denied inline and the backend never sees it.
func TestFilterInjectsSecretToBackendOnly(t *testing.T) {
	broker := New(
		MapStore{"stripe_key": "sk_live_SUPERSECRET"},
		[]Grant{{Peers: []string{"pubkey:AGENT"}, Secrets: []string{"stripe_*"}, Tools: []string{"charge"}}},
		nil,
	)

	run := func(peerKey string) (backendSaw, trace string, reply string) {
		backend := newRecordingBackend()
		var traceBuf bytes.Buffer
		tracer := policy.NewTracer(&traceBuf, func() string { return "T" }, policy.TraceOptions{Payloads: true})
		eng := policy.NewEngine(&policy.Policy{DefaultAllow: true}, nil, nil)
		f := policy.NewFilterEngine(backend, policy.Caller{Backend: "pay", Peer: "agent.mesh", PeerKey: peerKey}, eng, policy.NewAuditLog(nil, nil), tracer)
		f.SetSecretResolver(broker)

		replies := make(chan string, 4)
		go func() {
			sc := bufio.NewScanner(f)
			for sc.Scan() {
				replies <- sc.Text()
			}
			close(replies)
		}()
		f.Write([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"charge","arguments":{"auth":"Bearer {{secret:stripe_key}}"}}}` + "\n"))

		select {
		case r := <-replies:
			reply = r
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for reply")
		}
		return backend.got.String(), traceBuf.String(), reply
	}

	// Granted identity: the backend receives the resolved secret; the trace does not.
	saw, trace, reply := run("AGENT")
	if !strings.Contains(saw, "sk_live_SUPERSECRET") {
		t.Fatalf("backend should have received the resolved secret, got: %s", saw)
	}
	if strings.Contains(trace, "sk_live_SUPERSECRET") {
		t.Fatalf("SECRET VALUE LEAKED INTO TRACE:\n%s", trace)
	}
	if !strings.Contains(trace, "{{secret:stripe_key}}") {
		t.Fatalf("trace should record the reference form: %s", trace)
	}
	if !strings.Contains(reply, `"ok":true`) {
		t.Fatalf("granted call should have reached the backend and returned ok, got: %s", reply)
	}

	// Ungranted identity: denied inline, backend never sees the call.
	saw2, _, reply2 := run("STRANGER")
	if strings.Contains(saw2, "sk_live") || strings.Contains(saw2, "charge") {
		t.Fatalf("ungranted call must never reach the backend, but it saw: %s", saw2)
	}
	if !strings.Contains(reply2, "blocked") {
		t.Fatalf("ungranted call should be denied inline, got: %s", reply2)
	}
}
