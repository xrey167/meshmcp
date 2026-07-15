package policy

import (
	"bufio"
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestTracerRecordsBothDirections(t *testing.T) {
	backend := newEchoBackend()
	var buf bytes.Buffer
	tr := NewTracer(&buf, func() string { return "T" }, TraceOptions{})
	// No policy: tracing-only. Everything forwards, everything is recorded.
	f := NewFilter(backend, Caller{Backend: "fs", Peer: "p.netbird.cloud"}, nil, nil, tr)

	replies := make(chan string, 8)
	go func() {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			replies <- sc.Text()
		}
		close(replies)
	}()
	write := func(s string) {
		if _, err := f.Write([]byte(s + "\n")); err != nil {
			t.Fatalf("write: %v", err)
		}
	}

	write(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
	write(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"go.mod"}}}`)

	// Wait for both responses so all four messages have been recorded.
	got := 0
	timeout := time.After(5 * time.Second)
	for got < 2 {
		select {
		case <-replies:
			got++
		case <-timeout:
			t.Fatalf("timed out waiting for replies")
		}
	}

	var events []TraceEvent
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		var ev TraceEvent
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("bad trace line %q: %v", line, err)
		}
		events = append(events, ev)
	}

	var sawC2SToolReq, sawS2CResp bool
	for _, ev := range events {
		if ev.Dir == "c2s" && ev.Kind == "request" && ev.Method == "tools/call" {
			if ev.Tool != "read_file" {
				t.Fatalf("tool not captured: %+v", ev)
			}
			if ev.RPCID != "2" {
				t.Fatalf("rpc id not captured: %+v", ev)
			}
			sawC2SToolReq = true
		}
		if ev.Dir == "s2c" && ev.Kind == "response" {
			sawS2CResp = true
		}
		if ev.Peer != "p.netbird.cloud" || ev.Backend != "fs" {
			t.Fatalf("identity not stamped: %+v", ev)
		}
	}
	if !sawC2SToolReq {
		t.Fatalf("no c2s tools/call request recorded:\n%s", buf.String())
	}
	if !sawS2CResp {
		t.Fatalf("no s2c response recorded:\n%s", buf.String())
	}
}

func TestTracerCapsPayload(t *testing.T) {
	var buf bytes.Buffer
	tr := NewTracer(&buf, func() string { return "T" }, TraceOptions{Payloads: true, MaxBytes: 16})
	big := strings.Repeat("x", 100)
	line := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"w","arguments":{"data":"` + big + `"}}}`)
	tr.record(Caller{Backend: "fs", Peer: "p"}, "c2s", line, "allow")

	var ev TraceEvent
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &ev); err != nil {
		t.Fatalf("bad trace: %v", err)
	}
	if !strings.Contains(string(ev.Payload), "truncated") {
		t.Fatalf("expected truncated payload marker, got %s", ev.Payload)
	}
}
