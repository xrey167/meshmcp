package policy

import (
	"bytes"
	"strings"
	"testing"
)

// A tiny trace (payloads on) with two requests and their responses.
const sampleTrace = `
{"dir":"c2s","kind":"request","method":"initialize","rpc_id":"1","payload":{"protocolVersion":"2025-06-18"},"bytes":10}
{"dir":"s2c","kind":"response","rpc_id":"1","payload":{"serverInfo":{"name":"demo"}},"bytes":10}
{"dir":"c2s","kind":"notification","method":"notifications/initialized","bytes":5}
{"dir":"c2s","kind":"request","method":"tools/call","tool":"add","rpc_id":"2","payload":{"name":"add","arguments":{"a":2,"b":40}},"bytes":10}
{"dir":"s2c","kind":"response","rpc_id":"2","payload":{"content":[{"type":"text","text":"42"}]},"bytes":10}
`

func TestExtractReplay(t *testing.T) {
	set, err := ExtractReplay(strings.NewReader(sampleTrace))
	if err != nil {
		t.Fatal(err)
	}
	// initialize (req), notifications/initialized (notify), tools/call (req)
	if len(set.Requests) != 3 {
		t.Fatalf("expected 3 replayable messages, got %d", len(set.Requests))
	}
	if set.Requests[1].Method != "notifications/initialized" || !set.Requests[1].Notify {
		t.Fatalf("second message should be the notification, got %+v", set.Requests[1])
	}
	call := set.Requests[2]
	if call.Tool != "add" || !bytes.Contains(call.Line, []byte(`"method":"tools/call"`)) {
		t.Fatalf("reconstructed tools/call line wrong: %s", call.Line)
	}
	if !bytes.Contains(call.Line, []byte(`"a":2`)) {
		t.Fatalf("params not reconstructed: %s", call.Line)
	}
	if _, ok := set.OrigResp["2"]; !ok {
		t.Fatalf("original response for id 2 missing")
	}
}

func TestForkTruncates(t *testing.T) {
	set, _ := ExtractReplay(strings.NewReader(sampleTrace))
	if got := set.Fork(2); len(got) != 2 {
		t.Fatalf("fork(2) should give 2 messages, got %d", len(got))
	}
	if got := set.Fork(0); len(got) != 3 {
		t.Fatalf("fork(0) should give all 3, got %d", len(got))
	}
}

func TestDiffResponse(t *testing.T) {
	// Key order differs but content is identical → equal.
	a := []byte(`{"x":1,"y":2}`)
	b := []byte(`{"y":2,"x":1}`)
	if eq, _ := DiffResponse(a, b); !eq {
		t.Fatalf("key-order-only difference should compare equal")
	}
	// Value differs → not equal.
	c := []byte(`{"x":1,"y":3}`)
	if eq, detail := DiffResponse(a, c); eq || detail == "" {
		t.Fatalf("value difference should be reported, got eq=%v detail=%q", eq, detail)
	}
}
