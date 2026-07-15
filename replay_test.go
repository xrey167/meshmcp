package main

import (
	"bufio"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"meshmcp/policy"
)

// echoAddBackend is an in-process backend: it replies to tools/call "add" with
// the sum, and to any other request with {"ok":true}. behave lets a test make
// it diverge (return a wrong sum) to prove replay detects the difference.
func echoAddBackend(in io.Reader, out io.Writer, wrong bool) {
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 0, 1<<20), 1<<20)
	bw := bufio.NewWriter(out)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var m struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params struct {
				Name      string `json:"name"`
				Arguments struct{ A, B int } `json:"arguments"`
			} `json:"params"`
		}
		_ = json.Unmarshal([]byte(line), &m)
		if len(m.ID) == 0 {
			continue // notification
		}
		var result string
		if m.Method == "tools/call" && m.Params.Name == "add" {
			sum := m.Params.Arguments.A + m.Params.Arguments.B
			if wrong {
				sum++ // the "new tool version" is buggy
			}
			result = `{"content":[{"type":"text","text":"` + itoa(sum) + `"}]}`
		} else {
			result = `{"ok":true}`
		}
		bw.WriteString(`{"jsonrpc":"2.0","id":` + string(m.ID) + `,"result":` + result + "}\n")
		bw.Flush()
	}
}

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}

// The recorded trace: add(2,40) originally returned 42.
const replayTrace = `
{"dir":"c2s","kind":"request","method":"initialize","rpc_id":"1","payload":{},"bytes":10}
{"dir":"s2c","kind":"response","rpc_id":"1","payload":{"ok":true},"bytes":10}
{"dir":"c2s","kind":"notification","method":"notifications/initialized","bytes":5}
{"dir":"c2s","kind":"request","method":"tools/call","tool":"add","rpc_id":"2","payload":{"name":"add","arguments":{"a":2,"b":40}},"bytes":10}
{"dir":"s2c","kind":"response","rpc_id":"2","payload":{"content":[{"type":"text","text":"42"}]},"bytes":10}
`

func runReplayAgainst(t *testing.T, wrong bool) int {
	t.Helper()
	set, err := policy.ExtractReplay(strings.NewReader(replayTrace))
	if err != nil {
		t.Fatal(err)
	}
	reqR, reqW := io.Pipe()
	respR, respW := io.Pipe()
	go func() { echoAddBackend(reqR, respW, wrong); respW.Close() }()

	mismatch, err := runReplay(reqW, respR, set.Requests, set.OrigResp, 5*time.Second, io.Discard)
	if err != nil {
		t.Fatalf("runReplay: %v", err)
	}
	return mismatch
}

func TestReplayMatchesOriginal(t *testing.T) {
	if m := runReplayAgainst(t, false); m != 0 {
		t.Fatalf("faithful backend should produce 0 mismatches, got %d", m)
	}
}

func TestReplayDetectsDivergence(t *testing.T) {
	if m := runReplayAgainst(t, true); m != 1 {
		t.Fatalf("buggy backend should produce exactly 1 divergence, got %d", m)
	}
}
