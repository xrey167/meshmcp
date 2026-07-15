package policy

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

// ReplayReq is one client->server request reconstructed from a trace, ready to
// be re-issued against a backend.
type ReplayReq struct {
	Seq    int    // ordinal within the extracted request stream (1-based)
	ID     string // JSON-RPC id (raw), used to match the response ("" for notifications)
	Method string
	Tool   string
	Notify bool   // a client notification: send fire-and-forget, no response awaited
	Line   []byte // the full JSON-RPC line to send
}

// ReplaySet is the replayable view of a trace: the ordered requests and the
// originally-observed responses (by rpc id) to diff against.
type ReplaySet struct {
	Requests []ReplayReq
	OrigResp map[string]json.RawMessage // rpc id -> original result/error payload
}

// ExtractReplay reads a trace log (captured with payloads on) and reconstructs
// the ordered client->server requests plus the original server responses. This
// is what makes deterministic replay possible: the trace already holds every
// request's params and every response's result, attributed to a caller — so a
// session can be re-run against a different tool version and diffed. Requests
// whose params were not captured (trace without payloads) are still returned,
// but with an empty params body; the caller can warn.
func ExtractReplay(r io.Reader) (ReplaySet, error) {
	set := ReplaySet{OrigResp: map[string]json.RawMessage{}}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	seq := 0
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var ev TraceEvent
		if json.Unmarshal(line, &ev) != nil {
			continue
		}
		switch {
		case ev.Dir == "c2s" && ev.Kind == "request":
			seq++
			set.Requests = append(set.Requests, ReplayReq{
				Seq:    seq,
				ID:     ev.RPCID,
				Method: ev.Method,
				Tool:   ev.Tool,
				Line:   buildRequestLine(ev),
			})
		case ev.Dir == "c2s" && ev.Kind == "notification":
			seq++
			set.Requests = append(set.Requests, ReplayReq{
				Seq:    seq,
				Method: ev.Method,
				Notify: true,
				Line:   buildNotificationLine(ev),
			})
		case ev.Dir == "s2c" && ev.Kind == "response" && ev.RPCID != "":
			// Last response for an id wins (there should be exactly one).
			set.OrigResp[ev.RPCID] = ev.Payload
		}
	}
	if err := sc.Err(); err != nil {
		return set, err
	}
	return set, nil
}

// buildRequestLine reconstructs a JSON-RPC request line from a trace event.
func buildRequestLine(ev TraceEvent) []byte {
	id := ev.RPCID
	if id == "" {
		id = "null"
	}
	params := ev.Payload
	var buf bytes.Buffer
	buf.WriteString(`{"jsonrpc":"2.0","id":`)
	buf.WriteString(id)
	buf.WriteString(`,"method":`)
	b, _ := json.Marshal(ev.Method)
	buf.Write(b)
	if len(params) > 0 {
		buf.WriteString(`,"params":`)
		buf.Write(params)
	}
	buf.WriteByte('}')
	return buf.Bytes()
}

// buildNotificationLine reconstructs a JSON-RPC notification (no id) line.
func buildNotificationLine(ev TraceEvent) []byte {
	var buf bytes.Buffer
	buf.WriteString(`{"jsonrpc":"2.0","method":`)
	b, _ := json.Marshal(ev.Method)
	buf.Write(b)
	if len(ev.Payload) > 0 {
		buf.WriteString(`,"params":`)
		buf.Write(ev.Payload)
	}
	buf.WriteByte('}')
	return buf.Bytes()
}

// Fork returns the request prefix up to and including seq n (1-based); n<=0 or
// n>=len returns all. This is the "fork the session at message N" primitive:
// replay the first n requests, then diverge with a different backend.
func (s ReplaySet) Fork(n int) []ReplayReq {
	if n <= 0 || n >= len(s.Requests) {
		return s.Requests
	}
	return s.Requests[:n]
}

// DiffResponse compares an original (recorded) response payload with a freshly
// observed one, ignoring key order and whitespace. It returns equal=true when
// they are semantically identical, and otherwise a short human description.
func DiffResponse(orig, got json.RawMessage) (equal bool, detail string) {
	on := canonicalJSON(orig)
	gn := canonicalJSON(got)
	if bytes.Equal(on, gn) {
		return true, ""
	}
	return false, fmt.Sprintf("was %s  now %s", truncate(on, 120), truncate(gn, 120))
}

func canonicalJSON(raw json.RawMessage) []byte {
	if len(raw) == 0 {
		return []byte("null")
	}
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return raw
	}
	b, err := json.Marshal(v) // Go marshals map keys sorted → canonical
	if err != nil {
		return raw
	}
	return b
}

func truncate(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "…"
}
