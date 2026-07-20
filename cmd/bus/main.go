// bus is a governed event-bus MCP server (F28): identity-stamped, policy-filtered
// pub/sub over the mesh. Agents publish events to a topic and poll a topic for
// new events since a cursor (pull-based, which fits MCP's request/response
// shape and rides the resumable session). Every event is stamped with the
// publishing mesh identity (MESHMCP_PEER_KEY) and a monotonic sequence, and the
// firewall in front governs who may publish or subscribe to which topics
// (by tool name, or by the topic argument) — a zero-exposure event fabric where
// subscription is a capability and every delivery is attributable.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"sync"

	"github.com/xrey167/meshmcp/mcp"
)

// event is one published message on a topic.
type event struct {
	Seq     int             `json:"seq"`
	Topic   string          `json:"topic"`
	Payload json.RawMessage `json:"payload"`
	Peer    string          `json:"peer,omitempty"` // publishing WireGuard identity
}

// busStore is an append-only, topic-partitioned event log with polling. The
// sequence is global (across topics) so a single cursor orders every delivery.
type busStore struct {
	mu      sync.Mutex
	path    string
	seq     int
	byTopic map[string][]event
}

func openBusStore(path string) (*busStore, error) {
	b := &busStore{path: path, byTopic: map[string][]event{}}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return b, nil
		}
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 32<<20)
	for sc.Scan() {
		if len(sc.Bytes()) == 0 {
			continue
		}
		var e event
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			return nil, err
		}
		b.byTopic[e.Topic] = append(b.byTopic[e.Topic], e)
		if e.Seq > b.seq {
			b.seq = e.Seq
		}
	}
	return b, sc.Err()
}

// publish appends an event to a topic and returns its global sequence.
func (b *busStore) publish(topic string, payload json.RawMessage, peer string) (event, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.seq++
	e := event{Seq: b.seq, Topic: topic, Payload: payload, Peer: peer}
	if b.path != "" {
		f, err := os.OpenFile(b.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			b.seq--
			return event{}, err
		}
		line, _ := json.Marshal(e)
		if _, err := f.Write(append(line, '\n')); err != nil {
			f.Close()
			b.seq--
			return event{}, err
		}
		if err := f.Close(); err != nil {
			b.seq--
			return event{}, err
		}
	}
	b.byTopic[topic] = append(b.byTopic[topic], e)
	return e, nil
}

// poll returns up to limit events on topic with Seq > since, oldest first, plus
// the cursor to pass next time.
func (b *busStore) poll(topic string, since, limit int) (events []event, cursor int) {
	if limit <= 0 {
		limit = 100
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	cursor = since
	for _, e := range b.byTopic[topic] {
		if e.Seq <= since {
			continue
		}
		events = append(events, e)
		cursor = e.Seq
		if len(events) >= limit {
			break
		}
	}
	return events, cursor
}

// topics returns each topic and its event count.
func (b *busStore) topics() map[string]int {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := map[string]int{}
	for t, evs := range b.byTopic {
		out[t] = len(evs)
	}
	return out
}

func main() {
	path := "bus.jsonl"
	for i, a := range os.Args {
		if a == "--store" && i+1 < len(os.Args) {
			path = os.Args[i+1]
		}
	}
	st, err := openBusStore(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "bus:", err)
		os.Exit(1)
	}
	peer := os.Getenv("MESHMCP_PEER_KEY")
	if peer == "" {
		peer = os.Getenv("MESHMCP_PEER")
	}
	fmt.Fprintf(os.Stderr, "bus: started for peer %q, store %s\n", peer, path)

	s := mcp.New("meshmcp-bus", "0.1.0")
	registerBus(s, st, peer)
	if err := s.Serve(context.Background(), os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "bus:", err)
		os.Exit(1)
	}
}

func registerBus(s *mcp.Server, st *busStore, peer string) {
	s.AddTool(mcp.Tool{
		Name:        "publish",
		Description: "Publish an event to a topic. Stamped with the publisher's mesh identity and a global sequence.",
		InputSchema: objSchema(map[string]any{
			"topic":   strProp("the topic to publish to"),
			"payload": map[string]any{"type": "object", "description": "the event payload (any JSON object)"},
		}, "topic", "payload"),
		Handler: func(_ context.Context, args json.RawMessage) (mcp.ToolResult, error) {
			var a struct {
				Topic   string          `json:"topic"`
				Payload json.RawMessage `json:"payload"`
			}
			if err := json.Unmarshal(args, &a); err != nil || a.Topic == "" || len(a.Payload) == 0 {
				return errResult("topic and payload are required"), nil
			}
			e, err := st.publish(a.Topic, a.Payload, peer)
			if err != nil {
				return errResult("%v", err), nil
			}
			return jsonRes(map[string]any{"seq": e.Seq, "topic": e.Topic}), nil
		},
	})

	s.AddTool(mcp.Tool{
		Name:        "poll",
		Description: "Poll a topic for new events since a cursor (0 for the beginning). Returns events oldest-first and the next cursor.",
		InputSchema: objSchema(map[string]any{
			"topic": strProp("the topic to poll"),
			"since": map[string]any{"type": "number", "description": "return events with seq greater than this (default 0)"},
			"limit": map[string]any{"type": "number", "description": "max events to return (default 100)"},
		}, "topic"),
		Handler: func(_ context.Context, args json.RawMessage) (mcp.ToolResult, error) {
			var a struct {
				Topic        string `json:"topic"`
				Since, Limit int
			}
			if err := json.Unmarshal(args, &a); err != nil || a.Topic == "" {
				return errResult("topic is required"), nil
			}
			evs, cursor := st.poll(a.Topic, a.Since, a.Limit)
			return jsonRes(map[string]any{"count": len(evs), "events": evs, "cursor": cursor}), nil
		},
	})

	s.AddTool(mcp.Tool{
		Name:        "topics",
		Description: "List every topic and how many events it holds.",
		InputSchema: objSchema(nil),
		Handler: func(_ context.Context, _ json.RawMessage) (mcp.ToolResult, error) {
			t := st.topics()
			names := make([]string, 0, len(t))
			for n := range t {
				names = append(names, n)
			}
			sort.Strings(names)
			out := make([]map[string]any, 0, len(names))
			for _, n := range names {
				out = append(out, map[string]any{"topic": n, "events": t[n]})
			}
			return jsonRes(map[string]any{"count": len(out), "topics": out}), nil
		},
	})
}

func jsonRes(v any) mcp.ToolResult {
	b, _ := json.MarshalIndent(v, "", "  ")
	return mcp.ToolResult{Content: []mcp.Content{mcp.Text(string(b))}}
}

func errResult(format string, a ...any) mcp.ToolResult {
	return mcp.ToolResult{Content: []mcp.Content{mcp.Text(fmt.Sprintf(format, a...))}, IsError: true}
}

func objSchema(props map[string]any, required ...string) map[string]any {
	if props == nil {
		props = map[string]any{}
	}
	m := map[string]any{"type": "object", "properties": props}
	if len(required) > 0 {
		m["required"] = required
	}
	return m
}

func strProp(desc string) map[string]any {
	return map[string]any{"type": "string", "description": desc}
}
