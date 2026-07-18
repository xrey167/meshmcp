// scheduler is a governed scheduler / cron MCP server (F27): identity-attributed
// scheduled tool calls over the mesh. An agent registers a job — "call this tool
// with these args at this time, or every N seconds" — stamped with its mesh
// identity (MESHMCP_PEER_KEY). A worker polls `due` to fetch jobs that are ready
// and then makes the actual call over the mesh (itself governed + audited by the
// firewall). The scheduler is pure state: it never calls out, so every fired
// action stays attributable and policy-gated where the call is made.
package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"sync"
	"time"

	"meshmcp/mcp"
)

// job is one scheduled tool call.
type job struct {
	ID    string          `json:"id"`
	Tool  string          `json:"tool"`
	Args  json.RawMessage `json:"args,omitempty"`
	RunAt int64           `json:"run_at"`          // next fire time (unix seconds)
	Every int64           `json:"every,omitempty"` // recurrence seconds; 0 = one-shot
	Peer  string          `json:"peer,omitempty"`  // requesting WireGuard identity
	Done  bool            `json:"done,omitempty"`  // one-shot job has fired
}

// scheduleStore is an in-memory job set persisted as a JSONL snapshot.
type scheduleStore struct {
	mu   sync.Mutex
	path string
	now  func() time.Time
	jobs map[string]*job
}

func openScheduleStore(path string, now func() time.Time) (*scheduleStore, error) {
	if now == nil {
		now = time.Now
	}
	s := &scheduleStore{path: path, now: now, jobs: map[string]*job{}}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return s, nil
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
		var j job
		if err := json.Unmarshal(sc.Bytes(), &j); err != nil {
			return nil, err
		}
		s.jobs[j.ID] = &j
	}
	return s, sc.Err()
}

// persist rewrites the snapshot (small job sets; atomic temp+rename).
func (s *scheduleStore) persistLocked() error {
	if s.path == "" {
		return nil
	}
	tmp := s.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	w := bufio.NewWriter(f)
	for _, j := range s.jobs {
		b, _ := json.Marshal(j)
		w.Write(append(b, '\n'))
	}
	if err := w.Flush(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func (s *scheduleStore) schedule(tool string, args json.RawMessage, runAt, every int64, peer string) (*job, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var b [8]byte
	_, _ = rand.Read(b[:])
	j := &job{ID: "j_" + hex.EncodeToString(b[:]), Tool: tool, Args: args, RunAt: runAt, Every: every, Peer: peer}
	s.jobs[j.ID] = j
	return j, s.persistLocked()
}

// due returns jobs whose RunAt has arrived, advancing recurring jobs and marking
// one-shot jobs done. The worker that receives them makes the actual calls.
func (s *scheduleStore) due() ([]job, error) {
	now := s.now().Unix()
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []job
	for _, j := range s.jobs {
		if j.Done || j.RunAt > now {
			continue
		}
		out = append(out, *j)
		if j.Every > 0 {
			// advance to the next slot strictly in the future
			for j.RunAt <= now {
				j.RunAt += j.Every
			}
		} else {
			j.Done = true
		}
	}
	sort.Slice(out, func(i, k int) bool { return out[i].RunAt < out[k].RunAt })
	return out, s.persistLocked()
}

func (s *scheduleStore) list() []job {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]job, 0, len(s.jobs))
	for _, j := range s.jobs {
		out = append(out, *j)
	}
	sort.Slice(out, func(i, k int) bool { return out[i].RunAt < out[k].RunAt })
	return out
}

func (s *scheduleStore) cancel(id string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.jobs[id]; !ok {
		return false, nil
	}
	delete(s.jobs, id)
	return true, s.persistLocked()
}

func main() {
	path := "schedule.jsonl"
	for i, a := range os.Args {
		if a == "--store" && i+1 < len(os.Args) {
			path = os.Args[i+1]
		}
	}
	st, err := openScheduleStore(path, time.Now)
	if err != nil {
		fmt.Fprintln(os.Stderr, "scheduler:", err)
		os.Exit(1)
	}
	peer := os.Getenv("MESHMCP_PEER_KEY")
	if peer == "" {
		peer = os.Getenv("MESHMCP_PEER")
	}
	fmt.Fprintf(os.Stderr, "scheduler: started for peer %q, store %s\n", peer, path)

	s := mcp.New("meshmcp-scheduler", "0.1.0")
	registerScheduler(s, st, peer)
	if err := s.Serve(context.Background(), os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "scheduler:", err)
		os.Exit(1)
	}
}

func registerScheduler(s *mcp.Server, st *scheduleStore, peer string) {
	s.AddTool(mcp.Tool{
		Name:        "schedule",
		Description: "Schedule a tool call. Provide run_at (unix seconds) for a one-shot, or every (seconds) for a recurring job. Stamped with your mesh identity.",
		InputSchema: objSchema(map[string]any{
			"tool":   strProp("the tool to call when the job fires"),
			"args":   map[string]any{"type": "object", "description": "arguments for the tool"},
			"run_at": map[string]any{"type": "number", "description": "unix seconds for a one-shot fire"},
			"every":  map[string]any{"type": "number", "description": "recurrence interval in seconds"},
		}, "tool"),
		Handler: func(_ context.Context, args json.RawMessage) (mcp.ToolResult, error) {
			var a struct {
				Tool  string          `json:"tool"`
				Args  json.RawMessage `json:"args"`
				RunAt int64           `json:"run_at"`
				Every int64           `json:"every"`
			}
			if err := json.Unmarshal(args, &a); err != nil || a.Tool == "" {
				return errResult("tool is required"), nil
			}
			if a.RunAt == 0 && a.Every == 0 {
				return errResult("set run_at (one-shot) or every (recurring)"), nil
			}
			if a.RunAt == 0 {
				a.RunAt = st.now().Unix() + a.Every
			}
			j, err := st.schedule(a.Tool, a.Args, a.RunAt, a.Every, peer)
			if err != nil {
				return errResult("%v", err), nil
			}
			return jsonRes(map[string]any{"id": j.ID, "run_at": j.RunAt, "every": j.Every}), nil
		},
	})

	s.AddTool(mcp.Tool{
		Name:        "due",
		Description: "Fetch jobs that are ready to run now (advances recurring jobs, marks one-shots done). The worker makes the actual calls.",
		InputSchema: objSchema(nil),
		Handler: func(_ context.Context, _ json.RawMessage) (mcp.ToolResult, error) {
			jobs, err := st.due()
			if err != nil {
				return errResult("%v", err), nil
			}
			return jsonRes(map[string]any{"count": len(jobs), "jobs": jobs}), nil
		},
	})

	s.AddTool(mcp.Tool{
		Name:        "list",
		Description: "List all scheduled jobs.",
		InputSchema: objSchema(nil),
		Handler: func(_ context.Context, _ json.RawMessage) (mcp.ToolResult, error) {
			jobs := st.list()
			return jsonRes(map[string]any{"count": len(jobs), "jobs": jobs}), nil
		},
	})

	s.AddTool(mcp.Tool{
		Name:        "cancel",
		Description: "Cancel a scheduled job by id.",
		InputSchema: objSchema(map[string]any{"id": strProp("the job id to cancel")}, "id"),
		Handler: func(_ context.Context, args json.RawMessage) (mcp.ToolResult, error) {
			var a struct{ ID string }
			if err := json.Unmarshal(args, &a); err != nil || a.ID == "" {
				return errResult("id is required"), nil
			}
			ok, err := st.cancel(a.ID)
			if err != nil {
				return errResult("%v", err), nil
			}
			return jsonRes(map[string]any{"cancelled": ok}), nil
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
