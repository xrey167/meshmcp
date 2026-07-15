package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"time"

	"meshmcp/policy"
	"meshmcp/session"
)

// cmdReplay re-issues a traced session's requests against a backend and diffs
// each fresh response against the one originally recorded. Because meshmcp
// traces capture every request's params and every response's result — with
// caller identity — a past agent run can be deterministically re-played and,
// with --fork N, diverged at message N against a different tool version. This
// is time-travel debugging for agent runs.
func cmdReplay(args []string) error {
	fs := flag.NewFlagSet("replay", flag.ExitOnError)
	o := meshFlags(fs)
	fork := fs.Int("fork", 0, "replay only the first N requests, then stop (0 = whole trace)")
	plain := fs.Bool("plain", false, "use a plain (non-resumable) session")
	perTimeout := fs.Duration("response-timeout", 60*time.Second, "per-response timeout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		return fmt.Errorf("usage: meshmcp replay [flags] <trace.jsonl> <peer-ip:port>")
	}
	tracePath, target := fs.Arg(0), fs.Arg(1)

	tf, err := os.Open(tracePath)
	if err != nil {
		return err
	}
	set, err := policy.ExtractReplay(tf)
	tf.Close()
	if err != nil {
		return fmt.Errorf("read trace: %w", err)
	}
	if len(set.Requests) == 0 {
		return fmt.Errorf("trace %s has no client->server requests to replay", tracePath)
	}
	reqs := set.Fork(*fork)

	o.BlockInbound = true
	client, err := startMesh(o, os.Stderr)
	if err != nil {
		return err
	}
	defer stopMesh(client)

	reqR, reqW := io.Pipe()
	respR, respW := io.Pipe()
	local := &pipeLocal{r: reqR, w: respW}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if *plain {
		go runPlainBridge(ctx, client, target, local)
	} else {
		sc := session.NewClient(func(c context.Context) (net.Conn, error) {
			return client.Dial(c, "tcp", target)
		}, log.Printf)
		go func() { _ = sc.Run(ctx, local) }()
	}

	log.Printf("replaying %d requests from %s against %s", len(reqs), tracePath, target)
	mismatch, err := runReplay(reqW, respR, reqs, set.OrigResp, *perTimeout, os.Stdout)
	if err != nil {
		return err
	}
	if mismatch > 0 {
		return fmt.Errorf("replay diverged: %d response(s) differ from the recorded trace", mismatch)
	}
	return nil
}

// respMsg is a parsed response observed during replay.
type respMsg struct {
	id      string
	payload json.RawMessage
}

// runReplay sends each request line to reqW and, for non-notification
// requests, waits for the matching response from respR, diffing it against the
// recorded original. It returns the number of mismatches. It is transport-
// agnostic (pipes here, a mesh session in the command) so it is unit-testable
// against an in-process backend.
func runReplay(reqW io.WriteCloser, respR io.Reader, reqs []policy.ReplayReq, orig map[string]json.RawMessage, timeout time.Duration, out io.Writer) (int, error) {
	responses := make(chan respMsg, 64)
	go func() {
		sc := bufio.NewScanner(respR)
		sc.Buffer(make([]byte, 0, 1<<20), 1<<20)
		for sc.Scan() {
			var m struct {
				ID     json.RawMessage `json:"id"`
				Result json.RawMessage `json:"result"`
				Error  json.RawMessage `json:"error"`
			}
			if json.Unmarshal(sc.Bytes(), &m) != nil || len(m.ID) == 0 {
				continue // skip notifications / server->client requests
			}
			payload := m.Result
			if len(m.Error) > 0 {
				payload = m.Error
			}
			responses <- respMsg{id: string(m.ID), payload: payload}
		}
		close(responses)
	}()

	buffered := map[string]json.RawMessage{}
	awaitID := func(id string) (json.RawMessage, bool) {
		if p, ok := buffered[id]; ok {
			delete(buffered, id)
			return p, true
		}
		for {
			select {
			case r, ok := <-responses:
				if !ok {
					return nil, false
				}
				if r.id == id {
					return r.payload, true
				}
				buffered[r.id] = r.payload
			case <-time.After(timeout):
				return nil, false
			}
		}
	}

	mismatches := 0
	for _, req := range reqs {
		if _, err := reqW.Write(append(req.Line, '\n')); err != nil {
			return mismatches, err
		}
		if req.Notify {
			continue
		}
		got, ok := awaitID(req.ID)
		if !ok {
			fmt.Fprintf(out, "  #%-3d %-22s TIMEOUT (no response for id %s)\n", req.Seq, label(req), req.ID)
			mismatches++
			continue
		}
		want, hadOrig := orig[req.ID]
		if !hadOrig {
			fmt.Fprintf(out, "  #%-3d %-22s NEW    (no recorded response to compare)\n", req.Seq, label(req))
			continue
		}
		equal, detail := policy.DiffResponse(want, got)
		if equal {
			fmt.Fprintf(out, "  #%-3d %-22s OK\n", req.Seq, label(req))
		} else {
			fmt.Fprintf(out, "  #%-3d %-22s DIFF   %s\n", req.Seq, label(req), detail)
			mismatches++
		}
	}
	_ = reqW.Close()

	fmt.Fprintf(out, "replay complete: %d requests, %d divergence(s)\n", len(reqs), mismatches)
	return mismatches, nil
}

func label(r policy.ReplayReq) string {
	if r.Tool != "" {
		return r.Method + ":" + r.Tool
	}
	return r.Method
}
