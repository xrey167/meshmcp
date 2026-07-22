// Package air is meshmcp's Air module: the portable core of the AirDrop-native
// payload + discovery layer — the steer envelope, the discovery catalog model,
// and the ARD (Agentic Resource Discovery) record generation and resolution.
//
// This package is deliberately mesh-independent: it holds Air's domain types
// and pure logic (record formatting, DNS-record parsing, discovery resolution)
// with no dependency on the WireGuard mesh client, the policy engine, or the
// session layer. The command-line and HTTP wiring that binds these to a live
// mesh lives in the main package, which imports this one — so the reusable Air
// model can be tested and evolved on its own.
package air

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

// Steer envelope types. A steer is one of exactly these three actions.
const (
	SteerTask   = "task"   // run a tool call
	SteerNudge  = "nudge"  // augment in-flight guidance
	SteerCancel = "cancel" // interrupt
)

// SteerEnvelope is one instruction delivered to an agent's steer inbox (Air ·
// Steer, P1). It rides the same resumable, ACL'd mesh channel as a drop, but is
// framed as one newline-delimited JSON object rather than a file record. The
// agent's loop selects on a channel of these between its scripted steps.
type SteerEnvelope struct {
	Type   string          `json:"type"`             // "task" | "nudge" | "cancel"
	Tool   string          `json:"tool,omitempty"`   // type=task: tool to call
	Args   json.RawMessage `json:"args,omitempty"`   // type=task: tool arguments
	Text   string          `json:"text,omitempty"`   // type=nudge: free-form guidance
	Target string          `json:"target,omitempty"` // optional sub-work address, e.g. "task:9f2a" (AIR-STEER §1)
	ID     string          `json:"id,omitempty"`     // caller correlation id (audited)
}

// Validate reports whether the envelope is a well-formed steer: the type must
// be one of task/nudge/cancel, and a task must name a tool. Centralizing this
// here keeps the CLI, the agent loop, and the workflow validator agreeing on
// exactly what a valid steer is.
func (e SteerEnvelope) Validate() error {
	switch e.Type {
	case SteerTask:
		if e.Tool == "" {
			return fmt.Errorf("steer type %q requires a tool", SteerTask)
		}
	case SteerNudge, SteerCancel:
	default:
		return fmt.Errorf("unknown steer type %q (want %s, %s, or %s)", e.Type, SteerTask, SteerNudge, SteerCancel)
	}
	return nil
}

// maxEnvelopeLine bounds one newline-delimited envelope, so a peer on an
// agent's steer inbox cannot force an unbounded line buffer.
const maxEnvelopeLine = 1 << 20

// ParseEnvelope decodes one steer envelope from a JSON line.
func ParseEnvelope(line []byte) (SteerEnvelope, error) {
	var env SteerEnvelope
	if err := json.Unmarshal(line, &env); err != nil {
		return SteerEnvelope{}, fmt.Errorf("bad steer envelope: %w", err)
	}
	return env, nil
}

// ParseEnvelopes decodes newline-delimited JSON steer envelopes from r and
// calls onEnv for each. A malformed line ends the stream with an error; blank
// lines are skipped. The per-line buffer is bounded (maxEnvelopeLine).
func ParseEnvelopes(r io.Reader, onEnv func(SteerEnvelope)) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<16), maxEnvelopeLine)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		env, err := ParseEnvelope(line)
		if err != nil {
			return err
		}
		onEnv(env)
	}
	return sc.Err()
}
