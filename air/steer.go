// Package air is meshmcp's Air module: the portable core of the identity-native
// payload, discovery, Continuity, and live-work layer.
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
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"strings"
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
// be one of task/nudge/cancel, a task must name a tool, an optional target must
// follow the Air target grammar, and optional arguments must be valid JSON.
// Centralizing this here keeps the CLI, the agent loop, and the workflow
// validator agreeing on exactly what a valid steer is.
func (e SteerEnvelope) Validate() error {
	switch e.Type {
	case SteerTask:
		if strings.TrimSpace(e.Tool) == "" || e.Tool != strings.TrimSpace(e.Tool) || len(e.Tool) > 256 || steerHasControl(e.Tool) {
			return fmt.Errorf("steer type %q requires a tool", SteerTask)
		}
		if e.Text != "" {
			return fmt.Errorf("steer type %q must not carry nudge text", SteerTask)
		}
	case SteerNudge:
		// Empty nudge is the existing "clear guidance" operation.
		if len(e.Text) > 64<<10 || steerHasControl(e.Text) {
			return fmt.Errorf("steer type %q requires bounded single-line text", SteerNudge)
		}
		if e.Tool != "" || len(e.Args) != 0 {
			return fmt.Errorf("steer type %q must not carry a tool or arguments", SteerNudge)
		}
	case SteerCancel:
		if e.Tool != "" || len(e.Args) != 0 || e.Text != "" {
			return fmt.Errorf("steer type %q must not carry a tool, arguments, or text", SteerCancel)
		}
	default:
		return fmt.Errorf("unknown steer type %q (want %s, %s, or %s)", e.Type, SteerTask, SteerNudge, SteerCancel)
	}
	if _, err := ParseTarget(e.Target); err != nil {
		return fmt.Errorf("steer target: %w", err)
	}
	if len(e.Args) > 0 && !json.Valid(e.Args) {
		return fmt.Errorf("steer args must be valid JSON")
	}
	if len(e.ID) > 256 || steerHasControl(e.ID) {
		return fmt.Errorf("steer id is invalid")
	}
	return nil
}

// Task builds a task steer: run tool with args on the target work.
func Task(tool string, args json.RawMessage) SteerEnvelope {
	return SteerEnvelope{Type: SteerTask, Tool: tool, Args: args}
}

// TaskArgs builds a task steer, marshaling args to JSON (nil args → no args).
func TaskArgs(tool string, args map[string]any) SteerEnvelope {
	e := SteerEnvelope{Type: SteerTask, Tool: tool}
	if len(args) > 0 {
		if b, err := json.Marshal(args); err == nil {
			e.Args = b
		}
	}
	return e
}

// String renders a compact, log-friendly summary of the steer.
func (e SteerEnvelope) String() string {
	switch e.Type {
	case SteerTask:
		return fmt.Sprintf("task %s%s", e.Tool, targetSuffix(e.Target))
	case SteerNudge:
		return fmt.Sprintf("nudge %q%s", e.Text, targetSuffix(e.Target))
	case SteerCancel:
		return "cancel" + targetSuffix(e.Target)
	default:
		return fmt.Sprintf("steer(%s)%s", e.Type, targetSuffix(e.Target))
	}
}

func targetSuffix(t string) string {
	if t == "" {
		return ""
	}
	return " → " + t
}

// Nudge builds a nudge steer: augment in-flight guidance.
func Nudge(text string) SteerEnvelope { return SteerEnvelope{Type: SteerNudge, Text: text} }

// Cancel builds a cancel steer: interrupt the target work.
func Cancel() SteerEnvelope { return SteerEnvelope{Type: SteerCancel} }

// WriteEnvelope frames one envelope as a newline-delimited JSON record — the
// wire form the steer inbox reads (see ParseEnvelopes).
func WriteEnvelope(w io.Writer, e SteerEnvelope) error {
	if err := e.Validate(); err != nil {
		return err
	}
	line, err := json.Marshal(e)
	if err != nil {
		return err
	}
	if len(line) > maxEnvelopeLine {
		return fmt.Errorf("steer envelope exceeds the %d-byte limit", maxEnvelopeLine)
	}
	_, err = w.Write(append(line, '\n'))
	return err
}

// SteerMaxAckBytes bounds the agent inbox's application ACK/NACK.
const SteerMaxAckBytes = 4 << 10

const (
	SteerAckDelivered = "delivered"
	SteerAckRejected  = "rejected"
)

// SteerAck is the agent inbox's application-level answer. A delivered ACK is
// emitted only after strict validation, receipt audit, and enqueue to the
// agent's steer channel; transport frame acknowledgement is not enough.
type SteerAck struct {
	Version int    `json:"version"`
	ID      string `json:"id,omitempty"`
	Status  string `json:"status"`
	Reason  string `json:"reason,omitempty"`
}

func (a SteerAck) ValidateFor(env SteerEnvelope) error {
	if err := validateSteerAck(a); err != nil {
		return err
	}
	if subtle.ConstantTimeCompare([]byte(a.ID), []byte(env.ID)) != 1 {
		return fmt.Errorf("steer acknowledgement id mismatch")
	}
	return nil
}

func (a SteerAck) Delivered() bool { return a.Status == SteerAckDelivered }

func validateSteerAck(a SteerAck) error {
	if a.Version != HandoffVersion {
		return fmt.Errorf("unsupported steer acknowledgement version %d", a.Version)
	}
	if len(a.ID) > 256 || steerHasControl(a.ID) {
		return fmt.Errorf("steer acknowledgement id is invalid")
	}
	switch a.Status {
	case SteerAckDelivered:
		if a.Reason != "" {
			return fmt.Errorf("delivered steer acknowledgement must not carry a rejection reason")
		}
	case SteerAckRejected:
		if strings.TrimSpace(a.Reason) == "" || a.Reason != strings.TrimSpace(a.Reason) || len(a.Reason) > 128 || steerHasControl(a.Reason) {
			return fmt.Errorf("steer rejection reason is invalid")
		}
	default:
		return fmt.Errorf("unknown steer acknowledgement status %q", a.Status)
	}
	return nil
}

func WriteSteerAck(w io.Writer, ack SteerAck) error {
	if err := validateSteerAck(ack); err != nil {
		return err
	}
	b, err := json.Marshal(ack)
	if err != nil {
		return err
	}
	if len(b) > SteerMaxAckBytes {
		return fmt.Errorf("steer acknowledgement exceeds the %d-byte limit", SteerMaxAckBytes)
	}
	_, err = w.Write(append(b, '\n'))
	return err
}

func ReadSteerAck(r io.Reader) (SteerAck, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1024), SteerMaxAckBytes)
	if !sc.Scan() {
		if err := sc.Err(); err != nil {
			return SteerAck{}, err
		}
		return SteerAck{}, fmt.Errorf("missing steer acknowledgement")
	}
	line := bytes.TrimSpace(sc.Bytes())
	var ack SteerAck
	if len(line) == 0 {
		return ack, fmt.Errorf("empty steer acknowledgement")
	}
	if err := decodeStrictAirJSON(line, &ack); err != nil {
		return SteerAck{}, fmt.Errorf("bad steer acknowledgement: %w", err)
	}
	if err := validateSteerAck(ack); err != nil {
		return SteerAck{}, err
	}
	return ack, nil
}

func steerHasControl(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

// maxEnvelopeLine bounds one newline-delimited envelope, so a peer on an
// agent's steer inbox cannot force an unbounded line buffer.
const maxEnvelopeLine = 1 << 20

// ParseEnvelope decodes one steer envelope from a JSON line.
func ParseEnvelope(line []byte) (SteerEnvelope, error) {
	if err := rejectDuplicateTopLevelKeys(line); err != nil {
		return SteerEnvelope{}, fmt.Errorf("bad steer envelope: %w", err)
	}
	var env SteerEnvelope
	if err := decodeStrictAirJSON(line, &env); err != nil {
		return SteerEnvelope{}, fmt.Errorf("bad steer envelope: %w", err)
	}
	return env, nil
}

func rejectDuplicateTopLevelKeys(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := tok.(json.Delim)
	if !ok || delim != '{' {
		return fmt.Errorf("steer envelope must be a JSON object")
	}
	seen := map[string]struct{}{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		key, ok := tok.(string)
		if !ok {
			return fmt.Errorf("steer envelope has a non-string field name")
		}
		if _, duplicate := seen[key]; duplicate {
			return fmt.Errorf("steer envelope repeats field %q", key)
		}
		seen[key] = struct{}{}
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return err
		}
	}
	_, err = dec.Token()
	return err
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
