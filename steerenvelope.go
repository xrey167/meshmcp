package main

import "encoding/json"

// steerEnvelope is one instruction delivered to an agent's steer inbox (Air ·
// Steer, P1). It rides the same resumable, ACL'd mesh channel as a drop, but is
// framed as one newline-delimited JSON object rather than a file record. The
// agent's loop selects on a channel of these between its scripted steps.
type steerEnvelope struct {
	Type   string          `json:"type"`             // "task" | "nudge" | "cancel"
	Tool   string          `json:"tool,omitempty"`   // type=task: tool to call
	Args   json.RawMessage `json:"args,omitempty"`   // type=task: tool arguments
	Text   string          `json:"text,omitempty"`   // type=nudge: free-form guidance
	Target string          `json:"target,omitempty"` // optional sub-work address, e.g. "task:9f2a" (AIR-STEER §1)
	ID     string          `json:"id,omitempty"`     // caller correlation id (audited)
}
