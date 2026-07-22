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

import "encoding/json"

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
