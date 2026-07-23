package harness

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// ActionKind classifies a governed action. It becomes the audit record's Method
// so a replay can group by kind.
type ActionKind string

const (
	KindSpawn       ActionKind = "spawn"        // mint a worker / start a run
	KindToolCall    ActionKind = "tool_call"    // invoke an MCP tool
	KindRoute       ActionKind = "route"        // category → model-class routing decision
	KindVerdict     ActionKind = "verdict"      // a review/verify verdict
	KindChannelSend ActionKind = "channel_send" // gateway channel egress
	KindSecretRef   ActionKind = "secret_ref"   // reference a broker secret
	KindLoopStop    ActionKind = "loop_stop"    // stop-continuation
	KindCosign      ActionKind = "cosign"       // a co-sign grant/denial
)

// GovernedAction is the envelope wrapped around every harness action that
// matters, before it executes. It is the single input to Governor.Guard, whose
// path is identical for all actions:
//
//	Decide(policy) → (deny | allow | needs-cosign) → [approve] → Execute → Emit(audit)
//
// This is the choke point that gives the merged harness its guarantees.
type GovernedAction struct {
	Actor    Identity        // mesh identity of the caller (role worker / human)
	Kind     ActionKind      // Spawn, ToolCall, Route, Verdict, ...
	Target   string          // tool name / role / provider / channel — the policy "tool"
	Labels   []string        // data-flow labels this action carries (audited)
	Args     json.RawMessage // request payload; only its digest is audited
	RunID    string
	JobID    string
	Category Category
	Mode     Mode
	Provider string
}

// argsDigest returns "sha256:<hex>" of the (already-redacted) args, or "" when
// there are none. Only the digest is ever audited — never the raw args.
func (a GovernedAction) argsDigest() string {
	if len(a.Args) == 0 {
		return ""
	}
	sum := sha256.Sum256(a.Args)
	return "sha256:" + hex.EncodeToString(sum[:])
}
