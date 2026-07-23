// Package harness is meshmcp's identity-native, mesh-governed agent
// orchestration engine. It plans, delegates, spawns, verifies, and loops
// multi-agent coding/assistant work as a control-plane subsystem, so every
// orchestration action inherits meshmcp's existing guarantees rather than
// re-inventing them:
//
//   - Identity is transport-bound. Every actor (orchestrator, role worker,
//     provider bridge, human principal) is a mesh identity — a WireGuard
//     public key — never a self-asserted name. See Identity and Minter.
//
//   - Default-deny. No tool call, sub-agent spawn, provider invocation, or
//     cross-org call runs unless an allowlist policy permits it for the
//     calling identity. Role capability sets compile to a policy.Policy and
//     the policy.Engine is the single authority. See role.go and Governor.
//
//   - Tamper-evident. Every governed decision (spawn, route, tool call,
//     verdict, secret reference, loop stop, co-sign) emits one Ed25519-signed,
//     hash-chained audit record via policy.AuditLog. See Governor.
//
//   - Secrets by reference. Provider keys and tokens are referenced by name
//     ({{secret:NAME}}) and injected per identity by the secrets.Broker;
//     workers never see raw values. See provider adapters.
//
//   - Continuity via air. Run state, plans, tasks, and notepads that must
//     survive a crash, roam, or handoff go through air/checkpoint. See
//     Continuity.
//
// The engine unifies the capability surface of four external agent harnesses
// (oh-my-openagent, oh-my-claudecode, gajae-code, openclaw) into one Go
// subsystem. It does not run those projects; it re-implements their
// capabilities natively inside meshmcp's control plane. The engine drives
// external provider CLIs/APIs — it is not itself an inference engine.
//
// The companion package mcp/orchestrator exposes these capabilities as a dark
// MCP service; cmd/meshmcp adds the `harness` verb.
package harness
