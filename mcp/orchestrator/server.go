// Package orchestrator exposes the harness engine's capabilities as a dark MCP
// service — the tool catalog (delegation, planning, code intelligence, sessions,
// tasks, terminal, skills) that meshmcp already knows how to run on the mesh with
// zero public ports. Every tool call passes the harness Governor (policy.Engine
// + policy.AuditLog): default-deny by the caller's role, and one hash-chained
// audit record per call. Tool names keep the source projects' names so existing
// agent prompts port over unchanged.
package orchestrator

import (
	"context"
	"encoding/json"
	"io"

	"github.com/xrey167/meshmcp/harness"
	"github.com/xrey167/meshmcp/mcp"
	"github.com/xrey167/meshmcp/policy"
)

// Server registers the governed tool catalog on an mcp.Server, backed by a
// harness.Engine.
type Server struct {
	eng   *harness.Engine
	mcp   *mcp.Server
	tasks *taskStore
	bg    *bgJobs

	// caller is the identity every tool call is authorized as, until transport
	// identity injection is wired (a full mesh deployment resolves the caller
	// from the WireGuard peer). Defaults to a run-scoped orchestrator identity.
	caller harness.Identity
}

// New builds an orchestrator MCP server over eng. name/version identify it to
// clients.
func New(eng *harness.Engine, name, version string) *Server {
	s := &Server{
		eng:    eng,
		mcp:    mcp.New(name, version),
		tasks:  newTaskStore(),
		bg:     newBgJobs(),
		caller: harness.Identity{Key: "operator", FQDN: "orchestrator--mcp--0", Role: harness.RoleOrchestrator},
	}
	// Governance is a GLOBAL middleware, so no tool — present or future — can be
	// registered outside the firewall. Panics are recovered so a tool bug cannot
	// crash the dark service.
	s.mcp.Use(mcp.RecoverPanics(), s.govern)
	s.registerDelegate()
	s.registerPlan()
	s.registerCode()
	s.registerSessionAndTasks()
	s.registerEnv()
	s.registerSkill()
	return s
}

// SetCaller overrides the authorized caller identity (e.g. to drive as an
// executor role in a test, or once transport identity is injected).
func (s *Server) SetCaller(id harness.Identity) { s.caller = id }

// MCP returns the underlying mcp.Server (for wiring resources, or serving).
func (s *Server) MCP() *mcp.Server { return s.mcp }

// Serve runs the server over a stream (stdio or a mesh conn). All logs go to
// stderr; the stream is the MCP channel.
func (s *Server) Serve(ctx context.Context, r io.Reader, w io.Writer) error {
	return s.mcp.Serve(ctx, r, w)
}

// govern is the global tool middleware: it authorizes every tool call against
// the caller's role via the harness Governor and lets it proceed only on an
// allow. A deny or a pending co-sign returns an error result (visible to the
// model), never the tool's effect. The call is audited by Guard regardless.
func (s *Server) govern(next mcp.ToolHandler) mcp.ToolHandler {
	return func(ctx context.Context, args json.RawMessage) (mcp.ToolResult, error) {
		info, _ := mcp.ToolCallFrom(ctx)
		labels := toolLabels(info.Tool)
		d := s.eng.Governor().Guard(harness.GovernedAction{
			Actor:  s.caller,
			Kind:   harness.KindToolCall,
			Target: info.Tool,
			Labels: labels,
			Args:   redactArgs(args),
		}, nil)
		switch d.Outcome {
		case policy.OutcomeAllow:
			return next(ctx, args)
		case policy.OutcomeCosign:
			return errText("tool %q needs a human co-sign: %s", info.Tool, d.Reason), nil
		default:
			reason := d.Reason
			if reason == "" {
				reason = "default-deny (your role does not permit this tool)"
			}
			return errText("tool %q denied: %s", info.Tool, reason), nil
		}
	}
}

// redactArgs returns a copy of args safe to hash for audit. The Governor only
// stores the digest, but a secret reference marker must never be hashed in a way
// that could leak; markers are left literal (the broker resolves them elsewhere),
// so passing the raw args through is safe — only its sha256 is recorded.
func redactArgs(args json.RawMessage) json.RawMessage { return args }
