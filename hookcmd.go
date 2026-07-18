package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"gopkg.in/yaml.v3"

	"meshmcp/policy"
)

// cmdHook is meshmcp's client-hook adapter (F33): it turns the PreToolUse-style
// hook that Claude Code, Cursor, and Codex each expose into a meshmcp policy
// decision. The client runs `meshmcp hook --client <c>` as its pre-tool hook;
// meshmcp reads the tool + arguments on stdin, evaluates them against a local
// policy engine (+ DLP), records the verdict in the tamper-evident audit
// ledger, and writes the client-specific allow/deny/ask response on stdout — so
// EVERY tool the model calls (Bash, Edit, a native MCP tool), not only mesh
// backends, flows through the same firewall and audit. No mesh join required.
func cmdHook(args []string) error {
	if len(args) > 0 && args[0] == "install" {
		return hookInstall(args[1:])
	}
	fs := flag.NewFlagSet("hook", flag.ContinueOnError)
	client := fs.String("client", "claude-code", "hook dialect: claude-code | cursor | codex")
	cfgPath := fs.String("config", "", "hook policy config (YAML: policy, audit_log, dlp, identity)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := loadHookConfig(*cfgPath)
	if err != nil {
		return err
	}

	eng := policy.NewEngine(cfg.Policy, func() time.Time { return time.Now() }, nil)
	var dlp *policy.PatternDLPHook
	if len(cfg.DLP) > 0 {
		if dlp, err = policy.NewPatternDLP(cfg.DLP); err != nil {
			return err
		}
	}
	var audit *policy.AuditLog
	if cfg.AuditLog != "" {
		f, err := os.OpenFile(cfg.AuditLog, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			return fmt.Errorf("open hook audit log: %w", err)
		}
		defer f.Close()
		audit = policy.NewAuditLog(f, nowRFC3339)
		// Seed the chain from the existing tail so restarts don't reset seq.
		if tf, terr := os.Open(cfg.AuditLog); terr == nil {
			if seq, prev, lerr := policy.LastLink(tf); lerr == nil {
				audit.SeedFrom(seq, prev)
			}
			tf.Close()
		}
	}

	raw, _ := io.ReadAll(io.LimitReader(os.Stdin, maxHTTPBody))
	call := decodeHookCall(*client, raw)

	// An empty/unparseable hook payload (or a non-tool event) is allowed so we
	// never break the client; only a resolved tool name is governed.
	dec := policy.Decision{Outcome: policy.OutcomeAllow, Allow: true, RuleID: -1}
	if call.Tool != "" {
		dec = eng.DecideToolCall(cfg.identity(), cfg.identity(), call.Tool, nil)
		if dlp != nil {
			dec = dlp.DecideTool(policy.ToolCallInfo{Tool: call.Tool, Arguments: call.Args}, dec)
		}
		if audit != nil {
			_ = audit.Append(policy.AuditRecord{
				Backend: "client:" + *client, Peer: cfg.identity(),
				Method: "tools/call", Tool: call.Tool,
				Decision: dec.Outcome.String(), Reason: dec.Reason, Rule: dec.RuleID,
			})
		}
	}
	out := encodeHookDecision(*client, dec, call.Tool)
	_, _ = os.Stdout.Write(out)
	return nil
}

func nowRFC3339() string { return time.Now().UTC().Format(time.RFC3339) }

// hookConfig is the small YAML a hook adapter reads. It reuses the same Policy
// and DLP types the gateway uses, so a policy authored for a backend works here.
type hookConfig struct {
	Identity string           `yaml:"identity"`
	AuditLog string           `yaml:"audit_log"`
	Policy   *policy.Policy   `yaml:"policy"`
	DLP      []policy.DLPSpec `yaml:"dlp"`
}

func (h *hookConfig) identity() string {
	if h.Identity != "" {
		return h.Identity
	}
	return "local-agent"
}

func loadHookConfig(path string) (*hookConfig, error) {
	if path == "" {
		return nil, fmt.Errorf("meshmcp hook: --config <file> is required")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read hook config: %w", err)
	}
	var c hookConfig
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse hook config: %w", err)
	}
	if c.Policy == nil {
		return nil, fmt.Errorf("hook config %s: a policy is required", path)
	}
	if err := c.Policy.Validate(); err != nil {
		return nil, fmt.Errorf("hook config policy: %w", err)
	}
	if _, err := policy.NewPatternDLP(c.DLP); len(c.DLP) > 0 && err != nil {
		return nil, err
	}
	return &c, nil
}

// hookCall is the normalized (tool, args) extracted from any client's hook JSON.
type hookCall struct {
	Tool string
	Args json.RawMessage
}

// decodeHookCall extracts the tool name and arguments from a client's hook
// payload. Unknown shapes yield an empty Tool (which is allowed through).
func decodeHookCall(client string, raw []byte) hookCall {
	switch client {
	case "cursor":
		var in struct {
			ToolName  string          `json:"tool_name"`
			ToolInput json.RawMessage `json:"tool_input"`
			Command   string          `json:"command"`
			URL       string          `json:"url"`
		}
		_ = json.Unmarshal(raw, &in)
		if in.ToolName != "" {
			return hookCall{Tool: in.ToolName, Args: in.ToolInput}
		}
		if in.Command != "" {
			b, _ := json.Marshal(map[string]string{"command": in.Command})
			return hookCall{Tool: "Shell", Args: b}
		}
		if in.URL != "" {
			b, _ := json.Marshal(map[string]string{"url": in.URL})
			return hookCall{Tool: "Fetch", Args: b}
		}
		return hookCall{}
	default: // claude-code and codex share {tool_name, tool_input}
		var in struct {
			ToolName  string          `json:"tool_name"`
			ToolInput json.RawMessage `json:"tool_input"`
		}
		_ = json.Unmarshal(raw, &in)
		return hookCall{Tool: in.ToolName, Args: in.ToolInput}
	}
}

// encodeHookDecision renders the meshmcp decision in the client's expected hook
// response format. A co-sign outcome maps to "ask" (defer to the client's own
// human prompt), since this adapter is not on the mesh co-sign path.
func encodeHookDecision(client string, dec policy.Decision, tool string) []byte {
	verdict := "allow"
	switch dec.Outcome {
	case policy.OutcomeDeny:
		verdict = "deny"
	case policy.OutcomeCosign:
		verdict = "ask"
	}
	reason := dec.Reason
	if reason == "" && verdict == "deny" {
		reason = "blocked by meshmcp policy"
	}

	switch client {
	case "cursor":
		out := map[string]any{"permission": verdict, "continue": verdict != "deny"}
		if reason != "" {
			out["agentMessage"] = reason
			out["userMessage"] = "meshmcp: " + verdict + " " + tool
		}
		b, _ := json.Marshal(out)
		return append(b, '\n')
	case "codex":
		// Codex PermissionRequest: allow/deny, or decline to defer.
		decision := "allow"
		if verdict == "deny" {
			decision = "deny"
		} else if verdict == "ask" {
			decision = "decline"
		}
		b, _ := json.Marshal(map[string]any{"decision": decision, "reason": reason})
		return append(b, '\n')
	default: // claude-code
		hso := map[string]any{"hookEventName": "PreToolUse", "permissionDecision": verdict}
		if reason != "" {
			hso["permissionDecisionReason"] = reason
		}
		b, _ := json.Marshal(map[string]any{"hookSpecificOutput": hso})
		return append(b, '\n')
	}
}

// hookInstall prints the exact hook configuration to add to a client so its
// pre-tool hook calls `meshmcp hook`. It prints (never silently edits the
// user's settings), so the operator pastes it where they want it.
func hookInstall(args []string) error {
	fs := flag.NewFlagSet("hook install", flag.ContinueOnError)
	client := fs.String("client", "claude-code", "claude-code | cursor | codex")
	cfgPath := fs.String("config", "./meshmcp-hook.yaml", "path to the hook policy config")
	if err := fs.Parse(args); err != nil {
		return err
	}
	switch *client {
	case "claude-code":
		fmt.Printf(`# Add to .claude/settings.json (project) or ~/.claude/settings.json (user):
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "*",
        "hooks": [
          { "type": "command", "command": "meshmcp hook --client claude-code --config %s" }
        ]
      }
    ]
  }
}
`, *cfgPath)
	case "cursor":
		fmt.Printf(`# Add to .cursor/hooks.json (project) or ~/.cursor/hooks.json (user):
{
  "version": 1,
  "hooks": {
    "beforeShellExecution": [ { "command": "meshmcp hook --client cursor --config %s" } ],
    "beforeMCPExecution":   [ { "command": "meshmcp hook --client cursor --config %s" } ]
  }
}
`, *cfgPath, *cfgPath)
	case "codex":
		fmt.Printf(`# Codex hooks (~/.codex): wire a PermissionRequest hook to:
#   meshmcp hook --client codex --config %s
# (Codex's hook config format is evolving; see its hooks docs for the exact key.)
`, *cfgPath)
	default:
		return fmt.Errorf("unknown client %q (want: claude-code, cursor, codex)", *client)
	}
	return nil
}
