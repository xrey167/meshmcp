package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/xrey167/meshmcp/policy"
)

// cmdHook is meshmcp's client-hook adapter (F33): it turns the tool-lifecycle
// hooks that Claude Code, Cursor, and Codex expose into meshmcp policy +
// audit, so EVERY tool the model calls locally — not only mesh backends —
// flows through the same firewall. It dispatches on the hook event:
//
//   - pre-tool  (PreToolUse / beforeShellExecution / beforeMCPExecution /
//     PermissionRequest): authorize the call, apply DLP, carry session taint,
//     consult mesh co-sign, and return allow/deny/ask.
//   - post-tool (PostToolUse / afterFileEdit / afterMCPExecution): observe-only
//     — record the result (with an output content hash for provenance).
//   - prompt    (UserPromptSubmit / beforeSubmitPrompt): DLP-scan the prompt and
//     block on a match; record it.
//
// No mesh join is required — the same policy/DLP/audit the gateway uses, local.
func cmdHook(args []string) error {
	if len(args) > 0 && args[0] == "install" {
		return hookInstall(args[1:])
	}
	fs := flag.NewFlagSet("hook", flag.ContinueOnError)
	client := fs.String("client", "claude-code", "hook dialect: claude-code | cursor | codex")
	cfgPath := fs.String("config", "", "hook policy config (YAML: policy, audit_log, dlp, identity, cosign_store, session_dir, taint_tools)")
	event := fs.String("event", "", "hook event: pre-tool | post-tool | prompt (auto-detected from the payload when possible)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := loadHookConfig(*cfgPath)
	if err != nil {
		return err
	}

	var cosign policy.CosignStore
	var pending *policy.FilePending
	if cfg.CosignStore != "" {
		cosign = &policy.FileCosign{Dir: cfg.CosignStore}
		pending = &policy.FilePending{Dir: cfg.CosignStore}
	}
	eng := policy.NewEngine(cfg.Policy, func() time.Time { return time.Now() }, cosign)
	var dlp *policy.PatternDLPHook
	if len(cfg.DLP) > 0 {
		if dlp, err = policy.NewPatternDLP(cfg.DLP); err != nil {
			return err
		}
	}
	audit := openHookAudit(cfg.AuditLog)

	raw, _ := io.ReadAll(io.LimitReader(os.Stdin, maxHTTPBody))
	kind := hookEventKind(*event, raw)

	switch kind {
	case "post-tool":
		return hookPostTool(cfg, audit, raw)
	case "prompt":
		return hookPrompt(cfg, audit, dlp, *client, raw)
	default: // pre-tool
		return hookPreTool(cfg, eng, dlp, pending, audit, *client, raw)
	}
}

func nowRFC3339() string { return time.Now().UTC().Format(time.RFC3339) }

func openHookAudit(path string) *policy.AuditLog {
	if path == "" {
		return nil
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil
	}
	a := policy.NewAuditLog(f, nowRFC3339)
	if tf, terr := os.Open(path); terr == nil {
		if seq, prev, lerr := policy.LastLink(tf); lerr == nil {
			a.SeedFrom(seq, prev)
		}
		tf.Close()
	}
	return a
}

// hookPreTool authorizes a tool call: it carries session taint into the
// decision, applies DLP, consults co-sign, records the verdict, and writes the
// client-specific allow/deny/ask response.
func hookPreTool(cfg *hookConfig, eng *policy.Engine, dlp *policy.PatternDLPHook, pending *policy.FilePending, audit *policy.AuditLog, client string, raw []byte) error {
	call := decodeHookCall(client, raw)
	sess := hookSessionID(raw)

	dec := policy.Decision{Outcome: policy.OutcomeAllow, Allow: true, RuleID: -1}
	if call.Tool != "" {
		labels := cfg.readTaint(sess)
		dec = eng.DecideToolCall(cfg.identity(), cfg.identity(), call.Tool, labels)
		if dlp != nil {
			dec = dlp.DecideTool(policy.ToolCallInfo{Tool: call.Tool, Arguments: call.Args, Labels: labels}, dec)
		}
		if dec.Outcome == policy.OutcomeCosign && pending != nil {
			_ = pending.Record(policy.Pending{Peer: cfg.identity(), Backend: "client:" + client, Tool: call.Tool})
		}
		// Taint carry: an allowed call to a taint-source tool marks the session,
		// so a later privileged tool with taint_guard/block_labels is blocked —
		// network-layer prompt-injection defense, inside the client's tool loop.
		if dec.Outcome == policy.OutcomeAllow && cfg.isTaintTool(call.Tool) {
			cfg.markTainted(sess)
		}
		if audit != nil {
			_ = audit.Append(policy.AuditRecord{
				Backend: "client:" + client, Peer: cfg.identity(),
				Method: "tools/call", Tool: call.Tool,
				Decision: dec.Outcome.String(), Reason: dec.Reason, Rule: dec.RuleID, Cost: dec.Cost,
			})
		}
	}
	_, _ = os.Stdout.Write(encodeHookDecision(client, dec, call.Tool))
	return nil
}

// hookPostTool records a completed tool call for provenance (observe-only). It
// hashes the output so the ledger proves what a tool returned without storing
// the (possibly large / sensitive) content itself.
func hookPostTool(cfg *hookConfig, audit *policy.AuditLog, raw []byte) error {
	var in struct {
		ToolName   string          `json:"tool_name"`
		ToolOutput json.RawMessage `json:"tool_output"`
		Edits      json.RawMessage `json:"edits"`
	}
	_ = json.Unmarshal(raw, &in)
	if audit != nil && in.ToolName != "" {
		body := in.ToolOutput
		if len(body) == 0 {
			body = in.Edits
		}
		sum := sha256.Sum256(body)
		_ = audit.Append(policy.AuditRecord{
			Backend: "client", Peer: cfg.identity(),
			Method: "tools/result", Tool: in.ToolName,
			Decision: "observed", Rule: -1,
			Provenance: []string{"sha256:" + hex.EncodeToString(sum[:])},
		})
	}
	// PostToolUse is observe-only: return an empty (allow) response.
	fmt.Println("{}")
	return nil
}

// hookPrompt DLP-scans a submitted prompt and blocks on a match; it records the
// prompt (by hash) either way.
func hookPrompt(cfg *hookConfig, audit *policy.AuditLog, dlp *policy.PatternDLPHook, client string, raw []byte) error {
	var in struct {
		UserInput string `json:"user_input"`
		Prompt    string `json:"prompt"`
		Text      string `json:"text"`
	}
	_ = json.Unmarshal(raw, &in)
	prompt := firstNonEmpty(in.UserInput, in.Prompt, in.Text)
	blocked := false
	reason := ""
	if dlp != nil && prompt != "" {
		d := dlp.DecideTool(policy.ToolCallInfo{Tool: "prompt", Arguments: json.RawMessage(mustJSON(prompt))}, policy.Decision{Outcome: policy.OutcomeAllow, Allow: true})
		if d.Outcome == policy.OutcomeDeny {
			blocked, reason = true, d.Reason
		}
	}
	if audit != nil && prompt != "" {
		sum := sha256.Sum256([]byte(prompt))
		dec := "observed"
		if blocked {
			dec = "deny"
		}
		_ = audit.Append(policy.AuditRecord{
			Backend: "client:" + client, Peer: cfg.identity(),
			Method: "prompt", Decision: dec, Reason: reason, Rule: -1,
			Provenance: []string{"sha256:" + hex.EncodeToString(sum[:])},
		})
	}
	switch client {
	case "cursor":
		out := map[string]any{"continue": !blocked}
		if blocked {
			out["permission"] = "deny"
			out["agentMessage"] = reason
		}
		b, _ := json.Marshal(out)
		fmt.Println(string(b))
	default: // claude-code
		if blocked {
			b, _ := json.Marshal(map[string]any{"decision": "block", "reason": reason})
			fmt.Println(string(b))
		} else {
			fmt.Println("{}")
		}
	}
	return nil
}

// hookEventKind maps an explicit --event or the payload's own event field to
// one of pre-tool | post-tool | prompt.
func hookEventKind(explicit string, raw []byte) string {
	switch explicit {
	case "pre-tool", "post-tool", "prompt":
		return explicit
	}
	var peek struct {
		HookEventName string `json:"hook_event_name"`
	}
	_ = json.Unmarshal(raw, &peek)
	switch peek.HookEventName {
	case "PostToolUse", "PostToolUseFailure", "afterFileEdit", "afterMCPExecution":
		return "post-tool"
	case "UserPromptSubmit", "beforeSubmitPrompt":
		return "prompt"
	default:
		return "pre-tool"
	}
}

func hookSessionID(raw []byte) string {
	var peek struct {
		SessionID      string `json:"session_id"`
		ConversationID string `json:"conversation_id"`
	}
	_ = json.Unmarshal(raw, &peek)
	return firstNonEmpty(peek.SessionID, peek.ConversationID)
}

// hookConfig is the small YAML a hook adapter reads. It reuses the same Policy
// and DLP types the gateway uses, so a policy authored for a backend works here.
type hookConfig struct {
	Identity    string           `yaml:"identity"`
	AuditLog    string           `yaml:"audit_log"`
	Policy      *policy.Policy   `yaml:"policy"`
	DLP         []policy.DLPSpec `yaml:"dlp"`
	CosignStore string           `yaml:"cosign_store"`
	SessionDir  string           `yaml:"session_dir"`
	TaintTools  []string         `yaml:"taint_tools"`
}

func (h *hookConfig) identity() string {
	if h.Identity != "" {
		return h.Identity
	}
	return "local-agent"
}

func (h *hookConfig) isTaintTool(tool string) bool {
	for _, g := range h.TaintTools {
		if g == tool {
			return true
		}
		if ok, _ := path.Match(g, tool); ok {
			return true
		}
	}
	return false
}

// taintPath is the per-session taint marker file.
func (h *hookConfig) taintPath(sess string) string {
	if h.SessionDir == "" || sess == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(sess))
	return path.Join(h.SessionDir, "taint-"+hex.EncodeToString(sum[:8]))
}

func (h *hookConfig) readTaint(sess string) map[string]bool {
	p := h.taintPath(sess)
	if p == "" {
		return nil
	}
	if _, err := os.Stat(p); err == nil {
		return map[string]bool{"tainted": true}
	}
	return nil
}

func (h *hookConfig) markTainted(sess string) {
	p := h.taintPath(sess)
	if p == "" {
		return
	}
	_ = os.MkdirAll(h.SessionDir, 0o700)
	if f, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY, 0o600); err == nil {
		f.Close()
	}
}

func loadHookConfig(pathStr string) (*hookConfig, error) {
	if pathStr == "" {
		return nil, fmt.Errorf("meshmcp hook: --config <file> is required")
	}
	data, err := os.ReadFile(pathStr)
	if err != nil {
		return nil, fmt.Errorf("read hook config: %w", err)
	}
	var c hookConfig
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse hook config: %w", err)
	}
	if c.Policy == nil {
		return nil, fmt.Errorf("hook config %s: a policy is required", pathStr)
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

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }

// hookInstall prints the exact hook configuration to add to a client so its
// tool hooks call `meshmcp hook`. It prints (never silently edits the user's
// settings), so the operator pastes it where they want it.
func hookInstall(args []string) error {
	fs := flag.NewFlagSet("hook install", flag.ContinueOnError)
	client := fs.String("client", "claude-code", "claude-code | cursor | codex")
	cfgPath := fs.String("config", "./meshmcp-hook.yaml", "path to the hook policy config")
	if err := fs.Parse(args); err != nil {
		return err
	}
	c := *cfgPath
	switch *client {
	case "claude-code":
		fmt.Printf(`# Add to .claude/settings.json (project) or ~/.claude/settings.json (user):
{
  "hooks": {
    "PreToolUse":      [ { "matcher": "*", "hooks": [ { "type": "command", "command": "meshmcp hook --client claude-code --event pre-tool  --config %s" } ] } ],
    "PostToolUse":     [ { "matcher": "*", "hooks": [ { "type": "command", "command": "meshmcp hook --client claude-code --event post-tool --config %s" } ] } ],
    "UserPromptSubmit":[ { "hooks": [ { "type": "command", "command": "meshmcp hook --client claude-code --event prompt --config %s" } ] } ]
  }
}
`, c, c, c)
	case "cursor":
		fmt.Printf(`# Add to .cursor/hooks.json (project) or ~/.cursor/hooks.json (user):
{
  "version": 1,
  "hooks": {
    "beforeShellExecution": [ { "command": "meshmcp hook --client cursor --event pre-tool  --config %s" } ],
    "beforeMCPExecution":   [ { "command": "meshmcp hook --client cursor --event pre-tool  --config %s" } ],
    "afterFileEdit":        [ { "command": "meshmcp hook --client cursor --event post-tool --config %s" } ],
    "beforeSubmitPrompt":   [ { "command": "meshmcp hook --client cursor --event prompt --config %s" } ]
  }
}
`, c, c, c, c)
	case "codex":
		fmt.Printf(`# Codex hooks (~/.codex): wire a PermissionRequest hook to:
#   meshmcp hook --client codex --event pre-tool --config %s
# (Codex's hook config format is evolving; see its hooks docs for the exact key.)
`, c)
	default:
		return fmt.Errorf("unknown client %q (want: claude-code, cursor, codex)", *client)
	}
	return nil
}
