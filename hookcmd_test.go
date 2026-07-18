package main

import (
	"encoding/json"
	"strings"
	"testing"

	"meshmcp/policy"
)

func TestHookDecodeAndEncodeClaudeCode(t *testing.T) {
	// Decode a Claude Code PreToolUse payload.
	call := decodeHookCall("claude-code",
		[]byte(`{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}`))
	if call.Tool != "Bash" || !strings.Contains(string(call.Args), "rm -rf") {
		t.Fatalf("decode claude-code: %+v", call)
	}

	// Encode a deny.
	out := encodeHookDecision("claude-code", policy.Decision{Outcome: policy.OutcomeDeny, Reason: "blocked by rule"}, "Bash")
	var m struct {
		HSO struct {
			PermissionDecision       string `json:"permissionDecision"`
			PermissionDecisionReason string `json:"permissionDecisionReason"`
		} `json:"hookSpecificOutput"`
	}
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatal(err)
	}
	if m.HSO.PermissionDecision != "deny" || m.HSO.PermissionDecisionReason == "" {
		t.Fatalf("claude-code encode: %s", out)
	}
}

func TestHookEncodeCursorAndCodex(t *testing.T) {
	// Cursor: deny → permission:"deny", continue:false.
	out := encodeHookDecision("cursor", policy.Decision{Outcome: policy.OutcomeDeny, Reason: "nope"}, "Shell")
	var c struct {
		Permission string `json:"permission"`
		Continue   bool   `json:"continue"`
	}
	json.Unmarshal(out, &c)
	if c.Permission != "deny" || c.Continue {
		t.Fatalf("cursor deny encode: %s", out)
	}
	// Cursor: allow → permission:"allow".
	out = encodeHookDecision("cursor", policy.Decision{Outcome: policy.OutcomeAllow, Allow: true}, "Read")
	json.Unmarshal(out, &c)
	if c.Permission != "allow" {
		t.Fatalf("cursor allow encode: %s", out)
	}
	// Codex: cosign → decision:"decline".
	out = encodeHookDecision("codex", policy.Decision{Outcome: policy.OutcomeCosign, Reason: "needs human"}, "transfer")
	var cd struct {
		Decision string `json:"decision"`
	}
	json.Unmarshal(out, &cd)
	if cd.Decision != "decline" {
		t.Fatalf("codex cosign encode: %s", out)
	}
}

func TestHookCursorDecodeShell(t *testing.T) {
	call := decodeHookCall("cursor", []byte(`{"command":"curl http://evil"}`))
	if call.Tool != "Shell" || !strings.Contains(string(call.Args), "curl") {
		t.Fatalf("cursor shell decode: %+v", call)
	}
}

func TestHookTaintStateMachine(t *testing.T) {
	dir := t.TempDir()
	cfg := &hookConfig{SessionDir: dir, TaintTools: []string{"WebFetch", "mcp__*fetch*"}}

	// Tool matching.
	if !cfg.isTaintTool("WebFetch") || !cfg.isTaintTool("mcp__web__fetch_url") {
		t.Fatal("taint tool glob match failed")
	}
	if cfg.isTaintTool("Read") {
		t.Fatal("Read should not be a taint tool")
	}

	// A fresh session is clean; marking taints only that session.
	if cfg.readTaint("s1") != nil {
		t.Fatal("fresh session should be clean")
	}
	cfg.markTainted("s1")
	if cfg.readTaint("s1")["tainted"] != true {
		t.Fatal("s1 should be tainted after markTainted")
	}
	if cfg.readTaint("s2") != nil {
		t.Fatal("taint must be per-session (s2 unaffected)")
	}

	// No session_dir → taint is a no-op (nil labels, never panics).
	nocfg := &hookConfig{TaintTools: []string{"WebFetch"}}
	nocfg.markTainted("s1")
	if nocfg.readTaint("s1") != nil {
		t.Fatal("without session_dir taint must be a no-op")
	}
}

func TestHookEventKindDetection(t *testing.T) {
	cases := map[string]string{
		`{"hook_event_name":"PreToolUse"}`:         "pre-tool",
		`{"hook_event_name":"PostToolUse"}`:        "post-tool",
		`{"hook_event_name":"afterFileEdit"}`:      "post-tool",
		`{"hook_event_name":"UserPromptSubmit"}`:   "prompt",
		`{"hook_event_name":"beforeSubmitPrompt"}`: "prompt",
		`{"tool_name":"Bash"}`:                     "pre-tool", // no event field → default
	}
	for raw, want := range cases {
		if got := hookEventKind("", []byte(raw)); got != want {
			t.Errorf("hookEventKind(%s) = %q, want %q", raw, got, want)
		}
	}
	// An explicit --event overrides the payload.
	if got := hookEventKind("prompt", []byte(`{"hook_event_name":"PreToolUse"}`)); got != "prompt" {
		t.Errorf("explicit event override failed: %q", got)
	}
}
