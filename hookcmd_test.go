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
