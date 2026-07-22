package main

import (
	"os"
	"strings"
	"testing"
)

func rec(decision, backend, method, tool, peer string) streamRecord {
	return streamRecord{Decision: decision, Backend: backend, Method: method, Tool: tool, Peer: peer}
}

func TestMatchRecord(t *testing.T) {
	r := rec("deny", "drop", "drop/recv", "abc123", "phone.mesh")
	r.Reason = "not in allow list"
	cases := []struct {
		name string
		m    bindMatch
		want bool
	}{
		{"all-empty matches anything", bindMatch{}, true},
		{"decision match", bindMatch{Decision: "deny"}, true},
		{"decision miss", bindMatch{Decision: "allow"}, false},
		{"backend glob", bindMatch{Backend: "dr*"}, true},
		{"peer glob", bindMatch{Peer: "*.mesh"}, true},
		{"peer miss", bindMatch{Peer: "*.other"}, false},
		{"all fields match", bindMatch{Decision: "deny", Backend: "drop", Peer: "phone.mesh"}, true},
		{"one field misses -> no match", bindMatch{Decision: "deny", Peer: "laptop.mesh"}, false},
		{"literal non-glob mismatch", bindMatch{Peer: "[bad"}, false},
		// The '/' bug: a wildcard must span the separator in slash-bearing fields.
		{"method star spans slash", bindMatch{Method: "*"}, true},
		{"method prefix spans slash", bindMatch{Method: "drop/*"}, true},
		{"method contains spans slash", bindMatch{Method: "*rec*"}, true},
		// The reason trigger — the "why" is now matchable.
		{"reason glob", bindMatch{Reason: "*allow list*"}, true},
		{"reason miss", bindMatch{Reason: "*cost*"}, false},
	}
	for _, c := range cases {
		if got := matchRecord(c.m, r); got != c.want {
			t.Errorf("%s: matchRecord=%v, want %v", c.name, got, c.want)
		}
	}
}

// TestGlobMatch pins the wildcard semantics that distinguish this matcher from
// path.Match: `*` spans '/', `?` is one char, and anchoring is full-string.
func TestGlobMatch(t *testing.T) {
	cases := []struct {
		pattern, s string
		want       bool
	}{
		{"*", "tools/call", true}, // path.Match returns false here
		{"notifications/*", "notifications/air/steer", true},
		{"*steer*", "notifications/air/steer", true},
		{"tools/*", "tools/call", true},
		{"tools/?all", "tools/call", true},
		{"tools/?all", "tools/xxall", false},
		{"exact", "exact", true},
		{"exact", "exacts", false},
		{"", "", true},
		{"*", "", true},
		{"a*b*c", "axxbyyc", true},
		{"a*b*c", "axxbyy", false},
	}
	for _, c := range cases {
		if got := globMatch(c.pattern, c.s); got != c.want {
			t.Errorf("globMatch(%q,%q)=%v, want %v", c.pattern, c.s, got, c.want)
		}
	}
}

// TestFireBindingHelpers covers the pure reaction builders: print rows sanitize
// attacker-influenced fields, and run args are template-expanded.
func TestFireBindingHelpers(t *testing.T) {
	old := colorOn
	colorOn = false
	defer func() { colorOn = old }()

	r := rec("deny", "drop", "drop/recv", "sha", "phone.mesh")
	// A hostile field carrying an ANSI escape must be stripped from the print row.
	r.Reason = "evil\x1b[31mred\x1b]0;title\x07"
	line := formatPrintLine(bindingRule{Name: "notify", Do: bindAction{Print: "{peer} — {reason}"}}, r)
	if !strings.Contains(line, "phone.mesh") || !strings.Contains(line, "notify") {
		t.Fatalf("print row missing expected content: %q", line)
	}
	if strings.ContainsRune(line, '\x1b') {
		t.Fatalf("escape sequence not sanitized from print row: %q", line)
	}

	args := buildRunArgs(bindingRule{Do: bindAction{Run: []string{"air", "agent-steer", "--text", "drop from {peer}"}}}, r)
	want := []string{"air", "agent-steer", "--text", "drop from phone.mesh"}
	if strings.Join(args, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("buildRunArgs = %v, want %v", args, want)
	}
}

func TestExpandTemplate(t *testing.T) {
	r := rec("deny", "drop", "drop/recv", "sha256abc", "phone.mesh")
	r.Reason = "not in allow list"
	got := expandTemplate("{decision} {peer} {method} {backend} {tool} — {reason}", r)
	want := "deny phone.mesh drop/recv drop sha256abc — not in allow list"
	if got != want {
		t.Errorf("expandTemplate = %q, want %q", got, want)
	}
	// Unknown placeholders are left as-is.
	if got := expandTemplate("{unknown}", r); got != "{unknown}" {
		t.Errorf("unknown placeholder mangled: %q", got)
	}
}

func TestValidateBindings(t *testing.T) {
	print1 := bindingRule{Name: "n1", Do: bindAction{Print: "hi"}}
	run1 := bindingRule{Name: "r1", Do: bindAction{Run: []string{"air", "whoami"}}}

	if err := validateBindings(bindConfig{}, false); err == nil {
		t.Error("empty config should error")
	}
	if err := validateBindings(bindConfig{Bindings: []bindingRule{{Do: bindAction{Print: "x"}}}}, false); err == nil {
		t.Error("missing name should error")
	}
	if err := validateBindings(bindConfig{Bindings: []bindingRule{{Name: "n"}}}, false); err == nil {
		t.Error("no action should error")
	}
	both := bindingRule{Name: "b", Do: bindAction{Print: "x", Run: []string{"air"}}}
	if err := validateBindings(bindConfig{Bindings: []bindingRule{both}}, true); err == nil {
		t.Error("both print and run should error")
	}
	dup := bindConfig{Bindings: []bindingRule{print1, {Name: "n1", Do: bindAction{Print: "y"}}}}
	if err := validateBindings(dup, false); err == nil {
		t.Error("duplicate name should error")
	}
	// A run action is refused without --allow-exec (fail closed)...
	if err := validateBindings(bindConfig{Bindings: []bindingRule{run1}}, false); err == nil {
		t.Error("run without allow-exec should error")
	}
	// ...and permitted with it.
	if err := validateBindings(bindConfig{Bindings: []bindingRule{run1}}, true); err != nil {
		t.Errorf("run with allow-exec should pass: %v", err)
	}
	// A valid print-only config passes without exec.
	if err := validateBindings(bindConfig{Bindings: []bindingRule{print1}}, false); err != nil {
		t.Errorf("valid print config should pass: %v", err)
	}
}

func TestLoadBindConfig(t *testing.T) {
	dir := t.TempDir()
	p := dir + "/bindings.yaml"
	yaml := `bindings:
  - name: notify-on-deny
    on: { decision: deny }
    do: { print: "DENIED {peer} {method}" }
  - name: watch-drops
    on: { backend: drop, decision: allow }
    do: { run: ["air", "agent-steer", "100.64.0.5:9120", "--type", "nudge", "--text", "drop from {peer}"] }
`
	if err := os.WriteFile(p, []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadBindConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Bindings) != 2 {
		t.Fatalf("want 2 bindings, got %d", len(cfg.Bindings))
	}
	if cfg.Bindings[0].On.Decision != "deny" || cfg.Bindings[0].Do.Print == "" {
		t.Errorf("binding 0 parsed wrong: %+v", cfg.Bindings[0])
	}
	if got := strings.Join(cfg.Bindings[1].Do.Run, " "); !strings.Contains(got, "agent-steer") {
		t.Errorf("binding 1 run parsed wrong: %q", got)
	}
}
