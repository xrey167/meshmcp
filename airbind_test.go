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
		{"invalid glob fails closed", bindMatch{Peer: "[bad"}, false},
	}
	for _, c := range cases {
		if got := matchRecord(c.m, r); got != c.want {
			t.Errorf("%s: matchRecord=%v, want %v", c.name, got, c.want)
		}
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
