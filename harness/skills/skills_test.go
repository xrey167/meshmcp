package skills

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseSkillFrontMatter(t *testing.T) {
	data := []byte("---\nname: demo\ndescription: a demo skill\ntriggers: [foo, bar baz]\nmcp: websearch\nprovenance: market:signed\n---\n# Demo\nDo the thing.")
	s, err := ParseSkill(data, Project, "demo/SKILL.md", "")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if s.Name != "demo" || s.Description != "a demo skill" {
		t.Fatalf("front-matter not parsed: %+v", s)
	}
	if len(s.Triggers) != 2 || s.EmbeddedMCP != "websearch" || s.Provenance != "market:signed" {
		t.Fatalf("unexpected fields: %+v", s)
	}
	if s.Body == "" || s.Body[0] != '#' {
		t.Fatalf("body not extracted: %q", s.Body)
	}
}

func TestBuiltinsAndMatch(t *testing.T) {
	reg := NewRegistry()
	for _, s := range BuiltinSkills() {
		reg.Add(s)
	}
	if _, ok := reg.Get("git-master"); !ok {
		t.Fatal("git-master builtin missing")
	}
	m := reg.Match("please help me rebase my git branch")
	if len(m) == 0 || m[0].Name != "git-master" {
		t.Fatalf("expected git-master to match, got %v", names(m))
	}
	// A skill declaring an embedded MCP is surfaced so the tool layer can gate it.
	pw, _ := reg.Get("playwright")
	if pw.EmbeddedMCP != "browser" {
		t.Fatalf("playwright should declare an embedded MCP")
	}
}

func TestLoadScopesOverride(t *testing.T) {
	dir := t.TempDir()
	skillDir := filepath.Join(dir, "git-master")
	if err := os.MkdirAll(skillDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// A project skill named git-master overrides the builtin.
	body := "---\nname: git-master\ndescription: project override\ntriggers: [git]\n---\noverridden body"
	if err := os.WriteFile(filepath.Join(skillDir, "SKILL.md"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	reg, err := LoadScopes(dir, "")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	s, _ := reg.Get("git-master")
	if s.Description != "project override" || s.Scope != Project {
		t.Fatalf("project scope should override builtin, got %+v", s)
	}
}

func TestLoadDirMissingIsEmpty(t *testing.T) {
	got, err := LoadDir(filepath.Join(t.TempDir(), "nope"), User)
	if err != nil || got != nil {
		t.Fatalf("missing dir should be empty, no error: got=%v err=%v", got, err)
	}
}

func names(ss []Skill) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = s.Name
	}
	return out
}
