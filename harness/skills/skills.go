// Package skills is the harness's skill loader and registry. A skill is a
// SKILL.md document — YAML front-matter (name, description, triggers, an optional
// embedded MCP, provenance) plus a markdown body of instructions — loaded from
// three scopes (builtin, project `.harness/skills/`, user `~/.harness/skills/`),
// merging the source harnesses' conventions. A skill whose trigger matches the
// request is auto-injected (like omo's category-skill-reminder).
//
// Governance: a skill that embeds an MCP DECLARES it (Skill.EmbeddedMCP); the
// embedded MCP is only reachable over the mesh with broker-injected creds
// (enforced at the MCP tool layer, not here). Installing a new skill goes through
// the governed market, never an ad-hoc network fetch — so the loader only ever
// reads local, already-provenanced files.
package skills

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Scope is where a skill was loaded from.
type Scope string

const (
	Builtin Scope = "builtin"
	Project Scope = "project"
	User    Scope = "user"
)

// Skill is one loaded SKILL.md.
type Skill struct {
	Name        string
	Scope       Scope
	Description string
	Triggers    []string // keywords that auto-inject the skill
	EmbeddedMCP string   // declared embedded MCP name ("" = none)
	Provenance  string   // signed provenance / source ref
	Body        string   // markdown instructions
	Path        string
}

// frontMatter is the YAML header of a SKILL.md.
type frontMatter struct {
	Name        string   `yaml:"name"`
	Description string   `yaml:"description"`
	Triggers    []string `yaml:"triggers"`
	MCP         string   `yaml:"mcp"`
	Provenance  string   `yaml:"provenance"`
}

// ParseSkill parses SKILL.md content: an optional `---` fenced YAML front-matter
// followed by the markdown body. A file with no front-matter is treated as a
// bodiless skill named by fallbackName.
func ParseSkill(data []byte, scope Scope, path, fallbackName string) (Skill, error) {
	text := string(data)
	fm := frontMatter{}
	body := text
	if strings.HasPrefix(strings.TrimSpace(text), "---") {
		// split on the first two --- fences
		rest := strings.TrimSpace(text)
		rest = strings.TrimPrefix(rest, "---")
		if idx := strings.Index(rest, "\n---"); idx >= 0 {
			header := rest[:idx]
			body = strings.TrimSpace(rest[idx+len("\n---"):])
			if err := yaml.Unmarshal([]byte(header), &fm); err != nil {
				return Skill{}, fmt.Errorf("skills: parse front-matter of %s: %w", path, err)
			}
		}
	}
	name := fm.Name
	if name == "" {
		name = fallbackName
	}
	if name == "" {
		return Skill{}, fmt.Errorf("skills: %s has no name", path)
	}
	return Skill{
		Name:        name,
		Scope:       scope,
		Description: fm.Description,
		Triggers:    fm.Triggers,
		EmbeddedMCP: fm.MCP,
		Provenance:  fm.Provenance,
		Body:        body,
		Path:        path,
	}, nil
}

// LoadDir loads every SKILL.md under dir (recursively). A skill lives either as
// <dir>/<name>/SKILL.md or <dir>/<name>.md. Missing dir is not an error (that
// scope is simply empty).
func LoadDir(dir string, scope Scope) ([]Skill, error) {
	if dir == "" {
		return nil, nil
	}
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		return nil, nil
	}
	var out []Skill
	err = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		base := d.Name()
		if base != "SKILL.md" && !strings.HasSuffix(base, ".md") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		fallback := strings.TrimSuffix(base, ".md")
		if base == "SKILL.md" {
			fallback = filepath.Base(filepath.Dir(path))
		}
		s, err := ParseSkill(data, scope, path, fallback)
		if err != nil {
			return err
		}
		out = append(out, s)
		return nil
	})
	return out, err
}

// Registry holds loaded skills, later scopes overriding earlier by name (user >
// project > builtin).
type Registry struct {
	skills map[string]Skill
	order  []string
}

// NewRegistry builds an empty registry.
func NewRegistry() *Registry { return &Registry{skills: map[string]Skill{}} }

// Add registers or overrides a skill by name.
func (r *Registry) Add(s Skill) {
	if _, ok := r.skills[s.Name]; !ok {
		r.order = append(r.order, s.Name)
	}
	r.skills[s.Name] = s
}

// Get returns a skill by name.
func (r *Registry) Get(name string) (Skill, bool) {
	s, ok := r.skills[name]
	return s, ok
}

// List returns skills in load order.
func (r *Registry) List() []Skill {
	out := make([]Skill, 0, len(r.order))
	for _, n := range r.order {
		out = append(out, r.skills[n])
	}
	return out
}

// Match returns skills whose triggers appear in text (auto-injection), most
// specific (longest trigger) first.
func (r *Registry) Match(text string) []Skill {
	lc := strings.ToLower(text)
	type hit struct {
		s   Skill
		max int
	}
	var hits []hit
	for _, s := range r.List() {
		best := 0
		for _, tr := range s.Triggers {
			if tr != "" && strings.Contains(lc, strings.ToLower(tr)) && len(tr) > best {
				best = len(tr)
			}
		}
		if best > 0 {
			hits = append(hits, hit{s, best})
		}
	}
	sort.SliceStable(hits, func(i, j int) bool { return hits[i].max > hits[j].max })
	out := make([]Skill, len(hits))
	for i, h := range hits {
		out[i] = h.s
	}
	return out
}

// LoadScopes loads builtin skills plus project and user scope directories, in
// precedence order (user overrides project overrides builtin).
func LoadScopes(projectDir, userDir string) (*Registry, error) {
	reg := NewRegistry()
	for _, s := range BuiltinSkills() {
		reg.Add(s)
	}
	proj, err := LoadDir(projectDir, Project)
	if err != nil {
		return nil, err
	}
	for _, s := range proj {
		reg.Add(s)
	}
	usr, err := LoadDir(userDir, User)
	if err != nil {
		return nil, err
	}
	for _, s := range usr {
		reg.Add(s)
	}
	return reg, nil
}
