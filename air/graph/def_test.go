package graph

import (
	"errors"
	"testing"
)

const reflectYAML = `
name: sql-fixer
entry: draft
bounds:
  max_iterations: 25
  cost_budget: 500000
  converge: "critic.ok == true"
nodes:
  - id: draft
    backend: rag.mesh:7100
    tool: rag_search
    args: {query: "schema"}
    edges:
      - to: critic
  - id: critic
    backend: lint.mesh:7100
    tool: lint
    edges:
      - to: draft
        when: "critic.ok == false"
        loop: true
      - to: execute
        when: "critic.ok == true"
  - id: execute
    backend: mail.mesh:7100
    tool: send
    side_effecting: true
    require_cosign: true
    edges:
      - to: END
`

func TestDefinition_ParseAndCompile(t *testing.T) {
	def, err := Parse([]byte(reflectYAML))
	if err != nil {
		t.Fatal(err)
	}
	if def.Name != "sql-fixer" || def.Entry != "draft" || len(def.Nodes) != 3 {
		t.Fatalf("unexpected parse: %+v", def)
	}
	exec, ok := def.Node("execute")
	if !ok || !exec.SideEffecting || !exec.RequireCosign {
		t.Fatalf("execute node spec not parsed: %+v", exec)
	}
	g, err := def.Compile()
	if err != nil {
		t.Fatal(err)
	}
	if g.Bounds.MaxIterations != 25 || g.Bounds.Converge == nil {
		t.Fatalf("bounds not compiled: %+v", g.Bounds)
	}
	if _, found := g.node("critic"); !found {
		t.Fatal("critic node missing after compile")
	}
}

func TestDefinition_CompileRejectsUnknownEdge(t *testing.T) {
	bad := `
entry: a
bounds: {max_iterations: 5}
nodes:
  - id: a
    edges:
      - to: ghost
`
	def, err := Parse([]byte(bad))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := def.Compile(); !errors.Is(err, ErrInvalidGraph) {
		t.Fatalf("expected ErrInvalidGraph for unknown edge target, got %v", err)
	}
}

func TestDefinition_ParseRejectsUnknownField(t *testing.T) {
	bad := `
entry: a
nodes:
  - id: a
    bogus_field: 1
`
	if _, err := Parse([]byte(bad)); err == nil {
		t.Fatal("expected parse error for unknown field")
	}
}
