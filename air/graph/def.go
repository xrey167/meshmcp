package graph

import (
	"bytes"
	"fmt"

	"gopkg.in/yaml.v3"
)

// Definition is the declarative, serializable form of a graph — what a user
// writes in YAML and what the runner persists into a checkpoint so a resume can
// rebuild the exact same structure. It carries node tool-call specs (backend /
// tool / args) and edge predicates as STRINGS; Compile turns it into an in-memory
// Graph with compiled predicates. Node execute functions are NOT part of the
// definition — the runner attaches them — which is what keeps this format pure
// and free of any mesh/gateway coupling.
type Definition struct {
	Name   string    `yaml:"name" json:"name"`
	Entry  string    `yaml:"entry" json:"entry"`
	Bounds BoundsDef `yaml:"bounds" json:"bounds"`
	Nodes  []NodeDef `yaml:"nodes" json:"nodes"`
}

// BoundsDef is the serializable form of Bounds: MaxIterations and CostBudget as
// numbers and Converge as a predicate expression string.
type BoundsDef struct {
	MaxIterations int    `yaml:"max_iterations" json:"max_iterations"`
	CostBudget    int    `yaml:"cost_budget" json:"cost_budget"`
	Converge      string `yaml:"converge" json:"converge"`
}

// NodeDef is one node's declaration: its id, the governed tool call it makes
// (backend + tool + args, run through the egress gateway by the runner), whether
// it is side-effecting (so the runner brackets it with a pre-execution intent to
// stay double-fire-safe on resume) and whether it requires a human co-sign, plus
// its conditional edges.
type NodeDef struct {
	ID            string         `yaml:"id" json:"id"`
	Backend       string         `yaml:"backend" json:"backend"`
	Tool          string         `yaml:"tool" json:"tool"`
	Args          map[string]any `yaml:"args" json:"args"`
	SideEffecting bool           `yaml:"side_effecting" json:"side_effecting"`
	RequireCosign bool           `yaml:"require_cosign" json:"require_cosign"`
	Edges         []EdgeDef      `yaml:"edges" json:"edges"`
}

// EdgeDef is the serializable form of an Edge: a target, an optional When
// predicate expression, and a Loop marker for a back-edge.
type EdgeDef struct {
	To   string `yaml:"to" json:"to"`
	When string `yaml:"when" json:"when"`
	Loop bool   `yaml:"loop" json:"loop"`
}

// Parse decodes a YAML graph definition, rejecting unknown fields so a typo in a
// node key is an error rather than a silently ignored, mis-wired graph.
func Parse(data []byte) (*Definition, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("graph: empty definition")
	}
	var d Definition
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&d); err != nil {
		return nil, fmt.Errorf("graph: parse definition: %w", err)
	}
	return &d, nil
}

// Node returns the definition of node id and whether it exists — used by the
// runner to look up a node's tool-call spec while the Graph drives routing.
func (d *Definition) Node(id string) (NodeDef, bool) {
	for _, n := range d.Nodes {
		if n.ID == id {
			return n, true
		}
	}
	return NodeDef{}, false
}

// Compile turns a Definition into a validated in-memory Graph: it compiles the
// convergence and every edge predicate, wires the node/edge structure (Exec left
// nil for the runner to attach), and runs Validate — which coerces a non-positive
// MaxIterations to the safe default, so the compiled graph is always bounded. A
// bad predicate expression or an invalid structure is reported here, at load
// time, before any node runs.
func (d *Definition) Compile() (*Graph, error) {
	converge, err := CompilePredicate(d.Bounds.Converge)
	if err != nil {
		return nil, fmt.Errorf("graph: converge predicate: %w", err)
	}
	nodes := make([]Node, 0, len(d.Nodes))
	for _, nd := range d.Nodes {
		edges := make([]Edge, 0, len(nd.Edges))
		for _, ed := range nd.Edges {
			when, err := CompilePredicate(ed.When)
			if err != nil {
				return nil, fmt.Errorf("graph: node %q edge to %q: %w", nd.ID, ed.To, err)
			}
			edges = append(edges, Edge{To: ed.To, When: when, Loop: ed.Loop})
		}
		nodes = append(nodes, Node{ID: nd.ID, Edges: edges})
	}
	g := &Graph{
		Name:  d.Name,
		Entry: d.Entry,
		Nodes: nodes,
		Bounds: Bounds{
			Converge:      converge,
			MaxIterations: d.Bounds.MaxIterations,
			CostBudget:    d.Bounds.CostBudget,
		},
	}
	if err := g.Validate(); err != nil {
		return nil, err
	}
	return g, nil
}
