package graph

import (
	"fmt"
	"strconv"
	"strings"
)

// CompilePredicate compiles a tiny, dependency-free predicate expression into a
// Predicate over GraphState. It is intentionally minimal — enough to route
// reflection/replan loops on node outputs and taint labels, no expression library.
//
// Grammar (no parentheses in v1; documented and deliberate):
//
//	expr   := or
//	or     := and ( "||" and )*
//	and    := atom ( "&&" atom )*
//	atom   := "label:" NAME            // true if the taint label is set
//	        | PATH OP VALUE            // compare a state path to a literal
//	        | PATH                     // truthy: the path resolves to true / non-zero / non-empty
//	OP     := "==" | "!=" | ">=" | "<=" | ">" | "<"
//	PATH   := NAME ( "." NAME )*       // node id then fields into its output map
//	VALUE  := true | false | number | "quoted string" | bareword
//
// A PATH that does not resolve is treated as absent: a comparison against it is
// false and a bare truthiness test is false (missing field = false), so a
// predicate never errors at evaluation time. An empty expression is a nil
// predicate (unconditional / never-converges), which callers handle.
func CompilePredicate(expr string) (Predicate, error) {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return nil, nil
	}
	orParts := splitTop(expr, "||")
	ands := make([][]atom, 0, len(orParts))
	for _, op := range orParts {
		andParts := splitTop(op, "&&")
		as := make([]atom, 0, len(andParts))
		for _, ap := range andParts {
			a, err := parseAtom(strings.TrimSpace(ap))
			if err != nil {
				return nil, err
			}
			as = append(as, a)
		}
		ands = append(ands, as)
	}
	return func(s GraphState) bool {
		for _, conj := range ands { // OR over conjunctions
			all := true
			for _, a := range conj {
				if !a.eval(s) {
					all = false
					break
				}
			}
			if all {
				return true
			}
		}
		return false
	}, nil
}

// splitTop splits s on sep. There are no parentheses in the grammar, so this is a
// plain substring split; it exists as a named seam should grouping ever be added.
func splitTop(s, sep string) []string {
	parts := strings.Split(s, sep)
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

// atom is one comparison, label test, or truthiness test.
type atom struct {
	label string // set => "label:<label>" test
	path  string // state path (empty when label is set)
	op    string // comparison operator ("" => truthiness)
	value string // right-hand literal (raw text)
}

func parseAtom(s string) (atom, error) {
	if s == "" {
		return atom{}, fmt.Errorf("graph: empty predicate atom")
	}
	if lbl, ok := strings.CutPrefix(s, "label:"); ok {
		lbl = strings.TrimSpace(lbl)
		if lbl == "" {
			return atom{}, fmt.Errorf("graph: empty label in predicate")
		}
		return atom{label: lbl}, nil
	}
	// Longest operators first so ">=" is not read as ">".
	for _, op := range []string{"==", "!=", ">=", "<=", ">", "<"} {
		if i := strings.Index(s, op); i >= 0 {
			lhs := strings.TrimSpace(s[:i])
			rhs := strings.TrimSpace(s[i+len(op):])
			if lhs == "" || rhs == "" {
				return atom{}, fmt.Errorf("graph: malformed comparison %q", s)
			}
			return atom{path: lhs, op: op, value: rhs}, nil
		}
	}
	return atom{path: s}, nil // bare truthiness
}

func (a atom) eval(s GraphState) bool {
	if a.label != "" {
		return s.Labels[a.label]
	}
	got, ok := resolvePath(s.Data, a.path)
	if a.op == "" { // truthiness
		return ok && truthy(got)
	}
	if !ok {
		return a.op == "!=" // a missing field differs from any concrete literal
	}
	return compare(got, a.value, a.op)
}

// resolvePath walks a dotted path into the nested Data payload. The first segment
// keys into Data (a node id); each further segment keys into a nested
// map[string]any (a field of that node's output). Returns false if any segment is
// missing or a non-terminal segment is not an object.
func resolvePath(data map[string]any, path string) (any, bool) {
	segs := strings.Split(path, ".")
	var cur any = data
	for _, seg := range segs {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		cur, ok = m[seg]
		if !ok {
			return nil, false
		}
	}
	return cur, true
}

// truthy reports whether a resolved value counts as true for a bare path atom.
func truthy(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case string:
		return x != ""
	case float64:
		return x != 0
	case int:
		return x != 0
	case nil:
		return false
	default:
		return true
	}
}

// compare evaluates `got OP literal`. Numbers compare numerically when both sides
// parse as numbers; otherwise == and != fall back to string equality and the
// ordering operators require numbers (a non-numeric ordering compare is false).
func compare(got any, literal, op string) bool {
	gf, gok := toFloat(got)
	lf, lok := toFloat(literal)
	if gok && lok {
		switch op {
		case "==":
			return gf == lf
		case "!=":
			return gf != lf
		case ">":
			return gf > lf
		case "<":
			return gf < lf
		case ">=":
			return gf >= lf
		case "<=":
			return gf <= lf
		}
	}
	gs := toString(got)
	ls := unquote(literal)
	switch op {
	case "==":
		return gs == ls
	case "!=":
		return gs != ls
	default:
		return false // ordering on non-numbers is undefined => false
	}
}

func toFloat(v any) (float64, bool) {
	switch x := v.(type) {
	case float64:
		return x, true
	case int:
		return float64(x), true
	case string:
		f, err := strconv.ParseFloat(strings.TrimSpace(x), 64)
		return f, err == nil
	default:
		return 0, false
	}
}

func toString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case bool:
		return strconv.FormatBool(x)
	case float64:
		return strconv.FormatFloat(x, 'g', -1, 64)
	case int:
		return strconv.Itoa(x)
	case nil:
		return ""
	default:
		return fmt.Sprintf("%v", x)
	}
}

// unquote strips a single pair of matching quotes from a literal, leaving bare
// words untouched.
func unquote(s string) string {
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}
