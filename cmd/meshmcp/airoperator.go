package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// air operator is the second-operator onboarding verb: it manages the config's
// `operators` list — the people permitted to approve co-signs, approve/deny/
// revoke pairing, and list/steer sessions. Adding an operator here grants that
// control surface WITHOUT hand-editing control.allow (they are recognized on the
// same acl). Identity is the unforgeable WireGuard public key.
//
// add/remove edit the config surgically at the YAML-node level, so the rest of a
// hand-authored file — its comments, ordering, and formatting — is preserved;
// only the operators subtree changes.

// cmdAirOperator implements `air operator <list|add|remove>`.
func cmdAirOperator(args []string) error {
	if len(args) == 0 {
		return airOperatorUsage()
	}
	switch args[0] {
	case "list", "ls":
		return cmdAirOperatorList(args[1:])
	case "add":
		return cmdAirOperatorAdd(args[1:])
	case "remove", "rm":
		return cmdAirOperatorRemove(args[1:])
	case "-h", "--help", "help":
		return airOperatorUsage()
	default:
		return fmt.Errorf("air operator: unknown subcommand %q (want list|add|remove)", args[0])
	}
}

func airOperatorUsage() error {
	fmt.Println("usage: meshmcp air operator <list|add|remove>")
	fmt.Println("  list                                    show configured operators")
	fmt.Println("  add    --pubkey <k> [--fqdn <f>] [--role <r>]   grant the control/pairing surface")
	fmt.Println("  remove --pubkey <k>                     revoke it")
	fmt.Println("  (all take --config <path>, default: the resolved gateway config)")
	return nil
}

// cmdAirOperatorList prints the configured operators.
func cmdAirOperatorList(args []string) error {
	fs := flag.NewFlagSet("air operator list", flag.ExitOnError)
	cfgPath := fs.String("config", defaultConfigPath(), "path to the meshmcp config file")
	asJSON := fs.Bool("json", false, "print the operators as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		return fmt.Errorf("air operator list: %w", err)
	}
	if *asJSON {
		return printJSONValue(cfg.Operators)
	}
	if len(cfg.Operators) == 0 {
		fmt.Println(dim("no operators configured in " + *cfgPath))
		fmt.Println(dim("  add one with `air operator add --pubkey <key>`"))
		return nil
	}
	fmt.Println(okLine("%d operator(s) in %s", len(cfg.Operators), bold(*cfgPath)))
	for _, o := range cfg.Operators {
		line := "  " + cyan(o.PubKey)
		if o.FQDN != "" {
			line += dim("  " + o.FQDN)
		}
		if len(o.Roles) > 0 {
			line += dim("  roles=" + strings.Join(o.Roles, ","))
		}
		fmt.Println(line)
	}
	return nil
}

// cmdAirOperatorAdd appends an operator to the config, preserving the rest of
// the file. It refuses a duplicate pubkey and re-validates the whole config
// before writing, so a bad edit never lands on disk.
func cmdAirOperatorAdd(args []string) error {
	fs := flag.NewFlagSet("air operator add", flag.ExitOnError)
	cfgPath := fs.String("config", defaultConfigPath(), "path to the meshmcp config file")
	pubkey := fs.String("pubkey", "", "the operator's WireGuard public key (required)")
	fqdn := fs.String("fqdn", "", "advisory mesh FQDN")
	var roles stringList
	fs.Var(&roles, "role", "role label (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*pubkey) == "" {
		return fmt.Errorf("air operator add: --pubkey is required")
	}

	doc, root, err := loadConfigDoc(*cfgPath)
	if err != nil {
		return fmt.Errorf("air operator add: %w", err)
	}
	seq := ensureSeq(root, "operators")
	// Refuse a duplicate pubkey up front (clearer than the post-write validation).
	for _, op := range seq.Content {
		if v := mapScalar(op, "pubkey"); v == *pubkey {
			return fmt.Errorf("air operator add: pubkey %q is already an operator", *pubkey)
		}
	}
	seq.Content = append(seq.Content, operatorNode(*pubkey, *fqdn, roles))

	if err := marshalValidateWrite(*cfgPath, doc); err != nil {
		return fmt.Errorf("air operator add: %w", err)
	}
	fmt.Println(okLine("added operator %s", cyan(*pubkey)))
	return nil
}

// cmdAirOperatorRemove drops the operator with the given pubkey from the config.
func cmdAirOperatorRemove(args []string) error {
	fs := flag.NewFlagSet("air operator remove", flag.ExitOnError)
	cfgPath := fs.String("config", defaultConfigPath(), "path to the meshmcp config file")
	pubkey := fs.String("pubkey", "", "the operator's WireGuard public key (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*pubkey) == "" {
		return fmt.Errorf("air operator remove: --pubkey is required")
	}

	doc, root, err := loadConfigDoc(*cfgPath)
	if err != nil {
		return fmt.Errorf("air operator remove: %w", err)
	}
	seq := mapValue(root, "operators")
	if seq == nil || seq.Kind != yaml.SequenceNode {
		return fmt.Errorf("air operator remove: no operators configured")
	}
	kept := seq.Content[:0]
	removed := false
	for _, op := range seq.Content {
		if mapScalar(op, "pubkey") == *pubkey {
			removed = true
			continue
		}
		kept = append(kept, op)
	}
	if !removed {
		return fmt.Errorf("air operator remove: %q is not an operator", *pubkey)
	}
	seq.Content = kept

	if err := marshalValidateWrite(*cfgPath, doc); err != nil {
		return fmt.Errorf("air operator remove: %w", err)
	}
	fmt.Println(okLine("removed operator %s", cyan(*pubkey)))
	return nil
}

// --- YAML-node helpers: surgical edits that preserve the rest of the file ---

// loadConfigDoc reads the config file into a YAML document node and returns the
// document plus its root mapping node. It errors on a missing file (an operator
// edit targets an existing gateway config) or a non-mapping root.
func loadConfigDoc(path string) (*yaml.Node, *yaml.Node, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("read config %s: %w", path, err)
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return nil, nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, nil, fmt.Errorf("config %s is not a YAML mapping", path)
	}
	return &doc, doc.Content[0], nil
}

// mapValue returns the value node for key in a mapping node, or nil.
func mapValue(root *yaml.Node, key string) *yaml.Node {
	for i := 0; i+1 < len(root.Content); i += 2 {
		if root.Content[i].Value == key {
			return root.Content[i+1]
		}
	}
	return nil
}

// mapScalar returns the string value of a scalar key in a mapping node, or "".
func mapScalar(root *yaml.Node, key string) string {
	if root.Kind != yaml.MappingNode {
		return ""
	}
	if v := mapValue(root, key); v != nil && v.Kind == yaml.ScalarNode {
		return v.Value
	}
	return ""
}

// ensureSeq returns the sequence node for key, creating an empty one (and its
// key) at the end of the mapping when absent.
func ensureSeq(root *yaml.Node, key string) *yaml.Node {
	if v := mapValue(root, key); v != nil {
		return v
	}
	keyNode := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}
	seq := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	root.Content = append(root.Content, keyNode, seq)
	return seq
}

// operatorNode builds a mapping node for one operator.
func operatorNode(pubkey, fqdn string, roles []string) *yaml.Node {
	m := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	add := func(k, v string) {
		m.Content = append(m.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: k},
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: v})
	}
	add("pubkey", pubkey)
	if fqdn != "" {
		add("fqdn", fqdn)
	}
	if len(roles) > 0 {
		seq := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
		for _, r := range roles {
			seq.Content = append(seq.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: r})
		}
		m.Content = append(m.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "roles"}, seq)
	}
	return m
}

// marshalValidateWrite renders the mutated document, re-validates it through
// the REAL loadConfig path (so a mutation can never write a gateway config that
// would refuse to load — e.g. one that leaves an enabled control endpoint with
// no allowed identity), and only then atomically replaces the file (0600).
func marshalValidateWrite(path string, doc *yaml.Node) error {
	out, err := yaml.Marshal(doc)
	if err != nil {
		return fmt.Errorf("render config: %w", err)
	}
	// Full validation via the real loader against a sibling temp file, so the
	// canonical path never holds an invalid config even transiently.
	tmp := path + ".tmp-validate"
	if err := os.WriteFile(tmp, out, 0o600); err != nil {
		return fmt.Errorf("write config %s: %w", tmp, err)
	}
	if _, err := loadConfig(tmp); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("mutation would produce an invalid config (nothing written): %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("replace config %s: %w", path, err)
	}
	return nil
}
