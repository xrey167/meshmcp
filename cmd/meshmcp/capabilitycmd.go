package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/xrey167/meshmcp/policy"
)

// stringList is a repeatable string flag.
type stringList []string

func (s *stringList) String() string { return fmt.Sprintf("%v", []string(*s)) }
func (s *stringList) Set(v string) error {
	*s = append(*s, v)
	return nil
}

// cmdCapability implements "meshmcp capability <keygen|issue>".
func cmdCapability(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: meshmcp capability <keygen|issue> ...")
	}
	switch args[0] {
	case "keygen":
		return capabilityKeygen(args[1:])
	case "issue":
		return capabilityIssue(args[1:])
	case "revoke":
		return capabilityRevoke(args[1:])
	case "list":
		return capabilityList(args[1:])
	default:
		return fmt.Errorf("meshmcp capability: unknown subcommand %q (want: keygen, issue, revoke, list)", args[0])
	}
}

// capabilityRevoke marks a capability id as revoked in a store the gateway
// pins via capabilities.revocation_store, so the token fails closed even before
// it expires.
func capabilityRevoke(args []string) error {
	fs := flag.NewFlagSet("capability revoke", flag.ContinueOnError)
	store := fs.String("store", "", "revocation store directory (matches the backend's revocation_store)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *store == "" || fs.NArg() != 1 {
		return fmt.Errorf("usage: meshmcp capability revoke --store <dir> <cap-id>")
	}
	id := fs.Arg(0)
	if err := (policy.FileRevocation{Dir: *store}).Revoke(id); err != nil {
		return fmt.Errorf("revoke %s: %w", id, err)
	}
	fmt.Printf("revoked capability %s (it will now fail closed at every gateway sharing %s)\n", id, *store)
	return nil
}

// capabilityList prints the revoked capability ids in a store.
func capabilityList(args []string) error {
	fs := flag.NewFlagSet("capability list", flag.ContinueOnError)
	store := fs.String("store", "", "revocation store directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *store == "" {
		return fmt.Errorf("usage: meshmcp capability list --store <dir>")
	}
	ids, err := (policy.FileRevocation{Dir: *store}).List()
	if err != nil {
		return err
	}
	if len(ids) == 0 {
		fmt.Println("no revoked capabilities")
		return nil
	}
	for _, id := range ids {
		fmt.Println(id)
	}
	return nil
}

// capabilityKeygen generates an Ed25519 authority key and prints its public key
// (which backends pin in capabilities.trusted_public_keys).
func capabilityKeygen(args []string) error {
	fs := flag.NewFlagSet("capability keygen", flag.ContinueOnError)
	out := fs.String("out", "capability-key.json", "path to write the authority key (0600)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	s, err := policy.GenerateSigner()
	if err != nil {
		return err
	}
	if err := s.SaveSigner(*out); err != nil {
		return err
	}
	fmt.Printf("wrote capability authority key to %s\n", *out)
	fmt.Printf("public key: %s\n", s.PubKeyHex())
	fmt.Printf("\npin it in a backend:\n  capabilities:\n    trusted_public_keys: [\"%s\"]\n", s.PubKeyHex())
	return nil
}

// capabilityIssue signs a short-lived grant and prints the token to stdout.
func capabilityIssue(args []string) error {
	fs := flag.NewFlagSet("capability issue", flag.ContinueOnError)
	keyPath := fs.String("key", "", "authority key file from `capability keygen` (required)")
	issuer := fs.String("issuer", "", "named issuer")
	subject := fs.String("subject", "", "caller's WireGuard public key (the grant's subject) (required)")
	audience := fs.String("audience", "", "backend name the grant is for (required)")
	ttl := fs.Duration("ttl", 15*time.Minute, "lifetime (max 24h)")
	notBefore := fs.Duration("not-before", 0, "delay before the grant becomes valid")
	var tools stringList
	fs.Var(&tools, "tool", "tool-name glob the grant covers (repeatable) (required)")
	var corpora stringList
	fs.Var(&corpora, "corpus", "corpus/subgraph glob the grant may query (repeatable; knowledge capabilities)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *keyPath == "" || *subject == "" || *audience == "" || len(tools) == 0 {
		return fmt.Errorf("capability issue: --key, --subject, --audience, and at least one --tool are required")
	}
	s, err := policy.LoadSigner(*keyPath)
	if err != nil {
		return fmt.Errorf("load authority key: %w", err)
	}
	now := time.Now()
	claims := policy.CapabilityClaims{
		Issuer:    *issuer,
		Subject:   *subject,
		Audience:  *audience,
		Tools:     tools,
		Corpora:   corpora,
		ExpiresAt: now.Add(*ttl).Unix(),
	}
	if *notBefore > 0 {
		claims.NotBefore = now.Add(*notBefore).Unix()
	}
	token, err := s.IssueCapability(claims, now)
	if err != nil {
		return err
	}
	// The token goes to stdout so it can be redirected to a 0600 file rather
	// than pasted into shell history.
	fmt.Fprintln(os.Stdout, token)
	fmt.Fprintf(os.Stderr, "issued capability for subject %s → %s (tools %v), valid %s\n", *subject, *audience, []string(tools), ttl.String())
	return nil
}
