package main

import (
	"fmt"
	"os"

	"meshmcp/policy"
)

// cmdAudit implements "meshmcp audit <subcommand>".
func cmdAudit(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: meshmcp audit verify <file>")
	}
	switch args[0] {
	case "verify":
		return auditVerify(args[1:])
	default:
		return fmt.Errorf("meshmcp audit: unknown subcommand %q (want: verify)", args[0])
	}
}

// auditVerify walks an audit log's hash chain and reports whether it is
// intact. Exit status is non-zero (via a returned error) if the chain is
// broken, so it drops straight into CI / compliance checks.
func auditVerify(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: meshmcp audit verify <file>")
	}
	f, err := os.Open(args[0])
	if err != nil {
		return err
	}
	defer f.Close()

	res, err := policy.VerifyChain(f)
	if err != nil {
		return fmt.Errorf("read audit log: %w", err)
	}
	if res.OK {
		fmt.Printf("OK  %d records, chain intact\n", res.Count)
		fmt.Printf("    head %s\n", res.LastHash)
		return nil
	}
	fmt.Fprintf(os.Stderr, "TAMPERED  %d records read; chain breaks at seq %d\n", res.Count, res.BreakSeq)
	fmt.Fprintf(os.Stderr, "          %s\n", res.Reason)
	return fmt.Errorf("audit log %s failed verification", args[0])
}
