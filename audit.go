package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"meshmcp/policy"
)

// cmdAudit implements "meshmcp audit <subcommand>".
func cmdAudit(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: meshmcp audit <verify|keygen> ...")
	}
	switch args[0] {
	case "verify":
		return auditVerify(args[1:])
	case "keygen":
		return auditKeygen(args[1:])
	default:
		return fmt.Errorf("meshmcp audit: unknown subcommand %q (want: verify, keygen)", args[0])
	}
}

// auditKeygen generates a gateway Ed25519 signing key for audit checkpoints and
// prints the public key (which verifiers pin with --pubkey).
func auditKeygen(args []string) error {
	fs := flag.NewFlagSet("audit keygen", flag.ContinueOnError)
	out := fs.String("out", "audit-signing-key.json", "path to write the signing key (0600)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	signer, err := policy.GenerateSigner()
	if err != nil {
		return err
	}
	if err := signer.SaveSigner(*out); err != nil {
		return err
	}
	fmt.Printf("wrote signing key to %s\n", *out)
	fmt.Printf("public key: %s\n", signer.PubKeyHex())
	fmt.Printf("\nverifiers pin this with:\n  meshmcp audit verify <log> --checkpoints <cps> --pubkey %s\n", signer.PubKeyHex())
	return nil
}

// auditVerify verifies an audit log. With --checkpoints it performs the full
// non-repudiable check (Ed25519 signatures + Merkle roots), which catches even
// a full-file rewrite; without it, it verifies the tamper-evident hash chain.
// A broken chain returns an error (non-zero exit) for CI / compliance gates.
func auditVerify(args []string) error {
	// The audit log is the first argument; flags follow it.
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return fmt.Errorf("usage: meshmcp audit verify <audit-log> [--checkpoints <f> --pubkey <hex>]")
	}
	logPath := args[0]
	fs := flag.NewFlagSet("audit verify", flag.ContinueOnError)
	checkpoints := fs.String("checkpoints", "", "signed checkpoint file (enables signature verification)")
	pubkey := fs.String("pubkey", "", "expected signer public key (hex) to pin against")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}

	if *checkpoints != "" {
		return auditVerifySigned(logPath, *checkpoints, *pubkey)
	}

	f, err := os.Open(logPath)
	if err != nil {
		return err
	}
	defer f.Close()
	res, err := policy.VerifyChain(f)
	if err != nil {
		return fmt.Errorf("read audit log: %w", err)
	}
	if res.OK {
		fmt.Printf("OK  %d records, hash chain intact\n", res.Count)
		fmt.Printf("    head %s\n", res.LastHash)
		fmt.Printf("    (tamper-evident; add --checkpoints for non-repudiable signature verification)\n")
		return nil
	}
	fmt.Fprintf(os.Stderr, "TAMPERED  %d records read; chain breaks at seq %d\n", res.Count, res.BreakSeq)
	fmt.Fprintf(os.Stderr, "          %s\n", res.Reason)
	return fmt.Errorf("audit log %s failed verification", logPath)
}

func auditVerifySigned(logPath, cpPath, pubkey string) error {
	lf, err := os.Open(logPath)
	if err != nil {
		return err
	}
	defer lf.Close()
	cf, err := os.Open(cpPath)
	if err != nil {
		return err
	}
	defer cf.Close()

	res, err := policy.VerifySigned(lf, cf, pubkey)
	if err != nil {
		return fmt.Errorf("verify: %w", err)
	}
	if res.OK {
		fmt.Printf("OK  %d records, %d signed checkpoint(s), %d records committed\n", res.Records, res.Checkpoints, res.CoveredRecords)
		fmt.Printf("    signer %s\n", res.SignerPub)
		fmt.Printf("    non-repudiable: the log is complete and unedited, provable with the public key alone\n")
		return nil
	}
	fmt.Fprintf(os.Stderr, "FAILED  %d records, %d checkpoint(s) read\n", res.Records, res.Checkpoints)
	fmt.Fprintf(os.Stderr, "        %s\n", res.Reason)
	return fmt.Errorf("audit log %s failed signed verification", logPath)
}
