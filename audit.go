package main

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path"
	"strconv"
	"strings"

	"meshmcp/policy"
)

// cmdAudit implements "meshmcp audit <subcommand>".
func cmdAudit(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: meshmcp audit <verify|keygen|export> ...")
	}
	switch args[0] {
	case "verify":
		return auditVerify(args[1:])
	case "keygen":
		return auditKeygen(args[1:])
	case "export":
		return auditExport(args[1:])
	case "receipt":
		return auditReceipt(args[1:])
	default:
		return fmt.Errorf("meshmcp audit: unknown subcommand %q (want: verify, keygen, export, receipt)", args[0])
	}
}

// auditReceipt emits a verifiable provenance receipt: the provenance-bearing
// records (tool + content hashes) a session/peer produced, together with the
// hash-chain verdict and head. Because those records are committed in the
// tamper-evident chain (and signed checkpoints, if configured), a third party
// can independently confirm the receipt with `meshmcp audit verify` and match
// the head — "prove what this session's tools did/produced." Extends F6 to the
// client-hook layer (the PostToolUse hook stamps each result's content hash).
func auditReceipt(args []string) error {
	fs := flag.NewFlagSet("audit receipt", flag.ContinueOnError)
	in := fs.String("in", "", "audit log (JSONL) to build the receipt from (required)")
	session := fs.String("peer", "", "restrict to this peer/session identity (optional)")
	toolGlob := fs.String("tool", "", "restrict to tools matching this glob (optional)")
	all := fs.Bool("all", false, "include records without provenance hashes too")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *in == "" {
		return fmt.Errorf("usage: meshmcp audit receipt --in <file> [--peer <id>] [--tool <glob>] > receipt.json")
	}
	data, err := os.ReadFile(*in)
	if err != nil {
		return err
	}
	chain, _ := policy.VerifyChain(bytes.NewReader(data))

	type entry struct {
		Seq        int      `json:"seq"`
		Time       string   `json:"time,omitempty"`
		Peer       string   `json:"peer,omitempty"`
		Tool       string   `json:"tool,omitempty"`
		Decision   string   `json:"decision,omitempty"`
		Provenance []string `json:"provenance,omitempty"`
	}
	var entries []entry
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var r policy.AuditRecord
		if json.Unmarshal([]byte(line), &r) != nil {
			continue
		}
		if !*all && len(r.Provenance) == 0 {
			continue
		}
		if *session != "" && r.Peer != *session && r.PeerKey != *session {
			continue
		}
		if *toolGlob != "" {
			if ok, _ := path.Match(*toolGlob, r.Tool); !ok {
				continue
			}
		}
		entries = append(entries, entry{Seq: r.Seq, Time: r.Time, Peer: r.Peer, Tool: r.Tool, Decision: r.Decision, Provenance: r.Provenance})
	}

	receipt := map[string]any{
		"source": *in,
		"chain": map[string]any{
			"ok":        chain.OK,
			"count":     chain.Count,
			"break_seq": chain.BreakSeq,
		},
		"filter":  map[string]any{"peer": *session, "tool": *toolGlob, "all": *all},
		"records": entries,
		"note":    "verify with: meshmcp audit verify " + *in + " (optionally --checkpoints --pubkey); the records above are committed in that chain",
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(receipt)
}

// auditExport converts an audit JSONL ledger to CSV on stdout for BI tools /
// spreadsheets. It reads the same records the verifier does; it does not verify
// the chain (use `audit verify` for that).
func auditExport(args []string) error {
	fs := flag.NewFlagSet("audit export", flag.ContinueOnError)
	in := fs.String("in", "", "audit log (JSONL) to export (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *in == "" {
		return fmt.Errorf("usage: meshmcp audit export --in <file> > out.csv")
	}
	f, err := os.Open(*in)
	if err != nil {
		return err
	}
	defer f.Close()

	w := csv.NewWriter(os.Stdout)
	defer w.Flush()
	_ = w.Write([]string{"seq", "time", "backend", "peer", "peer_key", "method", "tool", "decision", "reason", "rule"})

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var r policy.AuditRecord
		if json.Unmarshal([]byte(line), &r) != nil {
			continue
		}
		_ = w.Write([]string{
			strconv.Itoa(r.Seq), r.Time, r.Backend, r.Peer, r.PeerKey,
			r.Method, r.Tool, r.Decision, r.Reason, strconv.Itoa(r.Rule),
		})
	}
	return sc.Err()
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
