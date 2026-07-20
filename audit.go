package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
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
	case "attest":
		return auditAttest(args[1:])
	default:
		return fmt.Errorf("meshmcp audit: unknown subcommand %q (want: verify, keygen, export, receipt, attest)", args[0])
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
		fmt.Printf("OK  %d records, %d signed checkpoint(s), %d records covered  [%s]\n", res.Records, res.Checkpoints, res.CoveredRecords, res.Status)
		fmt.Printf("    signer %s\n", res.SignerPub)
		switch res.Status {
		case policy.StatusSealed:
			fmt.Printf("    SEALED & TRUSTED: gateway-signed tamper-evident decision log — every record is covered\n")
			fmt.Printf("    by a checkpoint signed with the pinned key. A holder of the file cannot edit a\n")
			fmt.Printf("    covered record without the signing key. (Anchor a checkpoint externally to also\n")
			fmt.Printf("    defend against a key-holding insider who rolls the log and checkpoints back together.)\n")
		case policy.StatusUnsealed:
			fmt.Printf("    VALID but UNSEALED: %d record(s) after the last checkpoint are not yet sealed.\n", res.Records-res.CoveredRecords)
			fmt.Printf("    Flush a checkpoint and re-verify to seal the tail before treating the log as complete.\n")
		case policy.StatusUntrustedKey:
			fmt.Printf("    UNTRUSTED KEY: the chain is internally valid but no expected --pubkey was pinned,\n")
			fmt.Printf("    so the signer is unverified. Re-run with --pubkey <hex> to establish trust.\n")
		}
		if res.Status != policy.StatusSealed {
			return fmt.Errorf("audit log %s verified but is not fully sealed and trusted (status %s)", logPath, res.Status)
		}
		return nil
	}
	fmt.Fprintf(os.Stderr, "FAILED  %d records, %d checkpoint(s) read\n", res.Records, res.Checkpoints)
	fmt.Fprintf(os.Stderr, "        %s\n", res.Reason)
	return fmt.Errorf("audit log %s failed signed verification", logPath)
}

// auditAttest builds a compliance & attestation pack (F32): a single
// self-describing JSON bundle that references and hashes the constituent
// evidence — the audit log, its signed checkpoints, the effective policy — and
// records the verification verdict (signed Merkle when checkpoints+pubkey are
// given, else the hash chain). Because every artifact is hashed and the chain
// head is included, the bundle is independently verifiable with
// `meshmcp audit verify` and the public key alone — "prove what the fleet did,
// to an auditor, with math."
func auditAttest(args []string) error {
	fs := flag.NewFlagSet("audit attest", flag.ContinueOnError)
	auditPath := fs.String("audit", "", "audit log (JSONL) (required)")
	cpPath := fs.String("checkpoints", "", "signed checkpoint file (enables signed verification)")
	pubkey := fs.String("pubkey", "", "expected signer public key (hex) to pin against")
	policyPath := fs.String("policy", "", "effective policy file to include by hash (optional)")
	out := fs.String("out", "", "write the attestation JSON here (default stdout)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *auditPath == "" {
		return fmt.Errorf("usage: meshmcp audit attest --audit <file> [--checkpoints <f> --pubkey <hex>] [--policy <f>] [--out <f>]")
	}

	artifact := func(path string) (map[string]any, error) {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(b)
		return map[string]any{"path": path, "sha256": hex.EncodeToString(sum[:]), "bytes": len(b)}, nil
	}

	auditArt, err := artifact(*auditPath)
	if err != nil {
		return err
	}

	// Verify: signed Merkle when checkpoints+pubkey are present, else hash chain.
	verdict := map[string]any{}
	if *cpPath != "" {
		lf, err := os.Open(*auditPath)
		if err != nil {
			return err
		}
		defer lf.Close()
		cf, err := os.Open(*cpPath)
		if err != nil {
			return err
		}
		defer cf.Close()
		res, verr := policy.VerifySigned(lf, cf, *pubkey)
		if verr != nil {
			return fmt.Errorf("verify signed: %w", verr)
		}
		verdict = map[string]any{
			"mode": "signed-merkle", "ok": res.OK, "records": res.Records,
			"checkpoints": res.Checkpoints, "covered_records": res.CoveredRecords,
			"signer_pubkey": res.SignerPub, "reason": res.Reason,
			"sealed": res.Sealed, "trusted": res.Trusted, "status": res.Status,
		}
		cpArt, err := artifact(*cpPath)
		if err != nil {
			return err
		}
		verdict["checkpoints_artifact"] = cpArt
	} else {
		data, err := os.ReadFile(*auditPath)
		if err != nil {
			return err
		}
		res, _ := policy.VerifyChain(bytes.NewReader(data))
		verdict = map[string]any{
			"mode": "hash-chain", "ok": res.OK, "records": res.Count,
			"head": res.LastHash, "break_seq": res.BreakSeq,
		}
	}

	att := map[string]any{
		"kind":       "meshmcp/attestation",
		"version":    1,
		"audit":      auditArt,
		"verdict":    verdict,
		"verify_cmd": "meshmcp audit verify " + *auditPath + verifyHint(*cpPath, *pubkey),
		"note":       "each artifact is hashed; re-verify independently with the command above and match the sha256 values",
	}
	if *policyPath != "" {
		polArt, err := artifact(*policyPath)
		if err != nil {
			return err
		}
		att["policy"] = polArt
	}

	b, _ := json.MarshalIndent(att, "", "  ")
	b = append(b, '\n')
	if *out == "" {
		_, err := os.Stdout.Write(b)
		return err
	}
	if err := os.WriteFile(*out, b, 0o644); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "wrote attestation to %s\n", *out)
	return nil
}

func verifyHint(cp, pub string) string {
	if cp == "" {
		return ""
	}
	s := " --checkpoints " + cp
	if pub != "" {
		s += " --pubkey " + pub
	}
	return s
}
