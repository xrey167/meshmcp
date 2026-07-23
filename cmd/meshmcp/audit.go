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
	"sort"
	"strconv"
	"strings"

	"github.com/xrey167/meshmcp/policy"
)

// cmdAudit implements "meshmcp audit <subcommand>".
func cmdAudit(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: meshmcp audit <verify|keygen|export|receipt|attest|anchor> ...")
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
	case "anchor":
		return auditAnchor(args[1:])
	default:
		return fmt.Errorf("meshmcp audit: unknown subcommand %q (want: verify, keygen, export, receipt, attest, anchor)", args[0])
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
// With --anchors it additionally cross-checks the checkpoints against an
// external witness's anchor file, catching the one attack signatures alone
// cannot: a key-holding insider who rolls the log and checkpoints back
// together. A broken chain — or a witness disagreement — returns an error
// (non-zero exit) for CI / compliance gates.
func auditVerify(args []string) error {
	// The audit log is the first argument; flags follow it.
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return fmt.Errorf("usage: meshmcp audit verify <audit-log> [--checkpoints <f> --pubkey <hex> --anchors <f>]")
	}
	logPath := args[0]
	fs := flag.NewFlagSet("audit verify", flag.ContinueOnError)
	checkpoints := fs.String("checkpoints", "", "signed checkpoint file (enables signature verification)")
	pubkey := fs.String("pubkey", "", "expected signer public key (hex) to pin against")
	anchors := fs.String("anchors", "", "external witness anchor file to cross-check the checkpoints against")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}

	if *anchors != "" && *checkpoints == "" {
		return fmt.Errorf("--anchors requires --checkpoints (anchoring witnesses signed checkpoints)")
	}
	if *checkpoints != "" {
		return auditVerifySigned(logPath, *checkpoints, *pubkey, *anchors)
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

func auditVerifySigned(logPath, cpPath, pubkey, anchorPath string) error {
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

	// Anchor cross-check: only when the chain itself is OK (an invalid chain is
	// already the loudest verdict) and an anchor file was given. It ADDS
	// evidence to the result; the four-state Status is never remapped.
	if res.OK && anchorPath != "" {
		ares, aerr := verifyAnchorsAgainst(cpPath, anchorPath)
		if aerr != nil {
			return fmt.Errorf("verify anchors: %w", aerr)
		}
		res.AnchorStatus = ares.Status
		res.AnchorReason = ares.Reason
		res.AnchoredCheckpoints = ares.Matched
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
		switch res.AnchorStatus {
		case policy.AnchorStatusAnchored:
			fmt.Printf("    ANCHORED: all %d checkpoint(s) match the external witness\n", res.Checkpoints)
		case policy.AnchorStatusPartial:
			fmt.Fprintf(os.Stderr, "ANCHOR PARTIAL: %s — the unwitnessed checkpoint(s) could still be rolled back undetected\n", res.AnchorReason)
		case policy.AnchorStatusMismatch:
			fmt.Fprintf(os.Stderr, "ANCHOR MISMATCH: %s\n", res.AnchorReason)
			fmt.Fprintf(os.Stderr, "                the checkpoints file disagrees with the external witness — the log and\n")
			fmt.Fprintf(os.Stderr, "                checkpoints may have been rolled back or rewritten together (even by a\n")
			fmt.Fprintf(os.Stderr, "                holder of the signing key)\n")
			// Non-zero exit EVEN when Status == sealed: an internally consistent
			// chain that the witness contradicts is the insider case anchoring
			// exists to catch.
			return fmt.Errorf("audit log %s contradicts the external witness (anchor status %s)", logPath, res.AnchorStatus)
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

// loadCheckpointMap parses a checkpoints file into ordinal -> checkpoint for
// the anchor cross-check.
func loadCheckpointMap(cpPath string) (map[int]policy.Checkpoint, error) {
	f, err := os.Open(cpPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := map[int]policy.Checkpoint{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var cp policy.Checkpoint
		if err := json.Unmarshal([]byte(line), &cp); err != nil {
			return nil, fmt.Errorf("checkpoints %s: line is not a checkpoint: %w", cpPath, err)
		}
		out[cp.Seq] = cp
	}
	return out, sc.Err()
}

// verifyAnchorsAgainst runs the witness cross-check of an anchor file against
// a checkpoints file.
func verifyAnchorsAgainst(cpPath, anchorPath string) (policy.AnchorVerifyResult, error) {
	cpBySeq, err := loadCheckpointMap(cpPath)
	if err != nil {
		return policy.AnchorVerifyResult{}, err
	}
	af, err := os.Open(anchorPath)
	if err != nil {
		return policy.AnchorVerifyResult{}, err
	}
	defer af.Close()
	return policy.VerifyAnchors(af, cpBySeq)
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
	anchorsPath := fs.String("anchors", "", "external witness anchor file to cross-check the checkpoints against")
	policyPath := fs.String("policy", "", "effective policy file to include by hash (optional)")
	out := fs.String("out", "", "write the attestation JSON here (default stdout)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *auditPath == "" {
		return fmt.Errorf("usage: meshmcp audit attest --audit <file> [--checkpoints <f> --pubkey <hex> --anchors <f>] [--policy <f>] [--out <f>]")
	}
	if *anchorsPath != "" && *cpPath == "" {
		return fmt.Errorf("--anchors requires --checkpoints (anchoring witnesses signed checkpoints)")
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
		// Anchor cross-check evidence (orthogonal to the four-state status): the
		// verdict says whether an external witness agrees with the checkpoints.
		if *anchorsPath != "" && res.OK {
			ares, aerr := verifyAnchorsAgainst(*cpPath, *anchorsPath)
			if aerr != nil {
				return fmt.Errorf("verify anchors: %w", aerr)
			}
			verdict["anchor_status"] = ares.Status
			if ares.Reason != "" {
				verdict["anchor_reason"] = ares.Reason
			}
			verdict["anchored_checkpoints"] = ares.Matched
			anchorArt, err := artifact(*anchorsPath)
			if err != nil {
				return err
			}
			verdict["anchors_artifact"] = anchorArt
		}
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
		"kind":       "github.com/xrey167/meshmcp/attestation",
		"version":    1,
		"audit":      auditArt,
		"verdict":    verdict,
		"verify_cmd": "meshmcp audit verify " + *auditPath + verifyHint(*cpPath, *pubkey, *anchorsPath),
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

func verifyHint(cp, pub, anchors string) string {
	if cp == "" {
		return ""
	}
	s := " --checkpoints " + cp
	if pub != "" {
		s += " --pubkey " + pub
	}
	if anchors != "" {
		s += " --anchors " + anchors
	}
	return s
}

// auditAnchor replays every checkpoint from a checkpoints file to a witness —
// the recovery path after a witness outage. To a peer witness (--url) it is
// idempotent: the receiver dedups by (signer, ordinal, hash), so re-posting
// already-witnessed checkpoints is a no-op and only the gap is filled. To a
// local anchor file (--out) it appends records for checkpoints the file does
// not already witness, continuing the self-linked chain.
func auditAnchor(args []string) error {
	fs := flag.NewFlagSet("audit anchor", flag.ContinueOnError)
	cpPath := fs.String("checkpoints", "", "signed checkpoint file to replay (required)")
	outPath := fs.String("out", "", "append anchor records to this local anchor file")
	witnessURL := fs.String("url", "", "POST each checkpoint to this peer witness endpoint (e.g. http://control:9600/v1/anchor)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *cpPath == "" || (*outPath == "") == (*witnessURL == "") {
		return fmt.Errorf("usage: meshmcp audit anchor --checkpoints <f> (--out <anchor-file> | --url <witness-url>)")
	}
	cpBySeq, err := loadCheckpointMap(*cpPath)
	if err != nil {
		return err
	}
	seqs := make([]int, 0, len(cpBySeq))
	for s := range cpBySeq {
		seqs = append(seqs, s)
	}
	sort.Ints(seqs)

	if *witnessURL != "" {
		// Post (not Anchor): the replay wants a synchronous per-checkpoint
		// verdict from the witness, not background delivery.
		pa := policy.NewPeerAnchor(*witnessURL)
		for _, s := range seqs {
			if err := pa.Post(cpBySeq[s]); err != nil {
				return fmt.Errorf("checkpoint %d: %w", s, err)
			}
		}
		fmt.Printf("anchored %d checkpoint(s) to %s\n", len(seqs), *witnessURL)
		return nil
	}

	// Local file: skip checkpoints the file already witnesses (same hash);
	// refuse on a conflicting hash — that is fork evidence, not a replay.
	// Records attributed to a DIFFERENT signer belong to another gateway's
	// chain in a shared witness file and are not conflicts (same skip rule as
	// VerifyAnchors); unattributed records (signer "") count as this file's
	// own. Two existing same-chain records for one ordinal with different
	// hashes mean the file already holds fork evidence — refuse to extend it.
	signer := ""
	for _, cp := range cpBySeq {
		signer = cp.PubKey
		break
	}
	already := map[int]string{}
	prev := ""
	if f, oerr := os.Open(*outPath); oerr == nil {
		recs, lastHash, rerr := policy.ReadAnchorRecords(f)
		f.Close()
		if rerr != nil {
			return fmt.Errorf("anchor file %s: %w", *outPath, rerr)
		}
		prev = lastHash
		for _, r := range recs {
			if r.Signer != "" && signer != "" && r.Signer != signer {
				continue // another gateway's record in a shared witness file
			}
			if h, dup := already[r.Seq]; dup && h != r.Checkpoint {
				return fmt.Errorf("anchor file %s already holds two conflicting records for checkpoint %d (fork evidence; refusing to replay into it)", *outPath, r.Seq)
			}
			already[r.Seq] = r.Checkpoint
		}
	} else if !os.IsNotExist(oerr) {
		return oerr
	}
	f, err := os.OpenFile(*outPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	fa := policy.NewFileAnchor(f, prev)
	appended := 0
	for _, s := range seqs {
		cp := cpBySeq[s]
		if h, ok := already[s]; ok {
			if h != cp.Hash() {
				return fmt.Errorf("checkpoint %d conflicts with the anchor file's existing record (fork evidence; refusing to overwrite a witness)", s)
			}
			continue
		}
		if err := fa.Anchor(cp); err != nil {
			return fmt.Errorf("checkpoint %d: %w", s, err)
		}
		appended++
	}
	fmt.Printf("anchored %d checkpoint(s) to %s (%d already witnessed)\n", appended, *outPath, len(seqs)-appended)
	return nil
}
