package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/xrey167/meshmcp/air"
	"github.com/xrey167/meshmcp/control"
	"github.com/xrey167/meshmcp/policy"
)

// meshmcp revoke-device is the "my laptop was stolen" flow: ONE audited command
// that severs every trust relationship a peer identity holds with this gateway,
// instead of an operator hunting across four stores under pressure. It runs on
// the gateway host against the local stores the config names:
//
//   - pairing: the peer stops being RECOGNIZED (paired store revoke)
//   - grants: every written (identity, verb, scope) capability is removed
//   - capabilities: the identity is subject-revoked in each backend's
//     revocation store, killing every outstanding signed token it holds
//   - operators / control.allow: the identity is dropped from the config's
//     operator surface (surgical YAML edit, config re-validated before write)
//   - management plane: with a NetBird PAT (control node only), the peer is
//     deregistered from the account
//
// Every completed step is appended to the gateway's tamper-evident audit
// ledger. The command never fails silently-partial: it prints a checklist of
// what was done, what was skipped (not configured / not reachable from this
// host), and what still needs doing elsewhere, and exits non-zero if any
// ATTEMPTED step failed.

// revokeStep is one checklist row of the revocation pass.
type revokeStep struct {
	name   string
	status string // "done" | "skip" | "fail"
	detail string
}

// cmdRevokeDevice implements `meshmcp revoke-device` / `air revoke`.
func cmdRevokeDevice(args []string) error {
	fs := flag.NewFlagSet("revoke-device", flag.ExitOnError)
	cfgPath := fs.String("config", defaultConfigPath(), "gateway config naming the stores to revoke from")
	var grantStores stringList
	fs.Var(&grantStores, "grant-store", "additional grant store file to purge this identity from (repeatable; e.g. air kg serve's --grant-store)")
	device := fs.String("device", "", "NetBird peer name to deregister from the management account (needs --netbird-token / $NB_API_TOKEN)")
	nbToken := fs.String("netbird-token", "", "NetBird PAT for management-side deregistration ($NB_API_TOKEN)")
	nbAPI := fs.String("netbird-api", "https://api.netbird.io", "NetBird management API base URL")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: meshmcp revoke-device [flags] <peer-wireguard-pubkey>\n  one audited command that revokes the identity everywhere this gateway can reach — pairing, grants, capabilities, operator surface, and (with --netbird-token) the management account")
	}
	pubKey := strings.TrimSpace(fs.Arg(0))
	if pubKey == "" {
		return fmt.Errorf("revoke-device: the peer's WireGuard public key is required")
	}

	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		return fmt.Errorf("revoke-device: %w", err)
	}

	// The audit trail for the revocation itself: append to the gateway's shared
	// ledger so the lost-device response is part of the same tamper-evident
	// chain the rest of the gateway writes.
	var audit *policy.AuditLog
	if cfg.AuditLog != "" {
		seq, lastHash, serr := seedAuditFromExisting(cfg.AuditLog)
		if serr != nil {
			return fmt.Errorf("revoke-device: audit ledger: %w", serr)
		}
		f, err := os.OpenFile(cfg.AuditLog, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			return fmt.Errorf("revoke-device: open audit ledger: %w", err)
		}
		defer f.Close()
		audit = policy.NewAuditLog(f, func() string { return time.Now().UTC().Format(time.RFC3339) }).
			WithSync(auditFsyncEnabled(cfg.AuditFsync))
		if seq > 0 {
			audit.SeedFrom(seq, lastHash)
		}
	}
	record := func(action, outcome, reason string) {
		_ = audit.Append(policy.AuditRecord{
			Backend:  "gateway",
			Peer:     pubKey,
			PeerKey:  pubKey,
			Method:   "revoke-device/" + action,
			Decision: outcome,
			Reason:   reason,
			Rule:     -1,
		})
	}

	var steps []revokeStep
	done := func(name, detail string) { steps = append(steps, revokeStep{name, "done", detail}) }
	skip := func(name, detail string) { steps = append(steps, revokeStep{name, "skip", detail}) }
	fail := func(name string, err error) { steps = append(steps, revokeStep{name, "fail", err.Error()}) }

	// 1) Pairing: stop recognizing the identity.
	if cfg.Control != nil && cfg.Control.PairStore != "" {
		ps, err := air.OpenPairedStore(cfg.Control.PairStore)
		if err != nil {
			fail("pairing", err)
		} else if removed, err := ps.Revoke(pubKey); err != nil {
			fail("pairing", err)
		} else if removed {
			done("pairing", "recognition revoked in "+cfg.Control.PairStore)
			record("pairing", "allow", "recognition revoked")
		} else {
			// Also clear any still-pending request so the identity cannot sit in
			// the queue waiting for a mistaken approval.
			if dropped, _ := ps.Deny(pubKey); dropped {
				done("pairing", "pending request cleared in "+cfg.Control.PairStore)
				record("pairing", "allow", "pending pair request cleared")
			} else {
				skip("pairing", "identity was not paired or pending")
			}
		}
	} else {
		skip("pairing", "no pair store configured")
	}

	// 2) Grants: purge every written capability for the identity from each
	// named grant store. Grant stores are per-service (flag-configured), so the
	// operator passes their paths; an unknown store cannot be discovered here.
	for _, gpath := range grantStores {
		gs, err := air.OpenGrantStore(gpath)
		if err != nil {
			fail("grants "+gpath, err)
			continue
		}
		removed := 0
		var firstErr error
		for _, g := range gs.Grants() {
			if g.Identity != pubKey {
				continue
			}
			if _, err := gs.Remove(g.Identity, g.Verb, g.Scope); err != nil {
				firstErr = err
				break
			}
			removed++
		}
		// Drop pending opportunities too — a revoked device must not keep an
		// open ask an operator could mistakenly approve later.
		for _, p := range gs.Pending() {
			if p.Identity == pubKey {
				_, _ = gs.DropOpportunity(p.Identity, p.Verb, p.Scope)
			}
		}
		if firstErr != nil {
			fail("grants "+gpath, firstErr)
		} else if removed > 0 {
			done("grants "+gpath, fmt.Sprintf("%d grant(s) removed", removed))
			record("grants", "allow", fmt.Sprintf("%d grant(s) removed from %s", removed, gpath))
		} else {
			skip("grants "+gpath, "no grants held by this identity")
		}
	}
	if len(grantStores) == 0 {
		skip("grants", "no --grant-store given (pass each service's grant store to purge it)")
	}

	// 3) Capabilities: subject-revoke the identity in every backend's
	// revocation store — the kill-switch for outstanding signed tokens.
	capStores := 0
	for _, b := range cfg.Backends {
		if b.Capabilities == nil || b.Capabilities.RevocationStore == "" {
			continue
		}
		capStores++
		rev, err := policy.NewFileRevocation(b.Capabilities.RevocationStore)
		if err != nil {
			fail("capabilities "+b.Name, err)
			continue
		}
		if err := rev.RevokeSubject(pubKey); err != nil {
			fail("capabilities "+b.Name, err)
			continue
		}
		done("capabilities "+b.Name, "identity subject-revoked in "+b.Capabilities.RevocationStore)
		record("capabilities", "allow", "subject revoked for backend "+b.Name)
	}
	if capStores == 0 {
		skip("capabilities", "no backend has a capability revocation store configured")
	}

	// 4) Operator surface: drop the identity from operators and control.allow
	// so a stolen operator device cannot keep steering sessions or approving
	// pairings. Surgical YAML edit; the mutated config is re-validated before it
	// replaces the file, and a config that would become invalid (e.g. an empty
	// control allow surface) is reported instead of written.
	if removedFrom, err := dropIdentityFromConfig(*cfgPath, pubKey); err != nil {
		fail("operator surface", err)
	} else if len(removedFrom) > 0 {
		done("operator surface", "removed from "+strings.Join(removedFrom, " + "))
		record("operators", "allow", "removed from "+strings.Join(removedFrom, " + "))
	} else {
		skip("operator surface", "identity is not an operator and not in control.allow")
	}

	// 5) Management plane: deregister the peer from the NetBird account. Only
	// the control node holds the PAT, so elsewhere this is a named next step.
	token := *nbToken
	if token == "" {
		token = os.Getenv("NB_API_TOKEN")
	}
	if token != "" && *device != "" {
		iss := &control.NetBirdIssuer{APIURL: *nbAPI, Token: token, Audit: audit}
		if err := iss.Deregister(*device); err != nil {
			fail("netbird deregistration", err)
		} else {
			done("netbird deregistration", "peer "+*device+" removed from the account")
		}
	} else {
		skip("netbird deregistration", "needs --device and --netbird-token/$NB_API_TOKEN — run on the control node")
	}

	audit.Flush()

	// The checklist: what happened, what was skipped, what failed.
	fmt.Println(bold("revoke-device " + pubKey))
	failures := 0
	for _, s := range steps {
		switch s.status {
		case "done":
			fmt.Println("  " + green("✓") + " " + s.name + "  " + dim(s.detail))
		case "skip":
			fmt.Println("  " + dim("–") + " " + s.name + "  " + dim(s.detail))
		case "fail":
			failures++
			fmt.Println("  " + amber("✗") + " " + s.name + "  " + s.detail)
		}
	}
	fmt.Println()
	if failures > 0 {
		return fmt.Errorf("revoke-device: %d step(s) failed — the identity may retain access on those surfaces; re-run after fixing them", failures)
	}
	fmt.Println(okLine("identity revoked on every reachable surface"))
	fmt.Println(dim("  skipped rows above name the surfaces this host could not reach — finish them where noted."))
	return nil
}

// dropIdentityFromConfig removes pubKey from the config's operators list and
// from control.allow (its `pubkey:<key>` form), editing the YAML surgically so
// the rest of the file is preserved. It returns which sections were changed. A
// mutation that would leave an enabled control endpoint with NO allowed
// identity at all is refused — revoking one device must not lock every
// operator out (the config would also fail validation and refuse to load).
func dropIdentityFromConfig(path, pubKey string) ([]string, error) {
	doc, root, err := loadConfigDoc(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var changed []string

	// operators: drop any entry whose pubkey matches.
	if seq := mapValue(root, "operators"); seq != nil && seq.Kind == yaml.SequenceNode {
		kept := seq.Content[:0]
		removed := false
		for _, op := range seq.Content {
			if mapScalar(op, "pubkey") == pubKey {
				removed = true
				continue
			}
			kept = append(kept, op)
		}
		if removed {
			seq.Content = kept
			changed = append(changed, "operators")
		}
	}

	// control.allow: drop the exact `pubkey:<key>` pattern.
	if ctrl := mapValue(root, "control"); ctrl != nil && ctrl.Kind == yaml.MappingNode {
		if allow := mapValue(ctrl, "allow"); allow != nil && allow.Kind == yaml.SequenceNode {
			kept := allow.Content[:0]
			removed := false
			for _, v := range allow.Content {
				if v.Kind == yaml.ScalarNode && v.Value == "pubkey:"+pubKey {
					removed = true
					continue
				}
				kept = append(kept, v)
			}
			if removed {
				allow.Content = kept
				changed = append(changed, "control.allow")
			}
		}
	}

	if len(changed) == 0 {
		return nil, nil
	}
	if err := marshalValidateWrite(path, doc); err != nil {
		return nil, err
	}
	return changed, nil
}
