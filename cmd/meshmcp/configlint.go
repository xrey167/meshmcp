package main

import (
	"flag"
	"fmt"
	"path"
	"strings"

	"github.com/xrey167/meshmcp/insight"
)

// configLint implements "meshmcp config lint" (S49): suspicious-but-VALID
// configuration. loadConfig already rejects structurally invalid configs;
// lint flags things that parse fine but weaken the security posture — an
// allow-everything rule, co-sign that can never be approved, a secret granted
// by glob, an unguarded egress tool. Warnings never fail the run unless
// --strict is set, so it drops into CI next to "config validate".
func configLint(args []string) error {
	fs := flag.NewFlagSet("config lint", flag.ContinueOnError)
	cfgPath := fs.String("config", "meshmcp.yaml", "config file to lint")
	strict := fs.Bool("strict", false, "exit non-zero when any warning is found")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		return fmt.Errorf("invalid: %w", err)
	}
	warns := lintConfig(cfg)
	for _, w := range warns {
		fmt.Printf("WARN  %s\n", w)
	}
	if len(warns) == 0 {
		fmt.Printf("OK  %s: no lint warnings\n", *cfgPath)
		return nil
	}
	fmt.Printf("%s: %d warning(s)\n", *cfgPath, len(warns))
	if *strict {
		return fmt.Errorf("config lint: %d warning(s) with --strict", len(warns))
	}
	return nil
}

// lintConfig runs every lint check over a loaded (already-valid) config.
func lintConfig(cfg *Config) []string {
	var warns []string
	warn := func(format string, a ...any) { warns = append(warns, fmt.Sprintf(format, a...)) }

	for _, b := range cfg.Backends {
		auditFile := b.AuditLog != "" || cfg.AuditLog != ""
		if b.Policy == nil {
			continue
		}
		p := b.Policy

		if p.DefaultAllow {
			warn("backend %q: default_allow: true — any tool not matched by a rule is allowed; prefer deny-by-default with explicit allow rules", b.Name)
		}

		cosignRules := 0
		for i, r := range p.Rules {
			if r.RequireCosign {
				cosignRules++
			}
			if !r.Allow || len(r.Methods) > 0 {
				continue
			}
			everyTool := matchesEveryPattern(r.Tools)
			everyPeer := matchesEveryPattern(r.Peers)
			// require_cosign exempts both wildcard checks: a hold-everything-
			// for-approval rule is a deliberate posture stricter than
			// deny-by-default, not an open door.
			switch {
			case everyTool && everyPeer && !r.RequireCosign:
				warn("backend %q rule #%d: allows every peer every tool — an allow-all rule defeats the policy", b.Name, i+1)
			case everyTool && !r.RequireCosign:
				warn("backend %q rule #%d: allow rule with a bare wildcard tool match (tools: %v) — scope it to the tools actually needed", b.Name, i+1, r.Tools)
			}
			// Egress-looking tools without a rate cap: an agent gone wrong (or
			// prompt-injected) can exfiltrate at full speed.
			if r.Rate == nil {
				for _, t := range r.Tools {
					if insight.LooksEgress(strings.TrimSuffix(t, "*")) {
						warn("backend %q rule #%d: egress-looking tool %q allowed with no rate limit — add rate: {max, per} to bound exfiltration speed", b.Name, i+1, t)
						break
					}
				}
			}
		}

		// Shadowed rules: an earlier, broader rule matches everything a later
		// rule matches, so the later rule can never fire (first match wins).
		for i, ri := range p.Rules {
			if ri.When != nil {
				continue // time-scoped rules don't always apply, so they don't shadow
			}
			for j := i + 1; j < len(p.Rules); j++ {
				rj := p.Rules[j]
				if (len(ri.Methods) > 0) != (len(rj.Methods) > 0) {
					continue // tools rules and methods rules are separate lanes
				}
				if patternsSubsume(ri.Peers, rj.Peers) && patternsSubsume(ri.Tools, rj.Tools) && patternsSubsume(ri.Methods, rj.Methods) {
					warn("backend %q rule #%d is shadowed by broader rule #%d and can never fire (first match wins)", b.Name, j+1, i+1)
				}
			}
		}

		if cosignRules > 0 {
			if b.CosignStore == "" {
				warn("backend %q: %d require_cosign rule(s) but no cosign_store — held calls can never be approved", b.Name, cosignRules)
			} else if b.ApprovalSigningKey == "" {
				warn("backend %q: require_cosign uses ambient (peer, tool) grants — set approval_signing_key for request-bound, single-use approvals", b.Name)
			}
			if !auditFile {
				warn("backend %q: require_cosign rules but audit goes to stderr only — set audit_log so approvals leave a verifiable record", b.Name)
			}
		}
		if b.Capabilities != nil && !auditFile {
			warn("backend %q: capability-gated backend without an audit_log file — grant use leaves no verifiable record", b.Name)
		}

		if b.Secrets != nil {
			for gi, g := range b.Secrets.Grants {
				for _, peer := range g.Peers {
					if peer == "*" || (strings.ContainsAny(peer, "*?[") && !strings.HasPrefix(peer, "pubkey:")) {
						warn("backend %q secret grant #%d: peer pattern %q is a glob — a credential grant should name exact identities (pubkey:<key>)", b.Name, gi+1, peer)
						break
					}
				}
			}
		}
	}
	return warns
}

// matchesEveryPattern reports whether a pattern list matches everything: empty
// (policy semantics: no restriction) or containing a bare "*".
func matchesEveryPattern(patterns []string) bool {
	if len(patterns) == 0 {
		return true
	}
	for _, p := range patterns {
		if p == "*" {
			return true
		}
	}
	return false
}

// patternsSubsume reports whether every pattern in narrow is covered by some
// pattern in broad (conservative: only certainly-covered counts, so a literal
// under a glob, an equal pattern, or anything under "*"/empty).
func patternsSubsume(broad, narrow []string) bool {
	if matchesEveryPattern(broad) {
		return true
	}
	if len(narrow) == 0 {
		return false // narrow matches everything, broad does not
	}
	for _, n := range narrow {
		if !patternCovered(broad, n) {
			return false
		}
	}
	return true
}

func patternCovered(broad []string, n string) bool {
	nLiteral := !strings.ContainsAny(n, "*?[")
	for _, b := range broad {
		if b == n {
			return true
		}
		if nLiteral {
			if ok, _ := path.Match(b, n); ok {
				return true
			}
			if k, isKey := strings.CutPrefix(n, "pubkey:"); isKey && b == "pubkey:"+k {
				return true
			}
		}
	}
	return false
}
