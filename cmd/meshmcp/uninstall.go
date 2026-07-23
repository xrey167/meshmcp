package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// meshmcp uninstall (alias: air remove) tears down a gateway's LOCAL footprint:
// the WireGuard identity (so a deleted binary does not leave a live enrolled key
// on disk), the tamper-evident audit ledger(s), the paired/cosign/session state,
// and — with --purge — the whole per-user data dir. It is deliberately a DRY RUN
// by default: without --yes it only prints what it WOULD remove, because deleting
// the mesh identity is irreversible (a fresh identity means a new mesh IP and
// re-pairing everywhere).
//
// It removes only local state. Deregistering the peer from the NetBird account is
// a management-plane action that only the control node (holder of the PAT) can
// perform — control.NetBirdIssuer.Deregister — and is pointed at here.

// statePath is one removable piece of local state.
type statePath struct {
	path  string
	label string
}

// gatherStatePaths collects the removable local state a gateway config declares,
// deduplicated and made absolute. cfgPath (the config file itself) is included
// unless keepConfig is set.
func gatherStatePaths(cfg *Config, cfgPath string, keepConfig bool) []statePath {
	var out []statePath
	seen := map[string]bool{}
	add := func(p, label string) {
		if p == "" {
			return
		}
		abs, err := filepath.Abs(p)
		if err != nil {
			abs = p
		}
		if seen[abs] {
			return
		}
		seen[abs] = true
		out = append(out, statePath{path: abs, label: label})
	}

	add(cfg.Mesh.ConfigPath, "mesh identity (WireGuard key + NetBird state)")
	add(cfg.AuditLog, "gateway audit ledger")
	add(cfg.Registry, "service registry")
	if cfg.Control != nil {
		add(cfg.Control.PairStore, "paired-peer store")
	}
	for _, b := range cfg.Backends {
		add(b.AuditLog, "backend "+b.Name+" audit ledger")
		add(b.CosignStore, "backend "+b.Name+" cosign/approval store")
		add(b.SessionStore, "backend "+b.Name+" session store")
		if b.Capabilities != nil {
			add(b.Capabilities.RevocationStore, "backend "+b.Name+" capability revocation store")
		}
	}
	if !keepConfig {
		add(cfgPath, "gateway config")
	}

	sort.Slice(out, func(i, j int) bool { return out[i].path < out[j].path })
	return out
}

// cmdUninstall implements `meshmcp uninstall` / `air remove`.
func cmdUninstall(args []string) error {
	fs := flag.NewFlagSet("uninstall", flag.ExitOnError)
	cfgPath := fs.String("config", defaultConfigPath(), "gateway config whose local state to remove")
	yes := fs.Bool("yes", false, "actually delete — without this the command is a dry run")
	purge := fs.Bool("purge", false, "also remove the entire per-user data dir (profile + scaffolded state)")
	keepConfig := fs.Bool("keep-config", false, "leave the config file itself in place")
	if err := fs.Parse(args); err != nil {
		return err
	}

	var targets []statePath
	if cfg, err := loadConfig(*cfgPath); err == nil {
		targets = gatherStatePaths(cfg, *cfgPath, *keepConfig)
	} else if !*purge {
		// No config to enumerate and not purging the data dir: nothing to do but
		// say why, rather than silently succeeding.
		return fmt.Errorf("uninstall: could not read %s (%v) — pass --config <file>, or --purge to remove the data dir", *cfgPath, err)
	} else {
		fmt.Fprintln(os.Stderr, dim("no gateway config at "+*cfgPath+" — removing the data dir only"))
	}

	// --purge removes the whole data dir (Phase B's canonical home), which also
	// covers the profile and any scaffolded state rooted there.
	if *purge {
		if dir, err := dataDirPath(); err == nil && dir != "" {
			targets = append(targets, statePath{path: dir, label: "per-user data dir (profile + scaffolded state)"})
		}
	}

	// Keep only state that actually exists, so the plan reflects reality.
	existing := targets[:0]
	for _, t := range targets {
		if _, err := os.Stat(t.path); err == nil {
			existing = append(existing, t)
		}
	}
	targets = existing

	if len(targets) == 0 {
		fmt.Println(okLine("nothing to remove — no local state found"))
		return nil
	}

	// Always print the plan first.
	fmt.Println(bold("meshmcp uninstall — local state to remove:"))
	for _, t := range targets {
		fmt.Printf("  %s  %s\n", cyan(t.path), dim("· "+t.label))
	}
	fmt.Println()

	if !*yes {
		fmt.Println(amber("dry run") + " — nothing was deleted. Re-run with " + bold("--yes") + " to remove the above.")
		fmt.Println(dim("  removing the mesh identity is irreversible: a fresh identity means a new mesh IP and re-pairing."))
		fmt.Println(dim("  to also deregister this peer from the NetBird account, the control node runs its Deregister path (only it holds the PAT)."))
		return nil
	}

	var failures int
	for _, t := range targets {
		if err := os.RemoveAll(t.path); err != nil {
			failures++
			fmt.Fprintln(os.Stderr, amber("!")+" could not remove "+t.path+": "+err.Error())
			continue
		}
		fmt.Println(green("✓") + " removed " + t.path)
	}
	if failures > 0 {
		return fmt.Errorf("uninstall: %d item(s) could not be removed", failures)
	}
	fmt.Println()
	fmt.Println(okLine("gateway removed from this machine"))
	fmt.Println(dim("  this peer may still appear in the NetBird account until the control node deregisters it."))
	return nil
}
