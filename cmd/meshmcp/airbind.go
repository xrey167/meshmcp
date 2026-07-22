package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Air · Bind — a programmable, governed reaction layer for the mesh.
//
// Rebind (docs.rebind.gg) is a programmable input layer: it intercepts an event
// and runs a script in response. Air Bind is the same idea turned onto the mesh —
// it watches the one universal event source meshmcp already produces, the
// hash-chained audit ledger, and fires a declared reaction when a record matches.
// The Air difference is the whole point: every trigger is an already-governed,
// already-audited mesh action, and every reaction that *acts* (rather than merely
// notifies) is itself a governed mesh action, deny-by-default — an executing
// binding requires explicit --allow-exec, so a bindings file can never silently
// run a command.
//
//	meshmcp air bind bindings.yaml                 # watch; print reactions only
//	meshmcp air bind --allow-exec bindings.yaml    # also run `do.run` reactions

// bindConfig is a bindings file: an ordered list of reaction rules.
type bindConfig struct {
	Bindings []bindingRule `yaml:"bindings"`
}

// bindingRule fires its action when an audit record matches its trigger.
type bindingRule struct {
	Name string     `yaml:"name"`
	On   bindMatch  `yaml:"on"`
	Do   bindAction `yaml:"do"`
}

// bindMatch is the trigger: each field is a glob against the audit record's same
// field; an empty field matches anything. An all-empty match fires on every
// record (a universal reaction, e.g. a notifier). Globs use `*` (any run of
// characters, INCLUDING '/') and `?` (one character) — audit fields are opaque
// identifiers, not filesystem paths, so `*` deliberately spans the '/' in values
// like "notifications/air/steer" or "tools/call".
type bindMatch struct {
	Decision string `yaml:"decision"` // allow | deny | cosign
	Backend  string `yaml:"backend"`
	Method   string `yaml:"method"`
	Tool     string `yaml:"tool"`
	Peer     string `yaml:"peer"`
	Reason   string `yaml:"reason"` // the "why" — cost-limit, DLP, "not in allow list", …
}

// bindAction is what fires when the trigger matches. Print emits a templated
// line (always safe). Run executes `meshmcp <args...>` with each arg templated —
// a governed reaction (it re-enters the firewall), gated behind --allow-exec.
type bindAction struct {
	Print string   `yaml:"print"`
	Run   []string `yaml:"run"`
}

// matchField reports whether a glob pattern matches value. An empty pattern
// matches anything. It delegates to globMatch, whose `*` spans '/' — unlike
// path.Match, whose `*` stops at a separator and would make a natural trigger
// like method:"*" or method:"notifications/*" silently match nothing.
func matchField(pattern, value string) bool {
	if pattern == "" {
		return true
	}
	return globMatch(pattern, value)
}

// globMatch reports whether pattern matches s, where `*` matches any run of
// characters (including none, and including '/') and `?` matches exactly one.
// A classic linear two-pointer wildcard match with backtracking on the last `*`.
func globMatch(pattern, s string) bool {
	px, sx := 0, 0
	star, starSx := -1, 0
	for sx < len(s) {
		switch {
		case px < len(pattern) && (pattern[px] == '?' || pattern[px] == s[sx]):
			px++
			sx++
		case px < len(pattern) && pattern[px] == '*':
			star, starSx = px, sx // remember the `*` and where we tried to start it
			px++
		case star >= 0: // no direct match, but a prior `*` can absorb one more char
			px = star + 1
			starSx++
			sx = starSx
		default:
			return false
		}
	}
	for px < len(pattern) && pattern[px] == '*' {
		px++
	}
	return px == len(pattern)
}

// matchRecord reports whether every set field of m matches r.
func matchRecord(m bindMatch, r streamRecord) bool {
	return matchField(m.Decision, r.Decision) &&
		matchField(m.Backend, r.Backend) &&
		matchField(m.Method, r.Method) &&
		matchField(m.Tool, r.Tool) &&
		matchField(m.Peer, r.Peer) &&
		matchField(m.Reason, r.Reason)
}

// expandTemplate replaces {field} placeholders with the record's values, so a
// reaction can name what fired it: {peer} {tool} {method} {backend} {decision}
// {reason} {time}. Unknown placeholders are left untouched.
func expandTemplate(s string, r streamRecord) string {
	rep := strings.NewReplacer(
		"{peer}", r.Peer,
		"{tool}", r.Tool,
		"{method}", r.Method,
		"{backend}", r.Backend,
		"{decision}", r.Decision,
		"{reason}", r.Reason,
		"{time}", r.Time,
	)
	return rep.Replace(s)
}

// validateBindings checks a loaded config: every rule needs a name and exactly
// one action kind, and a run rule is refused unless exec is allowed — so loading
// fails closed before a single record is read.
func validateBindings(cfg bindConfig, allowExec bool) error {
	if len(cfg.Bindings) == 0 {
		return fmt.Errorf("no bindings defined")
	}
	seen := map[string]bool{}
	for i, b := range cfg.Bindings {
		if b.Name == "" {
			return fmt.Errorf("binding %d: name is required", i)
		}
		if seen[b.Name] {
			return fmt.Errorf("binding %q: duplicate name", b.Name)
		}
		seen[b.Name] = true
		hasPrint, hasRun := b.Do.Print != "", len(b.Do.Run) > 0
		if !hasPrint && !hasRun {
			return fmt.Errorf("binding %q: do needs a print or run action", b.Name)
		}
		if hasPrint && hasRun {
			return fmt.Errorf("binding %q: do has both print and run — use one", b.Name)
		}
		if hasRun && !allowExec {
			return fmt.Errorf("binding %q has a run action; re-run with --allow-exec to permit executing reactions", b.Name)
		}
	}
	return nil
}

// buildRunArgs expands each of a run reaction's argv entries against the record,
// so a governed child is invoked with the trigger's values interpolated.
func buildRunArgs(b bindingRule, r streamRecord) []string {
	args := make([]string, len(b.Do.Run))
	for i, a := range b.Do.Run {
		args[i] = expandTemplate(a, r)
	}
	return args
}

// formatPrintLine renders a print reaction's row. The expanded template is
// passed through sanitizeCell because it interpolates attacker-influenced audit
// fields ({peer}, {tool}, {reason}, …): a hostile method name or dropped-file
// reason must not smuggle ANSI/OSC escapes into the operator's terminal — the
// same defence the stream renderer applies (formatAuditLine → sanitizeCell).
func formatPrintLine(b bindingRule, r streamRecord) string {
	return dim(streamTime(r.Time)) + "  " + cyan("⇒ "+b.Name) + "  " + sanitizeCell(expandTemplate(b.Do.Print, r))
}

// fireBinding runs one matched rule's action. A print reaction writes a sanitized
// templated line to w; a run reaction spawns `meshmcp <expanded args...>` as a
// child (the same governed re-entry as `air launch`). run errors are reported,
// never fatal — one failing reaction must not stop the watch.
func fireBinding(w io.Writer, b bindingRule, r streamRecord) {
	switch {
	case b.Do.Print != "":
		fmt.Fprintln(w, formatPrintLine(b, r))
	case len(b.Do.Run) > 0:
		args := buildRunArgs(b, r)
		exe, err := os.Executable()
		if err != nil {
			fmt.Fprintln(os.Stderr, red("bind "+b.Name+": ")+err.Error())
			return
		}
		fmt.Fprintln(w, dim(streamTime(r.Time))+"  "+amber("⇒ "+b.Name)+"  "+dim("run: meshmcp "+strings.Join(args, " ")))
		cmd := exec.Command(exe, args...)
		cmd.Env = agentChildEnv()
		cmd.Stdout = os.Stderr
		cmd.Stderr = os.Stderr
		if err := cmd.Start(); err != nil {
			fmt.Fprintln(os.Stderr, red("bind "+b.Name+": ")+err.Error())
			return
		}
		// Reap the child so a long-lived watcher firing many run reactions does
		// not leave a growing trail of defunct (zombie) processes; fire-and-forget
		// semantics are unchanged (we never block the watch on the child).
		go func() { _ = cmd.Wait() }()
	}
}

// cmdAirBind watches an audit ledger and fires declared reactions when records
// match — the mesh-native answer to a programmable input layer.
func cmdAirBind(args []string) error {
	fs := flag.NewFlagSet("air bind", flag.ExitOnError)
	fromStart := fs.Bool("from-start", false, "match existing records first, then follow (default: only new)")
	allowExec := fs.Bool("allow-exec", false, "permit bindings whose action runs a command (default: print reactions only)")
	auditPath := fs.String("audit", "", "audit JSONL ledger to watch (required)")
	interval := fs.Duration("interval", 500*time.Millisecond, "poll interval for new records")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: meshmcp air bind [flags] <bindings.yaml> --audit <audit.jsonl>")
	}
	cfg, err := loadBindConfig(fs.Arg(0))
	if err != nil {
		return fmt.Errorf("air bind: %w", err)
	}
	if err := validateBindings(cfg, *allowExec); err != nil {
		return fmt.Errorf("air bind: %w", err)
	}
	if *auditPath == "" {
		return fmt.Errorf("air bind: --audit <audit.jsonl> is required (the ledger to watch)")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	mode := "notify only"
	if *allowExec {
		mode = "exec enabled"
	}
	fmt.Fprintln(os.Stderr, dim("binding ")+bold(fmt.Sprint(len(cfg.Bindings)))+
		dim(" rule(s) to ")+bold(*auditPath)+dim(" · "+mode+" · Ctrl-C to stop"))

	err = followAudit(ctx, *auditPath, *fromStart, *interval, func(line []byte) {
		r, ok := parseStreamRecord(line)
		if !ok {
			return
		}
		for _, b := range cfg.Bindings {
			if matchRecord(b.On, r) {
				fireBinding(os.Stdout, b, r)
			}
		}
	})
	if err != nil {
		return fmt.Errorf("air bind: %w", err)
	}
	return nil
}

// loadBindConfig reads and parses a bindings YAML file.
func loadBindConfig(path string) (bindConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return bindConfig{}, fmt.Errorf("read bindings: %w", err)
	}
	var cfg bindConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return bindConfig{}, fmt.Errorf("parse bindings %s: %w", path, err)
	}
	return cfg, nil
}
