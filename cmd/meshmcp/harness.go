package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"

	"github.com/xrey167/meshmcp/air/checkpoint"
	"github.com/xrey167/meshmcp/control"
	hn "github.com/xrey167/meshmcp/harness"
	"github.com/xrey167/meshmcp/mcp/orchestrator"
	"github.com/xrey167/meshmcp/policy"
)

// netbirdEnroller adapts control.NetBirdIssuer to harness.Enroller so the
// EnrollMinter can mint real ephemeral mesh worker identities.
type netbirdEnroller struct{ iss *control.NetBirdIssuer }

func (e netbirdEnroller) Enroll(node string) (setupKey, mgmtURL string, err error) {
	resp, err := e.iss.Enroll(control.EnrollRequest{Node: node})
	if err != nil {
		return "", "", err
	}
	return resp.SetupKey, resp.ManagementURL, nil
}

func (e netbirdEnroller) Deregister(node string) error { return e.iss.Deregister(node) }

// cmdHarness is the `meshmcp harness ...` verb: the identity-native, mesh-governed
// agent orchestration engine. Subverbs mirror the source harnesses' surface but
// every action is governed by the agent firewall and written to the hash-chained
// audit log.
func cmdHarness(args []string) error {
	if len(args) == 0 {
		harnessUsage()
		return fmt.Errorf("harness: a subcommand is required")
	}
	switch args[0] {
	case "serve":
		return harnessServe(args[1:])
	case "run":
		return harnessRun(args[1:])
	case "plan":
		return harnessPlan(args[1:])
	case "interview":
		return harnessInterview(args[1:])
	case "verify":
		return harnessVerify(args[1:])
	case "roles":
		return harnessRoles(args[1:])
	case "status":
		return harnessStatus(args[1:])
	case "-h", "--help", "help":
		harnessUsage()
		return nil
	default:
		harnessUsage()
		return fmt.Errorf("harness: unknown subcommand %q", args[0])
	}
}

func harnessUsage() {
	fmt.Fprint(os.Stderr, `usage: meshmcp harness <subcommand> [flags]

  serve       start the orchestrator MCP dark service (stdio; --listen for mesh)
  run "<goal>"        run a goal through the merged pipeline
  plan "<goal>"       produce a plan + review (plan-only)
  interview "<goal>"  Socratic requirement clarification only
  verify "<goal>"     review_work + ultragoal check over a scope
  roles               list the canonical role registry and capabilities
  status <run_id>     load a run's state from the air state store (needs --state-dir)

common flags:
  --audit <file>       hash-chained audit log (default harness-audit.jsonl)
  --cosign-store <dir> co-sign approvals directory
  --state-dir <dir>    air/checkpoint continuity directory (run state survives restarts)
  --mode <mode>        quick|team|autopilot|ralph|ultrawork|synthesize|interview-only|plan-only
  --category <cat>     deep|ultrabrain|quick|writing|visual-engineering|artistry|...
`)
}

// harnessDeps builds the shared engine dependencies from common flags.
type harnessDeps struct {
	auditPath string
	cosignDir string
	stateDir  string
	mode      string
	category  string
	minter    string
	nbAPIURL  string
	nbToken   string
	nbGroups  string
	workerCmd string
}

func (d *harnessDeps) bind(fs *flag.FlagSet) {
	fs.StringVar(&d.auditPath, "audit", "harness-audit.jsonl", "hash-chained audit log file")
	fs.StringVar(&d.cosignDir, "cosign-store", "", "co-sign approvals directory")
	fs.StringVar(&d.stateDir, "state-dir", "", "air/checkpoint continuity directory")
	fs.StringVar(&d.mode, "mode", "", "run mode")
	fs.StringVar(&d.category, "category", "", "work category")
	fs.StringVar(&d.minter, "minter", "mem", "worker identity minter: mem | netbird (netbird mints real ephemeral mesh peers)")
	fs.StringVar(&d.nbAPIURL, "nb-api-url", "", "NetBird API URL (default https://api.netbird.io; used by --minter netbird)")
	fs.StringVar(&d.nbToken, "nb-token", "", "NetBird PAT (or $NB_API_TOKEN; used by --minter netbird)")
	fs.StringVar(&d.nbGroups, "nb-groups", "workers", "NetBird auto-groups for minted workers (comma-separated)")
	fs.StringVar(&d.workerCmd, "worker-cmd", "", "run execute-stage jobs as this external worker process (argv; empty = in-process workers)")
}

// buildMinter selects the worker identity minter. mem (default) generates
// in-process keys; netbird mints real ephemeral mesh peers via the control
// plane's issuer, retiring them on completion. Every enrollment is audited on al.
func (d *harnessDeps) buildMinter(al *policy.AuditLog) (hn.Minter, error) {
	switch d.minter {
	case "", "mem":
		return nil, nil // nil → NewEngine uses the in-process MemMinter
	case "netbird":
		token := d.nbToken
		if token == "" {
			token = os.Getenv("NB_API_TOKEN")
		}
		if token == "" {
			return nil, fmt.Errorf("--minter netbird requires a NetBird PAT via --nb-token or $NB_API_TOKEN")
		}
		apiURL := d.nbAPIURL
		if apiURL == "" {
			apiURL = "https://api.netbird.io"
		}
		var groups []string
		for _, g := range strings.Split(d.nbGroups, ",") {
			if g = strings.TrimSpace(g); g != "" {
				groups = append(groups, g)
			}
		}
		iss := &control.NetBirdIssuer{APIURL: apiURL, Token: token, Groups: groups, Audit: al}
		return hn.NewEnrollMinter(netbirdEnroller{iss: iss}), nil
	default:
		return nil, fmt.Errorf("unknown --minter %q (want mem|netbird)", d.minter)
	}
}

// engine builds a governed hn.Engine from the deps. The caller must call
// the returned closer to seal the audit log.
func (d *harnessDeps) engine() (*hn.Engine, func(), error) {
	af, err := os.OpenFile(d.auditPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, nil, fmt.Errorf("open audit log: %w", err)
	}
	al := policy.NewAuditLog(af, func() string { return time.Now().UTC().Format(time.RFC3339) })
	// Continue the chain across restarts.
	if seq, hash, err := seedAuditFromExisting(d.auditPath); err == nil && seq > 0 {
		al.SeedFrom(seq, hash)
	}

	var cosign policy.CosignStore
	if d.cosignDir != "" {
		cosign = &policy.FileCosign{Dir: d.cosignDir}
	}

	var cont hn.Continuity
	if d.stateDir != "" {
		store, err := checkpoint.New(d.stateDir, al)
		if err != nil {
			af.Close()
			return nil, nil, fmt.Errorf("state store: %w", err)
		}
		cont = hn.NewAirContinuity(store)
	}

	minter, err := d.buildMinter(al)
	if err != nil {
		af.Close()
		return nil, nil, err
	}

	opts := hn.EngineOpts{
		Audit:      al,
		Cosign:     cosign,
		Continuity: cont,
		Minter:     minter,
	}
	if d.workerCmd != "" {
		opts.Spawner = &hn.ExecSpawner{}
		opts.WorkerCommand = strings.Fields(d.workerCmd)
	}
	eng := hn.NewEngine(opts)
	closer := func() { al.Flush(); af.Close() }
	return eng, closer, nil
}

func harnessServe(args []string) error {
	fs := flag.NewFlagSet("harness serve", flag.ExitOnError)
	var d harnessDeps
	d.bind(fs)
	mo := meshFlags(fs)
	listen := fs.String("listen", "", "mesh listen address (e.g. :9200); empty serves over stdio")
	if err := fs.Parse(args); err != nil {
		return err
	}
	eng, closer, err := d.engine()
	if err != nil {
		return err
	}
	defer closer()

	if *listen == "" {
		srv := orchestrator.New(eng, "meshmcp-orchestrator", version)
		fmt.Fprintln(os.Stderr, "harness: serving orchestrator over stdio (dark MCP service)")
		return srv.Serve(context.Background(), os.Stdin, os.Stdout)
	}

	// Mesh listen: join the mesh and accept governed MCP connections. Each
	// connection gets its own orchestrator.Server over the SHARED engine (an
	// mcp.Server holds one active session at a time). Zero public ports — the
	// listener lives on the WireGuard mesh only, the spec's dark service.
	client, err := startMesh(mo, os.Stderr)
	if err != nil {
		return err
	}
	defer stopMesh(client)
	ln, err := client.ListenTCP(*listen)
	if err != nil {
		return fmt.Errorf("harness serve: listen on mesh %s: %w", *listen, err)
	}
	fmt.Fprintf(os.Stderr, "harness: orchestrator dark service on mesh %s\n", *listen)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, shutdownSignals...)
	go func() { <-sig; ln.Close() }()

	for {
		conn, err := ln.Accept()
		if err != nil {
			fmt.Fprintln(os.Stderr, "harness: orchestrator shutting down")
			return nil
		}
		go func() {
			defer conn.Close()
			srv := orchestrator.New(eng, "meshmcp-orchestrator", version)
			_ = srv.Serve(context.Background(), conn, conn)
		}()
	}
}

func harnessRun(args []string) error {
	fs := flag.NewFlagSet("harness run", flag.ExitOnError)
	var d harnessDeps
	d.bind(fs)
	budgetStr := fs.String("budget", "", "budget overrides, e.g. tokens=1000000,rounds=8,fanout=4")
	scope := fs.String("scope", "", "path scope for the run")
	if err := fs.Parse(args); err != nil {
		return err
	}
	goal := strings.TrimSpace(strings.Join(fs.Args(), " "))
	if goal == "" {
		return fmt.Errorf("harness run: a goal is required")
	}
	eng, closer, err := d.engine()
	if err != nil {
		return err
	}
	defer closer()

	req := hn.RunRequest{
		Goal:     goal,
		Mode:     hn.Mode(d.mode),
		Category: hn.Category(d.category),
		Budget:   parseBudget(*budgetStr),
	}
	if *scope != "" {
		req.Scope = hn.RepoScope{Paths: strings.Split(*scope, ",")}
	}
	st, err := eng.Run(context.Background(), req)
	if err != nil {
		return fmt.Errorf("harness run: %w", err)
	}
	printState(st)
	return nil
}

func harnessPlan(args []string) error {
	fs := flag.NewFlagSet("harness plan", flag.ExitOnError)
	var d harnessDeps
	d.bind(fs)
	style := fs.String("style", "team", "plan style: prometheus|ralplan|team")
	if err := fs.Parse(args); err != nil {
		return err
	}
	goal := strings.TrimSpace(strings.Join(fs.Args(), " "))
	if goal == "" {
		return fmt.Errorf("harness plan: a goal is required")
	}
	eng, closer, err := d.engine()
	if err != nil {
		return err
	}
	defer closer()
	plan, verdict, err := eng.MakePlan(context.Background(), goal, *style)
	if err != nil {
		return err
	}
	fmt.Printf("plan %s (%s) — %d step(s), verdict: %s\n", plan.ID, plan.Style, len(plan.Steps), verdict.Verdict)
	for _, s := range plan.Steps {
		fmt.Printf("  [%s] %s\n", s.ID, s.Intent)
	}
	if len(verdict.Gaps) > 0 {
		fmt.Printf("gaps: %s\n", strings.Join(verdict.Gaps, "; "))
	}
	return nil
}

func harnessInterview(args []string) error {
	fs := flag.NewFlagSet("harness interview", flag.ExitOnError)
	var d harnessDeps
	d.bind(fs)
	rounds := fs.Int("rounds", 3, "question rounds")
	if err := fs.Parse(args); err != nil {
		return err
	}
	goal := strings.TrimSpace(strings.Join(fs.Args(), " "))
	if goal == "" {
		return fmt.Errorf("harness interview: a goal is required")
	}
	eng, closer, err := d.engine()
	if err != nil {
		return err
	}
	defer closer()
	req, err := eng.DoInterview(context.Background(), goal, *rounds)
	if err != nil {
		return err
	}
	fmt.Printf("requirements %s\n", req.ID)
	for _, qa := range req.QA {
		fmt.Printf("  Q: %s\n  A: %s\n", qa.Q, qa.A)
	}
	for _, a := range req.Assumptions {
		fmt.Printf("  assume: %s\n", a)
	}
	return nil
}

func harnessVerify(args []string) error {
	fs := flag.NewFlagSet("harness verify", flag.ExitOnError)
	var d harnessDeps
	d.bind(fs)
	reviewers := fs.Int("reviewers", 5, "reviewer count")
	if err := fs.Parse(args); err != nil {
		return err
	}
	goal := strings.TrimSpace(strings.Join(fs.Args(), " "))
	if goal == "" {
		return fmt.Errorf("harness verify: a goal/scope is required")
	}
	eng, closer, err := d.engine()
	if err != nil {
		return err
	}
	defer closer()
	findings, summary, err := eng.DoReviewWork(context.Background(), goal, *reviewers)
	if err != nil {
		return err
	}
	met, gaps, err := eng.DoUltragoal(context.Background(), goal, []string{"review completed"})
	if err != nil {
		return err
	}
	fmt.Printf("%s\nfindings: %d\ngoal met: %v\n", summary, len(findings), met)
	if len(gaps) > 0 {
		fmt.Printf("residual gaps: %s\n", strings.Join(gaps, "; "))
	}
	return nil
}

func harnessRoles(args []string) error {
	for _, s := range hn.Roles() {
		ro := ""
		if s.ReadOnly {
			ro = " [read-only]"
		}
		fmt.Printf("%-14s%s\n  %s\n  allow: %s\n", s.Role, ro, s.Summary, strings.Join(s.AllowTools, ", "))
		if len(s.CosignTools) > 0 {
			fmt.Printf("  cosign: %s\n", strings.Join(s.CosignTools, ", "))
		}
	}
	return nil
}

func harnessStatus(args []string) error {
	fs := flag.NewFlagSet("harness status", flag.ExitOnError)
	var d harnessDeps
	d.bind(fs)
	key := fs.String("key", "", "creator key that owns the run")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if d.stateDir == "" {
		return fmt.Errorf("harness status: --state-dir is required to load persisted run state")
	}
	if fs.NArg() == 0 {
		return fmt.Errorf("harness status: a run id is required")
	}
	al := policy.NewAuditLog(nil, nil)
	store, err := checkpoint.New(d.stateDir, al)
	if err != nil {
		return err
	}
	cont := hn.NewAirContinuity(store)
	st, ok, err := cont.Load(hn.RunID(fs.Arg(0)), *key)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("no such run %q", fs.Arg(0))
	}
	printState(st)
	return nil
}

// --- helpers ---

func printState(st hn.RunState) {
	fmt.Printf("run %s\n  goal:     %s\n  mode:     %s\n  category: %s\n  status:   %s\n  stage:    %s\n  goal met: %v\n",
		st.ID, st.Goal, st.Mode, st.Category, st.Status, st.Stage, st.GoalMet)
	if st.Rounds > 0 {
		fmt.Printf("  rounds:   %d (stop: %s)\n", st.Rounds, st.StopReason)
	}
	if st.Plan != nil {
		fmt.Printf("  plan:     %d step(s)\n", len(st.Plan.Steps))
	}
	if len(st.Findings) > 0 {
		fmt.Printf("  findings: %d\n", len(st.Findings))
	}
	if len(st.Workers) > 0 {
		fmt.Printf("  workers:  %d retired\n", len(st.Workers))
	}
	if st.Error != "" {
		fmt.Printf("  error:    %s\n", st.Error)
	}
}

func parseBudget(s string) hn.Budget {
	b := hn.Budget{}
	for _, kv := range strings.Split(s, ",") {
		kv = strings.TrimSpace(kv)
		if kv == "" {
			continue
		}
		parts := strings.SplitN(kv, "=", 2)
		if len(parts) != 2 {
			continue
		}
		n, _ := strconv.Atoi(parts[1])
		switch parts[0] {
		case "tokens":
			b.Tokens = n
		case "rounds":
			b.LoopRounds = n
		case "fanout", "fan_out":
			b.FanOut = n
		}
	}
	return b
}
