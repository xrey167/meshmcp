package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/netbirdio/netbird/client/embed"
	"gopkg.in/yaml.v3"

	"github.com/xrey167/meshmcp/air/checkpoint"
	"github.com/xrey167/meshmcp/air/egress"
	"github.com/xrey167/meshmcp/air/graph"
	"github.com/xrey167/meshmcp/mcpclient"
	"github.com/xrey167/meshmcp/policy"
)

// cmdAirGraph is the umbrella for the air-agent-graph pillar: run a bounded,
// governed, cyclic agent loop; resume a parked or crashed run as its creator; or
// inspect a run's state and audit tail.
//
//	meshmcp air graph run     [mesh flags] [--policy p] [--audit f] --state-dir d [--budget N] [--max-iters N] [--dry-run] [--json] <graph.yaml>
//	meshmcp air graph resume  [mesh flags] [--policy p] [--audit f] --state-dir d --run-id ID [--json]
//	meshmcp air graph inspect --state-dir d --run-id ID [--audit f] [--verify] [--json]
func cmdAirGraph(args []string) error {
	if len(args) == 0 {
		return airGraphUsage()
	}
	switch args[0] {
	case "run":
		return cmdAirGraphRun(args[1:])
	case "resume":
		return cmdAirGraphResume(args[1:])
	case "inspect":
		return cmdAirGraphInspect(args[1:])
	case "-h", "--help", "help":
		return airGraphUsage()
	default:
		return fmt.Errorf("meshmcp air graph: unknown subcommand %q (want run | resume | inspect)", args[0])
	}
}

func airGraphUsage() error {
	fmt.Fprintln(os.Stderr, bold("meshmcp air graph")+dim(" — a bounded, governed, cyclic agent loop"))
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "  "+bold("air graph run")+"     [flags] --state-dir <d> <graph.yaml>   "+dim("drive a graph as a governed, checkpointed loop"))
	fmt.Fprintln(os.Stderr, "  "+bold("air graph resume")+"  [flags] --state-dir <d> --run-id <id>   "+dim("resume a parked/crashed run (creator only)"))
	fmt.Fprintln(os.Stderr, "  "+bold("air graph inspect")+" --state-dir <d> --run-id <id> [--verify] "+dim("replay a run's state/step and audit tail"))
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, dim("Every node's tool call is firewalled + budget-counted through the egress gateway,"))
	fmt.Fprintln(os.Stderr, dim("every step is checkpointed, and the loop is bounded (max-iter · budget · wall-clock · goal)."))
	fmt.Fprintln(os.Stderr, dim("A parked cosign node releases only via a signed, single-use, argument-bound approval (--approvals + --approval-key)."))
	return nil
}

// cmdAirGraphRun parses, validates, and drives a graph definition.
func cmdAirGraphRun(args []string) error {
	fs := flag.NewFlagSet("air graph run", flag.ExitOnError)
	o := meshFlags(fs)
	policyPath := fs.String("policy", "", "policy file governing node tool calls (default: ungoverned allow-all, with a warning)")
	auditPath := fs.String("audit", "", "append the run's hash-chained audit records to this file")
	stateDir := fs.String("state-dir", "", "directory for run checkpoints (required)")
	runID := fs.String("run-id", "", "run id / checkpoint key (default: a fresh time-based id)")
	budget := fs.Int("budget", 500000, "cumulative cost ceiling; the gateway halts the loop when a call would breach it")
	maxIters := fs.Int("max-iters", 0, "override the graph's max_iterations (0 = use the graph's, else the safe default)")
	timeout := fs.Duration("timeout", defaultGraphTimeout, "wall-clock bound for the whole run; on expiry the run checkpoints and stops resumable (zero/negative coerced to the default, never unbounded)")
	approvalsDir := fs.String("approvals", "", "request-bound approval store directory; a parked cosign node is released only by consuming a signed single-use approval from it")
	approvalKey := fs.String("approval-key", "", "Ed25519 key file pinning the approval signer (shared with the approver); required with --approvals")
	dryRun := fs.Bool("dry-run", false, "parse, compile, and print the node/edge plan without joining the mesh or running")
	jsonOut := fs.Bool("json", false, "print a machine-readable run summary")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: meshmcp air graph run [flags] --state-dir <d> <graph.yaml>")
	}
	def, g, err := loadGraphDef(fs.Arg(0), *maxIters)
	if err != nil {
		return err
	}
	if *dryRun {
		return printGraphPlan(def, g, *jsonOut)
	}
	if *stateDir == "" {
		return errNoStateDir
	}

	engine, warn, err := loadGraphEngine(*policyPath)
	if err != nil {
		return err
	}
	if warn != "" {
		fmt.Fprintln(os.Stderr, amber("warning: ")+dim(warn))
	}
	approvals, err := openGraphApprovals(*approvalsDir, *approvalKey)
	if err != nil {
		return err
	}

	o.BlockInbound = true
	client, err := startMesh(o, os.Stderr)
	if err != nil {
		return err
	}
	defer stopMesh(client)

	caller, err := selfCaller(client)
	if err != nil {
		return err
	}
	id := *runID
	if id == "" {
		id = fmt.Sprintf("graph-%d", time.Now().UnixNano())
	}

	audit, closeAudit, err := openGraphAudit(*auditPath)
	if err != nil {
		return err
	}
	defer closeAudit()

	store, err := checkpoint.New(*stateDir, audit)
	if err != nil {
		return fmt.Errorf("air graph run: checkpoint store: %w", err)
	}
	r := &graphRunner{
		def:       def,
		graph:     g,
		gw:        egress.NewGateway(engine, audit, *budget),
		store:     store,
		exec:      &meshExecutor{client: client},
		caller:    caller,
		runID:     id,
		audit:     audit,
		approvals: approvals,
	}
	log.Printf("graph %q run %s: entry=%s max_iters=%d budget=%d timeout=%s", def.Name, id, g.Entry, g.Bounds.MaxIterations, *budget, graphTimeout(*timeout))
	ctx, cancel := context.WithTimeout(context.Background(), graphTimeout(*timeout))
	defer cancel()
	out, err := r.start(ctx)
	if err != nil {
		return err
	}
	return reportRun(id, r, out, *jsonOut)
}

// cmdAirGraphResume continues a parked or crashed run as its creator.
func cmdAirGraphResume(args []string) error {
	fs := flag.NewFlagSet("air graph resume", flag.ExitOnError)
	o := meshFlags(fs)
	policyPath := fs.String("policy", "", "policy file governing node tool calls")
	auditPath := fs.String("audit", "", "append the run's audit records to this file")
	stateDir := fs.String("state-dir", "", "directory holding the run checkpoint (required)")
	runID := fs.String("run-id", "", "run id to resume (required)")
	timeout := fs.Duration("timeout", defaultGraphTimeout, "wall-clock bound for the resumed run (zero/negative coerced to the default, never unbounded)")
	approvalsDir := fs.String("approvals", "", "request-bound approval store directory; a parked cosign node is released only by consuming a signed single-use approval from it")
	approvalKey := fs.String("approval-key", "", "Ed25519 key file pinning the approval signer (shared with the approver); required with --approvals")
	jsonOut := fs.Bool("json", false, "print a machine-readable run summary")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *stateDir == "" {
		return errNoStateDir
	}
	if *runID == "" {
		return errors.New("air graph resume: --run-id is required")
	}
	engine, warn, err := loadGraphEngine(*policyPath)
	if err != nil {
		return err
	}
	if warn != "" {
		fmt.Fprintln(os.Stderr, amber("warning: ")+dim(warn))
	}
	approvals, err := openGraphApprovals(*approvalsDir, *approvalKey)
	if err != nil {
		return err
	}

	o.BlockInbound = true
	client, err := startMesh(o, os.Stderr)
	if err != nil {
		return err
	}
	defer stopMesh(client)

	caller, err := selfCaller(client)
	if err != nil {
		return err
	}
	audit, closeAudit, err := openGraphAudit(*auditPath)
	if err != nil {
		return err
	}
	defer closeAudit()
	store, err := checkpoint.New(*stateDir, audit)
	if err != nil {
		return fmt.Errorf("air graph resume: checkpoint store: %w", err)
	}
	// Rebuild the exact graph from the persisted definition (identity-bound load).
	def, g, budget, err := loadPersistedRun(store, *runID, caller.PeerKey)
	if err != nil {
		return err
	}
	r := &graphRunner{
		def:       def,
		graph:     g,
		gw:        egress.NewGateway(engine, audit, budget),
		store:     store,
		exec:      &meshExecutor{client: client},
		caller:    caller,
		runID:     *runID,
		audit:     audit,
		approvals: approvals,
	}
	ctx, cancel := context.WithTimeout(context.Background(), graphTimeout(*timeout))
	defer cancel()
	out, err := r.resume(ctx)
	if err != nil {
		return err
	}
	return reportRun(*runID, r, out, *jsonOut)
}

// cmdAirGraphInspect replays a run's state/step from its checkpoint and, with
// --verify, checks the audit chain end to end. It joins no mesh and runs nothing.
func cmdAirGraphInspect(args []string) error {
	fs := flag.NewFlagSet("air graph inspect", flag.ExitOnError)
	stateDir := fs.String("state-dir", "", "directory holding the run checkpoint (required)")
	runID := fs.String("run-id", "", "run id to inspect (required)")
	auditPath := fs.String("audit", "", "audit log to summarize / verify")
	verify := fs.Bool("verify", false, "verify the audit chain end to end (policy.VerifyChain)")
	jsonOut := fs.Bool("json", false, "print the run state as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *stateDir == "" {
		return errNoStateDir
	}
	if *runID == "" {
		return errors.New("air graph inspect: --run-id is required")
	}
	return inspectRun(*stateDir, *runID, *auditPath, *verify, *jsonOut)
}

// defaultGraphTimeout is the wall-clock bound applied when none (or a
// non-positive one) is configured — fail-closed: a run can never be configured
// unbounded in time, mirroring graph.DefaultMaxIterations for iterations.
const defaultGraphTimeout = 10 * time.Minute

// graphTimeout coerces a zero/negative configured timeout to the safe default.
func graphTimeout(d time.Duration) time.Duration {
	if d <= 0 {
		return defaultGraphTimeout
	}
	return d
}

// openGraphApprovals opens the request-bound approval store that can release a
// parked cosign node. Fail-closed pairing: --approvals without --approval-key
// is refused outright — with no pinned signer every consume would fail
// verification yet still SPEND the claimed approval file, silently burning
// grants. No dir = nil store = park-only.
func openGraphApprovals(dir, keyPath string) (policy.RequestApprovalStore, error) {
	if dir == "" {
		if keyPath != "" {
			return nil, errors.New("air graph: --approval-key requires --approvals")
		}
		return nil, nil
	}
	if keyPath == "" {
		return nil, errors.New("air graph: --approvals requires --approval-key (the pinned approval signer); refusing a store that would burn approvals it cannot verify")
	}
	signer, err := policy.LoadSigner(keyPath)
	if err != nil {
		return nil, fmt.Errorf("air graph: --approval-key %s: %w", keyPath, err)
	}
	return policy.NewFileApprovalStore(dir, 0, signer), nil
}

// loadGraphDef reads, parses, compiles, and validates a graph definition. A
// positive maxOverride replaces the graph's max_iterations before compilation.
func loadGraphDef(path string, maxOverride int) (*graph.Definition, *graph.Graph, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("air graph: read %s: %w", path, err)
	}
	def, err := graph.Parse(data)
	if err != nil {
		return nil, nil, err
	}
	if maxOverride > 0 {
		def.Bounds.MaxIterations = maxOverride
	}
	g, err := def.Compile()
	if err != nil {
		return nil, nil, err
	}
	return def, g, nil
}

// loadPersistedRun loads a run's checkpoint under the creator's identity and
// rebuilds its definition, compiled graph, and remaining budget. Remaining budget
// is the run's original budget minus the cost already mirrored into state, so the
// budget bound is honored across a resume.
func loadPersistedRun(store *checkpoint.Store, runID, callerKey string) (*graph.Definition, *graph.Graph, int, error) {
	cp, ok, err := store.Load(runID, callerKey)
	if err != nil {
		return nil, nil, 0, err
	}
	if !ok {
		return nil, nil, 0, fmt.Errorf("air graph: no run %q", runID)
	}
	var pr persistedRun
	if err := json.Unmarshal(cp.State, &pr); err != nil {
		return nil, nil, 0, fmt.Errorf("air graph: decode run state: %w", err)
	}
	def, err := graph.Parse(pr.Definition)
	if err != nil {
		return nil, nil, 0, err
	}
	g, err := def.Compile()
	if err != nil {
		return nil, nil, 0, err
	}
	remaining := pr.Budget - pr.State.Cost
	if remaining < 0 {
		remaining = 0
	}
	return def, g, remaining, nil
}

// loadGraphEngine builds the policy engine that governs node tool calls. With no
// policy file it returns an allow-all engine and a warning string (the run is
// ungoverned) rather than silently denying every call.
func loadGraphEngine(path string) (*policy.Engine, string, error) {
	if path == "" {
		return policy.NewEngine(&policy.Policy{DefaultAllow: true}, time.Now, nil), "no --policy given: this run is UNGOVERNED (allow-all)", nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, "", fmt.Errorf("air graph: read policy %s: %w", path, err)
	}
	var pol policy.Policy
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&pol); err != nil {
		return nil, "", fmt.Errorf("air graph: parse policy %s: %w", path, err)
	}
	if err := pol.Validate(); err != nil {
		return nil, "", fmt.Errorf("air graph: invalid policy %s: %w", path, err)
	}
	return policy.NewEngine(&pol, time.Now, nil), "", nil
}

// openGraphAudit opens (or creates) the run's hash-chained audit file, continuing
// an existing verified chain rather than resetting it. A blank path audits to
// stderr so a governed call is never unrecorded.
func openGraphAudit(path string) (*policy.AuditLog, func(), error) {
	clock := func() string { return time.Now().UTC().Format(time.RFC3339) }
	if path == "" {
		return policy.NewAuditLog(os.Stderr, clock), func() {}, nil
	}
	seq, last, err := seedAuditFromExisting(path)
	if err != nil {
		return nil, nil, fmt.Errorf("air graph: audit log %s: %w", path, err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, nil, fmt.Errorf("air graph: open audit %s: %w", path, err)
	}
	audit := policy.NewAuditLog(f, clock)
	audit.SeedFrom(seq, last)
	return audit, func() { f.Close() }, nil
}

// selfCaller reads this node's mesh identity (FQDN + public key) — the identity
// the gateway attributes every governed call to and that binds the checkpoint so
// only this identity can resume the run.
func selfCaller(client *embed.Client) (egress.Caller, error) {
	st, err := client.Status()
	if err != nil {
		return egress.Caller{}, fmt.Errorf("air graph: read mesh identity: %w", err)
	}
	key := st.LocalPeerState.PubKey
	if key == "" {
		return egress.Caller{}, errors.New("air graph: no local mesh public key; run is not identity-bound")
	}
	return egress.Caller{PeerFQDN: st.LocalPeerState.FQDN, PeerKey: key}, nil
}

// meshExecutor runs a node's tool call as a real MCP call over the mesh. It is the
// production toolExecutor; the Gateway governs whether Do is invoked at all.
type meshExecutor struct{ client *embed.Client }

func (m *meshExecutor) Do(ctx context.Context, backend, tool string, args []byte) ([]byte, error) {
	var uc *mcpclient.Client
	if err := retryConn(ctx, connRetryCap, func() error {
		conn, err := m.client.Dial(ctx, "tcp", backend)
		if err != nil {
			return fmt.Errorf("dial %s: %w", backend, err)
		}
		u := mcpclient.New(conn, nil)
		if _, err := u.Initialize(ctx, "meshmcp-air-graph"); err != nil {
			u.Close()
			return fmt.Errorf("initialize %s: %w", backend, err)
		}
		uc = u
		return nil
	}); err != nil {
		return nil, err
	}
	defer uc.Close()
	var argv any = map[string]any{}
	if len(args) > 0 {
		_ = json.Unmarshal(args, &argv)
	}
	res, err := uc.CallTool(ctx, tool, argv, false)
	if err != nil {
		return nil, fmt.Errorf("call %s: %w", tool, err)
	}
	return res, nil
}
