package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/xrey167/meshmcp/air"
	"github.com/xrey167/meshmcp/policy"
)

// Air · Osint — defensive self-recon of your OWN mesh's attack surface.
//
// Where whoami/map/catalog/change each answer from ONE caller's seat, osint
// inverts the view: it reads the trusted gateway config the operator alone
// holds and computes, across ALL configured identities, a reachability matrix
// plus a risk audit — "turn on the light in your own house". The pure analyzer
// lives in air/exposure.go; this is the thin CLI that loads the local config,
// projects it into the flat exposure model, renders the report, and optionally
// snapshots/diffs it (air change style) or cross-checks a live catalog against
// the static projection.
//
// Self-scope is a HARD rule: osint audits only a config you hold. It takes no
// remote target — a positional argument or a URL as --config is refused — and
// --live only ever dials the operator's OWN control endpoint (derived from the
// local mesh identity + control.port), aborting if the probed gateway's
// identity is not the operator's own.
func cmdAirOsint(args []string) error {
	fs := flag.NewFlagSet("air osint", flag.ExitOnError)
	o := meshFlags(fs) // used only in --live mode
	configPath := fs.String("config", "", "REQUIRED. Local gateway config to audit (a URL or remote target is refused)")
	identity := fs.String("identity", "", "report reachability for ONE identity only (\"pubkey:<key>\" or an FQDN); omit for the full matrix")
	minSeverity := fs.String("min-severity", "low", "only show findings >= this level (critical|high|medium|low)")
	snapshot := fs.String("snapshot", "", "diff this run against a saved report; the first run saves a baseline")
	update := fs.Bool("update", false, "after diffing, roll the snapshot forward to the current report")
	asJSON := fs.Bool("json", false, "print the report as JSON instead of the rendered screen")
	out := fs.String("out", "", "write the report JSON to this file")
	failOn := fs.String("fail-on", "", "exit non-zero if any finding >= this level (for CI)")
	auditLog := fs.String("audit-log", "", "append the recon event to this SEPARATE osint ledger (never the gateway's own audit_log)")
	live := fs.Bool("live", false, "cross-check the static projection against YOUR OWN live control catalog (needs control.port)")
	sign := fs.Bool("sign", false, "DEFERRED in v1: emit a signed attestation bundle")
	if err := fs.Parse(args); err != nil {
		return err
	}

	// Deferred features fail loudly rather than silently no-op.
	if *sign {
		return errors.New("air osint: --sign (signed attestation) is deferred in v1 — the report snapshot and the separate audit ledger are the verifiable artifacts for now")
	}

	// Self-scope: no remote target may be named. osint audits a local config.
	if fs.NArg() != 0 {
		return fmt.Errorf("air osint audits a local config, not a remote target (got %q); pass --config <path>, never an address", fs.Arg(0))
	}
	if *configPath == "" {
		return errors.New("air osint: --config <path> is required (the local gateway config to audit)")
	}
	if isRemoteConfigTarget(*configPath) {
		return fmt.Errorf("air osint audits a LOCAL config, not a remote target: %q is refused", *configPath)
	}

	minLevel, err := parseSeverityLevel(*minSeverity)
	if err != nil {
		return fmt.Errorf("air osint: --min-severity: %w", err)
	}
	var failLevel int
	if *failOn != "" {
		failLevel, err = parseSeverityLevel(*failOn)
		if err != nil {
			return fmt.Errorf("air osint: --fail-on: %w", err)
		}
	}

	cfg, err := loadConfig(*configPath)
	if err != nil {
		return fmt.Errorf("air osint: %w", err)
	}

	// Guard the ledger BEFORE any work: an osint run must never append to the
	// gateway's own audit chain (concurrent append corrupts tamper-evidence).
	if *auditLog != "" {
		if err := ensureSeparateLedger(*auditLog, cfg); err != nil {
			return fmt.Errorf("air osint: %w", err)
		}
	}

	mesh := projectExposure(cfg)
	report := air.BuildReport(mesh, nowRFC3339)

	// --live: cross-check the static projection against the operator's OWN live
	// catalog. It is self-only and derives the target from the local identity.
	if *live {
		peer, err := osintLiveCrossCheck(o, cfg, mesh)
		if err != nil {
			return fmt.Errorf("air osint: %w", err)
		}
		report.Gateway = peer // the verified live identity of the operator's gateway
		mesh.Gateway = peer
	}

	// Optional single-identity focus.
	if *identity != "" {
		report.Reach = []air.Reach{air.ReachabilityFor(mesh, *identity)}
	}

	// Output: JSON to a file, JSON to stdout, or the rendered Privacy Report.
	switch {
	case *out != "":
		if err := writeReportFile(*out, report); err != nil {
			return fmt.Errorf("air osint: %w", err)
		}
		fmt.Fprintln(os.Stderr, dim("report written to "+*out))
	case *asJSON:
		b, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(b))
	default:
		renderOsintReport(os.Stdout, report, minLevel)
	}

	// Snapshot / diff (air change style).
	if *snapshot != "" {
		if err := osintSnapshot(*snapshot, report, *update, *asJSON); err != nil {
			return fmt.Errorf("air osint: %w", err)
		}
	}

	// Ledger the run into its OWN chain, Decision:allow (a report is not a policy
	// denial). Grade/severity ride the Reason field.
	if *auditLog != "" {
		if err := appendOsintRecord(*auditLog, report); err != nil {
			return fmt.Errorf("air osint: %w", err)
		}
		fmt.Fprintln(os.Stderr, dim("sealed into osint ledger "+*auditLog+" · sha256 "+shortHash(reportHash(report))))
	} else if !*asJSON && *out == "" {
		fmt.Fprintln(os.Stderr, dim("not ledgered — pass --audit-log <separate file> to seal this run"))
	}

	// CI gate: exit non-zero if the surface breaches the threshold.
	if *failOn != "" && scoreBreaches(report.Score, failLevel) {
		return fmt.Errorf("air osint: surface has finding(s) >= %s (grade %s: %d critical, %d high, %d medium, %d low)",
			*failOn, report.Score.Grade, report.Score.Critical, report.Score.High, report.Score.Medium, report.Score.Low)
	}
	return nil
}

// isRemoteConfigTarget reports whether the --config value looks like a remote
// target rather than a local file path: a parseable URL with a scheme, or a
// bare host:port. Either is refused — osint audits only a local config.
func isRemoteConfigTarget(p string) bool {
	if u, err := url.Parse(p); err == nil && u.Scheme != "" && u.Host != "" {
		return true
	}
	// host:port with no path separators (e.g. "100.64.0.2:9443"): treat as remote.
	if !strings.ContainsAny(p, `/\`) {
		if _, _, err := net.SplitHostPort(p); err == nil {
			return true
		}
	}
	return false
}

// projectExposure flattens the trusted Config into the analyzer's dependency-free
// exposure model. The cosign fact for each secret grant is computed HERE (it is
// a policy-layer decision) so the pure analyzer never has to fabricate it.
func projectExposure(cfg *Config) air.MeshExposure {
	gatewayWideAudit := cfg.AuditLog != ""
	m := air.MeshExposure{Gateway: cfg.Mesh.DeviceName}
	if cfg.Control != nil && cfg.Control.Port != 0 {
		m.Control = air.ControlExposure{
			Enabled:       true,
			Allow:         cfg.Control.Allow,
			OnBehalfAllow: cfg.Control.OnBehalfAllow,
		}
	}
	for _, b := range cfg.Backends {
		be := air.BackendExposure{
			Name:         b.Name,
			Transport:    backendTransport(b),
			Allow:        b.Allow,
			Audited:      b.AuditLog != "" || gatewayWideAudit,
			PolicyGated:  b.Policy != nil,
			DefaultAllow: b.Policy == nil || b.Policy.DefaultAllow,
		}
		if b.Remote != nil {
			be.RemoteEndpoint = b.Remote.Endpoint
		}
		if b.Secrets != nil {
			for _, g := range b.Secrets.Grants {
				be.SecretGrants = append(be.SecretGrants, air.SecretGrantExposure{
					Secrets:  g.Secrets,
					Peers:    g.Peers,
					Tools:    g.Tools,
					Cosigned: grantIsCosigned(b.Policy, g.Tools),
				})
			}
		}
		m.Backends = append(m.Backends, be)
	}
	return m
}

// backendTransport reports the projected transport label.
func backendTransport(b *Backend) string {
	switch {
	case b.Remote != nil:
		return "remote"
	case b.HTTP != "":
		return "http"
	default:
		return "stdio"
	}
}

// grantIsCosigned reports whether EVERY policy rule that could authorize a tool
// the grant injects into requires co-sign — the honest, config-derived answer to
// "is this secret pull attended?". A default-allow policy, a missing authorizing
// rule, or any un-cosigned authorizing rule means the credential can be pulled
// unattended, so the grant is not cosigned. The grant's tool globs (empty = any
// tool) are correlated to the policy's allow rules.
func grantIsCosigned(pol *policy.Policy, grantTools []string) bool {
	if pol == nil || pol.DefaultAllow {
		return false // an unmatched call falls through to an un-cosigned allow
	}
	scope := grantTools
	if len(scope) == 0 {
		scope = []string{"*"} // empty grant tools = any tool
	}
	var relevant []policy.Rule
	for _, r := range pol.Rules {
		if !r.Allow || len(r.Methods) > 0 {
			continue // deny rules and method rules never authorize a tools/call
		}
		if rulesTouchTools(r.Tools, scope) {
			relevant = append(relevant, r)
		}
	}
	if len(relevant) == 0 {
		return false // no authorizing rule ⇒ the call is denied or default; not a cosign gate
	}
	for _, r := range relevant {
		if !r.RequireCosign {
			return false
		}
	}
	return true
}

// rulesTouchTools reports whether a rule's tool globs overlap the grant's tool
// scope — i.e. the rule could authorize a call the grant injects into.
func rulesTouchTools(ruleTools, grantTools []string) bool {
	if len(ruleTools) == 0 {
		return true // a rule with no tools governs every tool
	}
	for _, rt := range ruleTools {
		for _, gt := range grantTools {
			if globsOverlap(rt, gt) {
				return true
			}
		}
	}
	return false
}

// globsOverlap reports whether two tool-name globs can match a common tool. It is
// a conservative approximation: exact equality, a "*" on either side, or one glob
// matching the other's literal form.
func globsOverlap(a, b string) bool {
	if a == b || a == "*" || b == "*" {
		return true
	}
	if ok, _ := path.Match(a, b); ok {
		return true
	}
	if ok, _ := path.Match(b, a); ok {
		return true
	}
	return false
}

// --- severity helpers ---

// parseSeverityLevel maps a severity name to its rank (critical=0 … low=3).
func parseSeverityLevel(s string) (int, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return 0, nil
	case "high":
		return 1, nil
	case "medium":
		return 2, nil
	case "low":
		return 3, nil
	default:
		return 0, fmt.Errorf("%q is not one of critical|high|medium|low", s)
	}
}

func severityLevelOf(s air.Severity) int {
	switch s {
	case air.SevCritical:
		return 0
	case air.SevHigh:
		return 1
	case air.SevMedium:
		return 2
	default:
		return 3
	}
}

// scoreBreaches reports whether the score contains any finding at or above the
// given severity level (0=critical … 3=low).
func scoreBreaches(s air.ExposureScore, level int) bool {
	if level >= 0 && s.Critical > 0 {
		return true
	}
	if level >= 1 && s.High > 0 {
		return true
	}
	if level >= 2 && s.Medium > 0 {
		return true
	}
	if level >= 3 && s.Low > 0 {
		return true
	}
	return false
}

// --- ledger (its own chain, never the gateway's) ---

// ensureSeparateLedger refuses an --audit-log that collides with the gateway's
// own audit chain (gateway-wide or any backend's). A shared file would let two
// writers interleave records into one hash chain, silently corrupting the
// tamper-evidence both depend on.
func ensureSeparateLedger(auditLog string, cfg *Config) error {
	want, err := filepath.Abs(auditLog)
	if err != nil {
		return err
	}
	var configured []string
	if cfg.AuditLog != "" {
		configured = append(configured, cfg.AuditLog)
	}
	for _, b := range cfg.Backends {
		if b.AuditLog != "" {
			configured = append(configured, b.AuditLog)
		}
	}
	for _, c := range configured {
		abs, err := filepath.Abs(c)
		if err != nil {
			continue
		}
		// EqualFold biases toward refusing: on Windows the filesystem is
		// case-insensitive, and over-refusing merely asks for a different path,
		// whereas a missed collision would corrupt the live chain.
		if strings.EqualFold(abs, want) {
			return fmt.Errorf("--audit-log %q is the gateway's own audit ledger — osint must use a SEPARATE ledger (concurrent append corrupts the live chain's tamper-evidence)", auditLog)
		}
	}
	return nil
}

// appendOsintRecord seals the run into its own hash chain as a single
// Decision:"allow" record — a report is not a policy denial, so it must not trip
// the deny audit-webhook alert path. The grade and severity counts ride Reason.
func appendOsintRecord(auditLog string, report air.ExposureReport) error {
	seq, last, err := seedAuditFromExisting(auditLog)
	if err != nil {
		return fmt.Errorf("osint ledger %s: %w", auditLog, err)
	}
	f, err := os.OpenFile(auditLog, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("open osint ledger %s: %w", auditLog, err)
	}
	defer f.Close()
	log := policy.NewAuditLog(f, nowRFC3339)
	log.SeedFrom(seq, last)
	peer := report.Gateway
	if peer == "" {
		peer = "self"
	}
	s := report.Score
	return log.Append(policy.AuditRecord{
		Backend:  "",
		Peer:     peer,
		Method:   "air/osint",
		Decision: "allow", // findings are a REPORT, never a policy deny
		Reason: fmt.Sprintf("self-recon grade=%s crit=%d high=%d med=%d low=%d; report sha256=%s",
			s.Grade, s.Critical, s.High, s.Medium, s.Low, reportHash(report)),
		Rule: -1,
	})
}

// reportHash is the sha256 of the report's canonical JSON — the artifact hash
// carried in the ledger record so the sealed report is identifiable.
func reportHash(report air.ExposureReport) string {
	b, _ := json.Marshal(report)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func shortHash(h string) string {
	if len(h) > 8 {
		return h[:8]
	}
	return h
}

// --- snapshot / diff (mirrors airchange.go) ---

func osintSnapshot(path string, cur air.ExposureReport, update, asJSON bool) error {
	old, existed, err := loadReportSnapshot(path)
	if err != nil {
		return err
	}
	if !existed {
		if err := writeReportFile(path, cur); err != nil {
			return err
		}
		fmt.Fprintln(os.Stderr, okLine("baseline saved to %s", path)+dim(fmt.Sprintf(" · grade %s · %d finding(s)", cur.Score.Grade, len(cur.Findings))))
		return nil
	}
	delta := air.DiffReports(old, cur)
	if update {
		if err := writeReportFile(path, cur); err != nil {
			return err
		}
	}
	if asJSON {
		return printDeltaJSON(delta)
	}
	renderOsintDelta(delta)
	if update && !delta.Empty() {
		fmt.Fprintln(os.Stderr, dim("snapshot rolled forward to current"))
	}
	return nil
}

func loadReportSnapshot(path string) (rep air.ExposureReport, existed bool, err error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return air.ExposureReport{}, false, nil
	}
	if err != nil {
		return air.ExposureReport{}, false, err
	}
	if err := json.Unmarshal(data, &rep); err != nil {
		return air.ExposureReport{}, false, fmt.Errorf("snapshot %s is not an exposure report: %w", path, err)
	}
	return rep, true, nil
}

// writeReportFile writes the report as indented JSON at 0600 — a surface report
// names private mesh identities and endpoints, so it is owner-private by default.
func writeReportFile(path string, report air.ExposureReport) error {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}

// --- live self cross-check (self-only; derives the target from local identity) ---

// osintLiveCrossCheck dials the operator's OWN control endpoint (local mesh IP +
// control.port — never a positional target), verifies the live gateway identity
// is the operator's own, and reports whether the live catalog agrees with the
// static projection. It returns the verified gateway identity.
func osintLiveCrossCheck(o *meshOptions, cfg *Config, mesh air.MeshExposure) (string, error) {
	if cfg.Control == nil || cfg.Control.Port == 0 {
		return "", errors.New("--live needs a control endpoint (control.port) in the config; this gateway exposes none to cross-check")
	}
	o.BlockInbound = true
	client, err := startMesh(o, os.Stderr)
	if err != nil {
		return "", err
	}
	defer stopMesh(client)

	st, err := client.Status()
	if err != nil {
		return "", fmt.Errorf("mesh status: %w", err)
	}
	ownIP := strings.SplitN(st.LocalPeerState.IP, "/", 2)[0]
	ownFQDN := st.LocalPeerState.FQDN
	if ownIP == "" {
		return "", errors.New("--live: no local mesh IP; cannot reach your own control endpoint")
	}
	control := fmt.Sprintf("%s:%d", ownIP, cfg.Control.Port)

	hc := &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return client.Dial(ctx, "tcp", control)
			},
		},
	}
	cat, _, err := air.FetchCatalog(hc, "http://air-control"+air.CatalogPath)
	if err != nil {
		return "", fmt.Errorf("--live: fetch own catalog: %w", err)
	}
	if err := verifySelfGateway(cat.Gateway, ownFQDN); err != nil {
		return "", err
	}

	// Compare the operator's own live catalog to the static projection for self.
	self := ownFQDN
	if self == "" {
		self = "pubkey:" + st.LocalPeerState.PubKey
	}
	staticReach := air.ReachabilityFor(mesh, self)
	live := make([]string, 0, len(cat.Endpoints))
	for _, e := range cat.Endpoints {
		live = append(live, e.Name)
	}
	sort.Strings(live)
	onlyStatic := diffNames(staticReach.Backends, live)
	onlyLive := diffNames(live, staticReach.Backends)
	switch {
	case len(onlyStatic) == 0 && len(onlyLive) == 0:
		fmt.Fprintln(os.Stderr, okLine("live cross-check: catalog agrees with the static projection")+dim(fmt.Sprintf(" (%d backend(s))", len(live))))
	default:
		fmt.Fprintln(os.Stderr, amber("live cross-check: drift")+dim(" static-only="+strings.Join(onlyStatic, ",")+" live-only="+strings.Join(onlyLive, ",")))
	}
	if cat.Gateway != "" {
		return cat.Gateway, nil
	}
	return ownFQDN, nil
}

// verifySelfGateway aborts unless the live gateway identity is the operator's
// own — osint never probes a foreign gateway. An empty live identity is accepted
// (the catalog omits it) since the target was already derived from the local
// identity; a NON-empty mismatch is a hard abort.
func verifySelfGateway(catGateway, ownFQDN string) error {
	if catGateway == "" || ownFQDN == "" {
		return nil
	}
	if catGateway != ownFQDN {
		return fmt.Errorf("--live: the probed gateway identity %q is not your own %q — refusing to probe a foreign gateway", catGateway, ownFQDN)
	}
	return nil
}

// diffNames returns names in a not present in b.
func diffNames(a, b []string) []string {
	have := make(map[string]bool, len(b))
	for _, x := range b {
		have[x] = true
	}
	var out []string
	for _, x := range a {
		if !have[x] {
			out = append(out, x)
		}
	}
	sort.Strings(out)
	return out
}
