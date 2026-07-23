package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"runtime"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/xrey167/meshmcp/policy"
)

// meshmcp diag assembles a support bundle — the sysdiagnose moment. When
// something is wrong, "run one command and send me the file" beats a
// twenty-question support thread. The bundle is deliberately safe to share:
// the config is secret-redacted, the audit material is the tail plus the chain
// verdict (no secrets live in audit records), and nothing in the collection
// path joins the mesh or mutates state.

// diagAuditTailLines bounds how much ledger tail ships in a bundle.
const diagAuditTailLines = 200

// cmdDiag implements `meshmcp diag [--bundle out.tar.gz]`.
func cmdDiag(args []string) error {
	fs := flag.NewFlagSet("diag", flag.ExitOnError)
	cfgPath := fs.String("config", defaultConfigPath(), "gateway config to diagnose")
	bundle := fs.String("bundle", "", "write a shareable support bundle (tar.gz) to this path")
	if err := fs.Parse(args); err != nil {
		return err
	}

	files := collectDiag(*cfgPath)

	if *bundle == "" {
		// No bundle requested: print the collected sections to stdout.
		for _, f := range files {
			fmt.Printf("── %s ──\n%s\n", f.name, strings.TrimRight(string(f.body), "\n"))
		}
		return nil
	}

	out, err := os.OpenFile(*bundle, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("diag: create bundle: %w", err)
	}
	defer out.Close()
	gz := gzip.NewWriter(out)
	tw := tar.NewWriter(gz)
	now := time.Now()
	for _, f := range files {
		hdr := &tar.Header{Name: "meshmcp-diag/" + f.name, Mode: 0o600, Size: int64(len(f.body)), ModTime: now}
		if err := tw.WriteHeader(hdr); err != nil {
			return fmt.Errorf("diag: bundle write: %w", err)
		}
		if _, err := tw.Write(f.body); err != nil {
			return fmt.Errorf("diag: bundle write: %w", err)
		}
	}
	if err := tw.Close(); err != nil {
		return fmt.Errorf("diag: bundle finalize: %w", err)
	}
	if err := gz.Close(); err != nil {
		return fmt.Errorf("diag: bundle finalize: %w", err)
	}
	fmt.Println(okLine("wrote %s", bold(*bundle)))
	fmt.Println(dim("  config secrets are redacted; the bundle holds the audit tail + chain verdict, doctor output, versions, and the data-dir listing."))
	return nil
}

// diagFile is one named section of the bundle.
type diagFile struct {
	name string
	body []byte
}

// collectDiag gathers every section, best-effort: a section that cannot be
// collected reports its error in place rather than failing the whole bundle —
// a support bundle from a broken installation is exactly the point.
func collectDiag(cfgPath string) []diagFile {
	var files []diagFile
	add := func(name string, body []byte) { files = append(files, diagFile{name, body}) }

	// meta: versions and environment basics.
	var meta bytes.Buffer
	fmt.Fprintf(&meta, "meshmcp version: %s\n", version)
	fmt.Fprintf(&meta, "go: %s\nos/arch: %s/%s\n", runtime.Version(), runtime.GOOS, runtime.GOARCH)
	fmt.Fprintf(&meta, "time: %s\n", time.Now().UTC().Format(time.RFC3339))
	fmt.Fprintf(&meta, "config path: %s\n", cfgPath)
	if dir, err := dataDirPath(); err == nil {
		fmt.Fprintf(&meta, "data dir: %s\n", dir)
	}
	fmt.Fprintf(&meta, "$MESHMCP_LOG: %q\n$MESHMCP_CONTROL set: %v\n$NB_SETUP_KEY set: %v\n",
		os.Getenv("MESHMCP_LOG"), os.Getenv("MESHMCP_CONTROL") != "", os.Getenv("NB_SETUP_KEY") != "")
	add("meta.txt", meta.Bytes())

	// config: the raw file, secret-redacted. Redaction is line-based and
	// conservative: any setup_key value is masked whether or not the schema
	// recognizes it.
	if raw, err := os.ReadFile(cfgPath); err != nil {
		add("config.redacted.yaml", []byte(fmt.Sprintf("could not read config: %v\n", err)))
	} else {
		add("config.redacted.yaml", redactConfig(raw))
	}

	// doctor: the same pre-flight checks, captured.
	add("doctor.txt", captureDoctor(cfgPath))

	// audit: chain verdict + bounded tail for each ledger the config names.
	if cfg, err := loadConfig(cfgPath); err != nil {
		add("audit.txt", []byte(fmt.Sprintf("config did not load: %v\n", err)))
	} else {
		var audit bytes.Buffer
		ledgers := map[string]bool{}
		if cfg.AuditLog != "" {
			ledgers[cfg.AuditLog] = true
		}
		for _, b := range cfg.Backends {
			if b.AuditLog != "" {
				ledgers[b.AuditLog] = true
			}
		}
		if len(ledgers) == 0 {
			audit.WriteString("no audit ledger configured\n")
		}
		for path := range ledgers {
			fmt.Fprintf(&audit, "── ledger %s ──\n", path)
			f, err := os.Open(path)
			if err != nil {
				fmt.Fprintf(&audit, "open: %v\n", err)
				continue
			}
			res, verr := policy.VerifyChain(f)
			f.Close()
			fmt.Fprintf(&audit, "chain: ok=%v records=%d", res.OK, res.Count)
			if !res.OK {
				fmt.Fprintf(&audit, " break_seq=%d reason=%q", res.BreakSeq, res.Reason)
			}
			if verr != nil {
				fmt.Fprintf(&audit, " verify_error=%q", verr.Error())
			}
			audit.WriteString("\n")
			for _, line := range tailLines(path, diagAuditTailLines) {
				audit.WriteString(line)
				audit.WriteByte('\n')
			}
		}
		add("audit.txt", audit.Bytes())
	}

	// data dir: names and sizes only — enough to spot a missing identity file
	// or a runaway ledger without shipping the contents.
	var listing bytes.Buffer
	if dir, err := dataDirPath(); err != nil {
		fmt.Fprintf(&listing, "data dir unresolved: %v\n", err)
	} else if entries, err := os.ReadDir(dir); err != nil {
		fmt.Fprintf(&listing, "data dir %s: %v\n", dir, err)
	} else {
		fmt.Fprintf(&listing, "%s:\n", dir)
		for _, e := range entries {
			info, ierr := e.Info()
			if ierr != nil {
				fmt.Fprintf(&listing, "  %s (?)\n", e.Name())
				continue
			}
			fmt.Fprintf(&listing, "  %-40s %8d bytes  %s\n", e.Name(), info.Size(), info.ModTime().UTC().Format(time.RFC3339))
		}
	}
	add("datadir.txt", listing.Bytes())

	return files
}

// redactSetupKey masks the value of any block-style `setup_key:` line while
// keeping the key name visible, so the common config stays readable in a bundle
// with only the one irreducible secret hidden.
var redactSetupKey = regexp.MustCompile(`(?m)^(\s*setup_key\s*:).*$`)

// secretScalarKeys names config keys whose scalar value is — or can embed — a
// credential that must be masked before the config ships in a support bundle.
// The bool is whether the value is a postgres DSN: a DSN keeps its host/db/user
// visible (useful for support) with only the password masked via redactDSN;
// every other key is masked whole. session_store is a plain directory in the
// common case (isPostgresDSN false → nothing masked) and only carries a password
// when it is a postgres DSN. dpop_replay_store lives in the edge config (a
// separate file diag never reads) but is listed for forward-safety.
var secretScalarKeys = map[string]bool{ // key → value is a postgres DSN
	"setup_key":         false, // the mesh setup key — the classic inline secret
	"audit_webhook":     false, // a SIEM/Slack/PagerDuty URL: the whole URL is the secret
	"session_store":     true,  // a directory OR a postgres:// DSN whose password must go
	"dpop_replay_store": true,  // edge-config DSN; forward-safety only
}

// redactConfig masks every inline secret a gateway config can hold before it
// ships in a support bundle. Defense in depth: the line regex handles the common
// block-style setup_key readably, and a structural pass then masks the ACTUAL
// secret VALUES wherever they appear (any depth, flow-style `{setup_key: X}`,
// quoted, etc.), so no YAML styling can slip a secret past the line matcher.
// Postgres DSNs are password-masked (host/db stay visible); other secrets are
// masked whole. Every remaining credential-shaped field is a path or a
// secret-store *name* reference, never an inline value, so nothing else needs it.
func redactConfig(raw []byte) []byte {
	out := redactSetupKey.ReplaceAll(raw, []byte("$1 '[REDACTED]'"))
	for _, s := range secretScalars(raw) {
		replacement := []byte("[REDACTED]")
		if s.isDSN {
			if !isPostgresDSN(s.value) {
				continue // a plain path/dir under a DSN-capable key — not a secret
			}
			red := redactDSN(s.value)
			if red == s.value {
				continue // the DSN carried no password — nothing to mask
			}
			replacement = []byte(red)
		}
		out = bytes.ReplaceAll(out, []byte(s.value), replacement)
	}
	return out
}

// secretScalar is one secret-bearing config value and whether it is a DSN.
type secretScalar struct {
	value string
	isDSN bool
}

// secretScalars extracts every secret-bearing scalar (see secretScalarKeys) from
// the config at any nesting/style by parsing it, so redactConfig can mask the
// literal secret bytes regardless of YAML styling. Parse failures yield nothing
// (the line regex still applied).
func secretScalars(raw []byte) []secretScalar {
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil
	}
	var out []secretScalar
	var walk func(n *yaml.Node)
	walk = func(n *yaml.Node) {
		if n == nil {
			return
		}
		if n.Kind == yaml.MappingNode {
			for i := 0; i+1 < len(n.Content); i += 2 {
				key := n.Content[i].Value
				val := n.Content[i+1]
				if isDSN, ok := secretScalarKeys[key]; ok && val.Kind == yaml.ScalarNode {
					if v := strings.TrimSpace(val.Value); v != "" {
						out = append(out, secretScalar{value: v, isDSN: isDSN})
					}
				}
			}
		}
		for _, c := range n.Content {
			walk(c)
		}
	}
	walk(&doc)
	return out
}

// captureDoctor runs the doctor checks with stdout captured, so the bundle
// carries the same report an operator would see. Doctor is side-effect-free by
// contract, which is what makes this safe to run during collection.
func captureDoctor(cfgPath string) []byte {
	r, w, err := os.Pipe()
	if err != nil {
		return []byte(fmt.Sprintf("could not capture doctor output: %v\n", err))
	}
	saved := os.Stdout
	os.Stdout = w
	docErr := cmdDoctor([]string{"--config", cfgPath})
	os.Stdout = saved
	w.Close()
	out, _ := io.ReadAll(r)
	r.Close()
	if docErr != nil {
		out = append(out, []byte(fmt.Sprintf("doctor: %v\n", docErr))...)
	}
	return out
}

// tailLines returns up to n trailing lines of the file at path (best-effort).
func tailLines(path string, n int) []string {
	f, err := os.Open(path)
	if err != nil {
		return []string{fmt.Sprintf("tail: %v", err)}
	}
	defer f.Close()
	var tail []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for sc.Scan() {
		tail = append(tail, sc.Text())
		if len(tail) > n {
			tail = tail[1:]
		}
	}
	return tail
}
