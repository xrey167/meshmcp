package main

import (
	"archive/tar"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xrey167/meshmcp/policy"
)

// TestDiagBundleRedactsAndCollects proves the support bundle: it contains the
// documented sections, the config's setup_key is REDACTED, and the audit
// section carries the chain verdict for the configured ledger.
func TestDiagBundleRedactsAndCollects(t *testing.T) {
	t.Setenv("MESHMCP_HOME", t.TempDir())
	dir := t.TempDir()

	// A ledger with two real records so the verdict is meaningful.
	auditPath := filepath.Join(dir, "audit.jsonl")
	f, err := os.OpenFile(auditPath, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	al := policy.NewAuditLog(f, func() string { return time.Unix(0, 0).UTC().Format(time.RFC3339) })
	for i := 0; i < 2; i++ {
		if err := al.Append(policy.AuditRecord{Backend: "kb", Peer: "p", Method: "tools/call", Decision: "allow", Rule: 0}); err != nil {
			t.Fatal(err)
		}
	}
	f.Close()

	cfg := writeConfig(t, `
mesh:
  device_name: gw
  setup_key: super-secret-key-value
audit_log: `+auditPath+`
backends:
  - name: kb
    port: 9101
    stdio: ["echo"]
`)
	bundle := filepath.Join(dir, "diag.tar.gz")
	if err := cmdDiag([]string{"--config", cfg, "--bundle", bundle}); err != nil {
		t.Fatalf("diag: %v", err)
	}

	// Unpack and index the bundle.
	bf, err := os.Open(bundle)
	if err != nil {
		t.Fatal(err)
	}
	defer bf.Close()
	gz, err := gzip.NewReader(bf)
	if err != nil {
		t.Fatal(err)
	}
	sections := map[string]string{}
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(tr)
		sections[strings.TrimPrefix(hdr.Name, "meshmcp-diag/")] = string(b)
	}

	for _, want := range []string{"meta.txt", "config.redacted.yaml", "doctor.txt", "audit.txt", "datadir.txt"} {
		if _, ok := sections[want]; !ok {
			t.Errorf("bundle missing section %q (have %v)", want, keysOf(sections))
		}
	}

	// The one irreducible secret must not be in the bundle — anywhere.
	for name, body := range sections {
		if strings.Contains(body, "super-secret-key-value") {
			t.Errorf("secret leaked into bundle section %q", name)
		}
	}
	if !strings.Contains(sections["config.redacted.yaml"], "[REDACTED]") {
		t.Errorf("setup_key not visibly redacted:\n%s", sections["config.redacted.yaml"])
	}

	// The audit section reports an intact chain over both records.
	if !strings.Contains(sections["audit.txt"], "ok=true") || !strings.Contains(sections["audit.txt"], "records=2") {
		t.Errorf("audit verdict missing or wrong:\n%s", sections["audit.txt"])
	}
	// Version metadata present.
	if !strings.Contains(sections["meta.txt"], "meshmcp version:") {
		t.Errorf("meta section incomplete:\n%s", sections["meta.txt"])
	}
}

func keysOf(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// TestRedactConfigMasksEveryKeyForm proves redaction handles indentation and
// leaves non-secret lines untouched.
func TestRedactConfigMasksEveryKeyForm(t *testing.T) {
	in := "mesh:\n  setup_key: abc123\n  device_name: gw\nsetup_key: toplevel\n"
	out := string(redactConfig([]byte(in)))
	if strings.Contains(out, "abc123") || strings.Contains(out, "toplevel") {
		t.Fatalf("secret survived redaction:\n%s", out)
	}
	if !strings.Contains(out, "device_name: gw") {
		t.Fatalf("non-secret line was damaged:\n%s", out)
	}
	if !strings.Contains(out, "[REDACTED]") {
		t.Fatalf("no redaction applied:\n%s", out)
	}
}

// TestRedactConfigMasksNonBlockStyling is the defense-in-depth guarantee: the
// literal secret is masked even when the line regex can't match it — flow-style
// mappings, quoted values, and deeper nesting. A hand-authored config must not
// be able to smuggle the setup key past redaction by styling.
func TestRedactConfigMasksNonBlockStyling(t *testing.T) {
	cases := []string{
		"mesh: {setup_key: FLOWSECRET, device_name: gw}\n",     // flow mapping
		"mesh:\n  setup_key: \"QUOTEDSECRET\"\n",               // quoted scalar
		"mesh:\n  setup_key:    SPACEDSECRET\n",                // wide spacing
		"outer:\n  mesh:\n    setup_key: NESTEDSECRET\n",       // deeper nesting
		"mesh: {device_name: gw, setup_key: 'SINGLEQUOTED'}\n", // flow + single quotes
	}
	secrets := []string{"FLOWSECRET", "QUOTEDSECRET", "SPACEDSECRET", "NESTEDSECRET", "SINGLEQUOTED"}
	for i, in := range cases {
		out := string(redactConfig([]byte(in)))
		if strings.Contains(out, secrets[i]) {
			t.Errorf("case %d: secret %q survived redaction:\n%s", i, secrets[i], out)
		}
		if !strings.Contains(out, "[REDACTED]") {
			t.Errorf("case %d: no redaction marker applied:\n%s", i, out)
		}
	}
}
