package edge

import (
	"bytes"
	"os"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/xrey167/meshmcp/policy"
)

// yamlScalar builds a scalar YAML node for exercising UnmarshalYAML directly.
func yamlScalar(s string) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: s}
}

// validConfig returns a minimal well-formed files-mode config for mutation.
func validConfig() Config {
	return Config{
		Listen:     "127.0.0.1:0",
		PublicURL:  "https://mcp.example.com",
		StateDir:   "/tmp/edge-state",
		AuditLog:   "/tmp/edge-state/audit.jsonl",
		SigningKey: "/tmp/edge-state/key.json",
		TLS:        TLSConfig{CertFile: "/x/cert.pem", KeyFile: "/x/key.pem"},
		Backend: BackendConfig{
			Name:   "docs",
			Addr:   "gateway.mesh:9101",
			Tools:  []string{"search_*"},
			Policy: policy.Policy{DefaultAllow: false},
		},
	}
}

// TestConfigValidateBehindFront proves the loopback fence on the front mode: a
// loopback listen with no tls block is accepted, a non-loopback bind is refused
// (OAuth bearers would cross the network in cleartext), and a tls block alongside
// behind_front is refused (the front terminates TLS, not the edge).
func TestConfigValidateBehindFront(t *testing.T) {
	// Accepted: loopback listen, no tls, public_url is still the front's https URL.
	c := validConfig()
	c.BehindFront = true
	c.TLS = TLSConfig{}
	c.Listen = "127.0.0.1:8080"
	if _, err := c.Validate(); err != nil {
		t.Fatalf("loopback behind_front rejected: %v", err)
	}

	// Accepted: IPv6 loopback.
	c6 := validConfig()
	c6.BehindFront = true
	c6.TLS = TLSConfig{}
	c6.Listen = "[::1]:8080"
	if _, err := c6.Validate(); err != nil {
		t.Fatalf("[::1] behind_front rejected: %v", err)
	}

	// Refused: a non-loopback bind would leak bearers onto the network.
	for _, addr := range []string{"0.0.0.0:8080", "203.0.113.7:8443", "192.168.1.5:8080"} {
		cn := validConfig()
		cn.BehindFront = true
		cn.TLS = TLSConfig{}
		cn.Listen = addr
		if _, err := cn.Validate(); err == nil || !strings.Contains(err.Error(), "loopback") {
			t.Fatalf("non-loopback behind_front %q accepted or wrong error: %v", addr, err)
		}
	}

	// Refused: a tls block alongside behind_front (the front owns TLS).
	ct := validConfig() // validConfig sets files-mode TLS
	ct.BehindFront = true
	ct.Listen = "127.0.0.1:8080"
	if _, err := ct.Validate(); err == nil || !strings.Contains(err.Error(), "remove the tls block") {
		t.Fatalf("behind_front with a tls block accepted or wrong error: %v", err)
	}

	// public_url is still required and still https — the front's public URL is the
	// OAuth issuer, so behind_front does not relax it.
	cu := validConfig()
	cu.BehindFront = true
	cu.TLS = TLSConfig{}
	cu.Listen = "127.0.0.1:8080"
	cu.PublicURL = "http://insecure.example.com"
	if _, err := cu.Validate(); err == nil || !strings.Contains(err.Error(), "https") {
		t.Fatalf("behind_front accepted a non-https public_url: %v", err)
	}
}

// TestConfigValidateBeacon covers the beacon ingress mode: files-mode TLS with a
// control+zone is accepted (listen optional), and the mode rejects a missing
// control/zone, a behind_front combination, a missing cert, and tls.acme.
func TestConfigValidateBeacon(t *testing.T) {
	base := func() Config {
		c := validConfig() // files-mode TLS
		c.Beacon = &BeaconConfig{Control: "beacon.example.com:7443", Zone: "beacon.example.com"}
		c.Listen = "" // optional in beacon mode
		return c
	}
	if _, err := base().Validate(); err != nil {
		t.Fatalf("valid beacon config rejected: %v", err)
	}

	c := base()
	c.Beacon.Control = ""
	if _, err := c.Validate(); err == nil || !strings.Contains(err.Error(), "beacon.control") {
		t.Fatalf("missing beacon.control not caught: %v", err)
	}

	c = base()
	c.Beacon.Zone = ""
	if _, err := c.Validate(); err == nil || !strings.Contains(err.Error(), "beacon.zone") {
		t.Fatalf("missing beacon.zone not caught: %v", err)
	}

	c = base()
	c.BehindFront = true
	if _, err := c.Validate(); err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("beacon+behind_front not rejected: %v", err)
	}

	c = base()
	c.TLS = TLSConfig{} // no cert -> the gateway can't terminate TLS
	if _, err := c.Validate(); err == nil || !strings.Contains(err.Error(), "cert_file") {
		t.Fatalf("beacon without a cert not rejected: %v", err)
	}

	c = base() // files present; adding acme must be refused (beacon uses auto_cert/files)
	c.TLS.ACME = &ACMEConfig{Domains: []string{"beacon.example.com"}}
	if _, err := c.Validate(); err == nil || !strings.Contains(err.Error(), "acme") {
		t.Fatalf("beacon+acme not rejected: %v", err)
	}

	// auto_cert (ACME DNS-01) accepted in place of a static cert.
	c = base()
	c.TLS = TLSConfig{}
	c.Beacon.AutoCert = &BeaconAutoCert{Email: "ops@example.com"}
	if _, err := c.Validate(); err != nil {
		t.Fatalf("beacon.auto_cert rejected: %v", err)
	}

	// auto_cert AND static files is ambiguous.
	c = base() // has files
	c.Beacon.AutoCert = &BeaconAutoCert{Email: "ops@example.com"}
	if _, err := c.Validate(); err == nil || !strings.Contains(err.Error(), "exactly one") {
		t.Fatalf("auto_cert + files not rejected: %v", err)
	}

	// auto_cert requires an ACME contact email.
	c = base()
	c.TLS = TLSConfig{}
	c.Beacon.AutoCert = &BeaconAutoCert{}
	if _, err := c.Validate(); err == nil || !strings.Contains(err.Error(), "email") {
		t.Fatalf("auto_cert without email not rejected: %v", err)
	}
}

func TestConfigValidateAcceptsMinimal(t *testing.T) {
	c, err := validConfig().Validate()
	if err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	// Defaults applied.
	if c.Registration.Mode != RegistrationOpenApproval {
		t.Errorf("default registration mode = %q, want %q", c.Registration.Mode, RegistrationOpenApproval)
	}
	if c.OAuth.AccessTokenTTL.Std() != defaultAccessTokenTTL {
		t.Errorf("default access TTL = %s, want %s", c.OAuth.AccessTokenTTL.Std(), defaultAccessTokenTTL)
	}
	if !c.OAuth.SessionsEnabled() {
		t.Error("sessions should default to enabled")
	}
	if c.Limits.MaxMCPBodyBytes != defaultMaxMCPBodyBytes {
		t.Errorf("default body cap = %d", c.Limits.MaxMCPBodyBytes)
	}
}

func TestGlobsOverlap(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"search_docs", "search_files", false}, // distinct literals
		{"search_docs", "search_docs", true},   // equal
		{"search_*", "search_docs", true},      // glob vs matching literal
		{"search_*", "verify_docs", false},     // glob vs non-matching literal
		{"read_*", "read_file_*", true},        // two wildcards, shared prefix — the case the old check missed
		{"estimate_*", "verify_*", false},      // two wildcards, disjoint prefixes
		{"a*", "*b", true},                     // "ab" matches both
		{"*", "read_*", true},                  // star overlaps any glob
		{"*", "anything", true},                // star overlaps any literal
		{"read_a*", "read_b*", false},          // shared literal head but divergent before wildcard
	}
	for _, tc := range cases {
		if got := globsOverlap(tc.a, tc.b); got != tc.want {
			t.Errorf("globsOverlap(%q,%q)=%v want %v", tc.a, tc.b, got, tc.want)
		}
		if got := globsOverlap(tc.b, tc.a); got != tc.want {
			t.Errorf("globsOverlap(%q,%q) (swapped)=%v want %v", tc.b, tc.a, got, tc.want)
		}
	}
}

// A payment config with disjoint wildcard price globs must be ACCEPTED — the
// overlap check must not be so conservative that it rejects reasonable configs.
func TestPaymentDisjointWildcardGlobsAccepted(t *testing.T) {
	c := validConfig()
	c.Backend.Payment = PaymentConfig{
		Enabled: true, Asset: "USDC", PayTo: "0xServer", DevInsecureVerifier: true,
		Prices: map[string]string{"estimate_*": "1000", "verify_*": "5000"},
	}
	if _, err := c.Validate(); err != nil {
		t.Fatalf("disjoint wildcard price globs should validate, got: %v", err)
	}
}

func TestConfigValidateRejections(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{"no listen", func(c *Config) { c.Listen = "" }, "listen is required"},
		{"http public_url", func(c *Config) { c.PublicURL = "http://mcp.example.com" }, "must be an absolute https URL"},
		{"trailing slash", func(c *Config) { c.PublicURL = "https://mcp.example.com/" }, "must not end with a trailing slash"},
		{"no state_dir", func(c *Config) { c.StateDir = "" }, "state_dir is required"},
		{"no audit", func(c *Config) { c.AuditLog = "" }, "audit_log is required"},
		{"no signing key", func(c *Config) { c.SigningKey = "" }, "signing_key is required"},
		{"no tls", func(c *Config) { c.TLS = TLSConfig{} }, "tls requires either"},
		{"both tls modes", func(c *Config) {
			c.TLS.ACME = &ACMEConfig{Domains: []string{"mcp.example.com"}}
		}, "choose exactly one"},
		{"half tls files", func(c *Config) { c.TLS.KeyFile = "" }, "cert_file and key_file must both be set"},
		{"default_allow true", func(c *Config) { c.Backend.Policy.DefaultAllow = true }, "default_allow must be false"},
		{"no backend name", func(c *Config) { c.Backend.Name = "" }, "backend.name is required"},
		{"no backend addr", func(c *Config) { c.Backend.Addr = "" }, "backend.addr is required"},
		{"token mode no tokens", func(c *Config) { c.Registration.Mode = RegistrationToken }, "requires at least one initial_access_tokens"},
		{"bad registration mode", func(c *Config) { c.Registration.Mode = "wat" }, "registration.mode must be"},
		{"access ttl too long", func(c *Config) { c.OAuth.AccessTokenTTL = Duration(2 * time.Hour) }, "exceeds the 1h0m0s ceiling"},
		{"refresh shorter than access", func(c *Config) {
			c.OAuth.AccessTokenTTL = Duration(30 * time.Minute)
			c.OAuth.RefreshTokenTTL = Duration(time.Minute)
		}, "refresh_token_ttl must be >= access_token_ttl"},
		{"replay store plain path", func(c *Config) {
			c.OAuth.DPoPReplayStore = "/var/lib/replay"
		}, "dpop_replay_store must be a postgres"},
		{"replay store wrong scheme", func(c *Config) {
			c.OAuth.DPoPReplayStore = "mysql://u:p@db/x"
		}, "dpop_replay_store must be a postgres"},
		{"payment no asset", func(c *Config) {
			c.Backend.Payment = PaymentConfig{Enabled: true, PayTo: "0xS", Prices: map[string]string{"x": "1"}}
		}, "payment.asset is required"},
		{"payment no pay_to", func(c *Config) {
			c.Backend.Payment = PaymentConfig{Enabled: true, Asset: "USDC", Prices: map[string]string{"x": "1"}}
		}, "pay_to is required"},
		{"payment no prices", func(c *Config) {
			c.Backend.Payment = PaymentConfig{Enabled: true, Asset: "USDC", PayTo: "0xS"}
		}, "no prices are set"},
		{"payment empty price", func(c *Config) {
			c.Backend.Payment = PaymentConfig{Enabled: true, Asset: "USDC", PayTo: "0xS", Prices: map[string]string{"search_docs": ""}}
		}, "positive integer"},
		{"payment non-integer price", func(c *Config) {
			c.Backend.Payment = PaymentConfig{Enabled: true, Asset: "USDC", PayTo: "0xS", Prices: map[string]string{"search_docs": "1.5"}}
		}, "positive integer"},
		{"payment zero price", func(c *Config) {
			c.Backend.Payment = PaymentConfig{Enabled: true, Asset: "USDC", PayTo: "0xS", Prices: map[string]string{"search_docs": "0"}}
		}, "positive integer"},
		{"payment salt equals backend name", func(c *Config) {
			c.Backend.Name = "docs"
			c.Backend.Payment = PaymentConfig{Enabled: true, Asset: "USDC", PayTo: "0xS", Salt: "docs", Prices: map[string]string{"search_docs": "1"}}
		}, "salt must not equal the backend name"},
		{"payment single_use_store not postgres", func(c *Config) {
			c.Backend.Payment = PaymentConfig{Enabled: true, Asset: "USDC", PayTo: "0xS", SingleUseStore: "/var/lib/x", Prices: map[string]string{"search_docs": "1"}}
		}, "single_use_store must be a postgres"},
		{"payment bad glob", func(c *Config) {
			c.Backend.Payment = PaymentConfig{Enabled: true, Asset: "USDC", PayTo: "0xS", Prices: map[string]string{"[bad": "1"}}
		}, "bad tool glob"},
		{"payment overlapping globs", func(c *Config) {
			c.Backend.Payment = PaymentConfig{Enabled: true, Asset: "USDC", PayTo: "0xS", Prices: map[string]string{"search_*": "1", "search_docs": "2"}}
		}, "overlap"},
		{"payment overlapping two-wildcard globs", func(c *Config) {
			c.Backend.Payment = PaymentConfig{Enabled: true, Asset: "USDC", PayTo: "0xS", Prices: map[string]string{"read_*": "1", "read_file_*": "2"}}
		}, "overlap"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := validConfig()
			tc.mutate(&c)
			_, err := c.Validate()
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.want)
			}
		})
	}
}

func TestConfigValidateDPoPReplayStoreDSN(t *testing.T) {
	// A DSN error must never echo the value — it may carry credentials.
	c := validConfig()
	c.OAuth.DPoPReplayStore = "mysql://user:hunter2@db/x"
	if _, err := c.Validate(); err == nil || strings.Contains(err.Error(), "hunter2") {
		t.Fatalf("want scheme error without the DSN echoed, got %v", err)
	}

	for _, dsn := range []string{
		"postgres://meshmcp@db.internal:5432/meshmcp",
		"postgresql://meshmcp@db.internal/meshmcp",
	} {
		c := validConfig()
		c.OAuth.DPoPReplayStore = dsn
		if _, err := c.Validate(); err != nil {
			t.Errorf("dsn %q rejected: %v", dsn, err)
		}
	}
}

func TestConfigValidateACMEMode(t *testing.T) {
	c := validConfig()
	c.TLS = TLSConfig{ACME: &ACMEConfig{Domains: []string{"mcp.example.com"}, Email: "ops@example.com"}}
	got, err := c.Validate()
	if err != nil {
		t.Fatalf("valid acme config rejected: %v", err)
	}
	if got.TLS.ACME.Challenge != ChallengeTLSALPN01 {
		t.Errorf("acme challenge default = %q, want %q", got.TLS.ACME.Challenge, ChallengeTLSALPN01)
	}
	if got.TLS.ACME.HTTPPort != defaultACMEHTTPPort {
		t.Errorf("acme http port default = %d", got.TLS.ACME.HTTPPort)
	}

	// public_url host must be covered by the domains list.
	c2 := validConfig()
	c2.TLS = TLSConfig{ACME: &ACMEConfig{Domains: []string{"other.example.com"}}}
	if _, err := c2.Validate(); err == nil || !strings.Contains(err.Error(), "must be one of tls.acme.domains") {
		t.Fatalf("expected domain-coverage error, got %v", err)
	}

	// unknown challenge type rejected.
	c3 := validConfig()
	c3.TLS = TLSConfig{ACME: &ACMEConfig{Domains: []string{"mcp.example.com"}, Challenge: "dns-01"}}
	if _, err := c3.Validate(); err == nil || !strings.Contains(err.Error(), "challenge must be") {
		t.Fatalf("expected challenge error, got %v", err)
	}
}

// TestExampleConfigValidates guards against drift between examples/edge.yaml and
// the config schema: it must decode strictly (KnownFields) and pass Validate.
func TestExampleConfigValidates(t *testing.T) {
	data, err := os.ReadFile("../examples/edge.yaml")
	if err != nil {
		t.Skipf("example config not found: %v", err)
	}
	var cfg Config
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		t.Fatalf("examples/edge.yaml does not decode strictly: %v", err)
	}
	if _, err := cfg.Validate(); err != nil {
		t.Fatalf("examples/edge.yaml does not validate: %v", err)
	}
}

func TestDurationYAMLRoundTrip(t *testing.T) {
	var d Duration
	if err := d.UnmarshalYAML(yamlScalar("15m")); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if d.Std() != 15*time.Minute {
		t.Fatalf("got %s, want 15m", d.Std())
	}
	if err := d.UnmarshalYAML(yamlScalar("nope")); err == nil {
		t.Fatal("expected error on invalid duration")
	}
}
