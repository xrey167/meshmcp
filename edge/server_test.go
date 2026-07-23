package edge

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xrey167/meshmcp/policy"
	"github.com/xrey167/meshmcp/protocol/authorization"
)

// newTestServer builds an edge Server backed by a temp state dir, an in-memory
// audit writer, and a generated signer — no real listener or TLS.
func newTestServer(t *testing.T) (*Server, *bytes.Buffer) {
	t.Helper()
	dir := t.TempDir()
	cfg := validConfig()
	cfg.StateDir = dir
	cfg.AuditLog = filepath.Join(dir, "audit.jsonl")
	cfg.SigningKey = filepath.Join(dir, "key.json")

	signer, err := policy.GenerateSigner()
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	var auditBuf bytes.Buffer
	srv, err := New(cfg, Options{
		Now:         func() time.Time { return time.Unix(1_700_000_000, 0).UTC() },
		Signer:      signer,
		AuditWriter: &auditBuf,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return srv, &auditBuf
}

func TestProtectedResourceMetadata(t *testing.T) {
	srv, _ := newTestServer(t)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// Fetch via the same well-known path a client derives.
	resp, err := http.Get(ts.URL + wellKnownPRM + pathMCP)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "*" {
		t.Errorf("PRM must be CORS-open, got %q", got)
	}
	var prm authorization.ProtectedResourceMetadata
	if err := json.NewDecoder(resp.Body).Decode(&prm); err != nil {
		t.Fatal(err)
	}
	if prm.Resource != "https://mcp.example.com/mcp" {
		t.Errorf("resource = %q", prm.Resource)
	}
	if len(prm.AuthorizationServers) != 1 || prm.AuthorizationServers[0] != "https://mcp.example.com" {
		t.Errorf("authorization_servers = %v", prm.AuthorizationServers)
	}
}

func TestAuthorizationServerMetadataSupportsPKCE(t *testing.T) {
	srv, _ := newTestServer(t)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	for _, path := range []string{wellKnownAS, wellKnownOIDC} {
		resp, err := http.Get(ts.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		var md authorization.AuthorizationServerMetadata
		if err := json.NewDecoder(resp.Body).Decode(&md); err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if !md.SupportsPKCE() {
			t.Fatalf("%s: metadata must advertise PKCE (S256)", path)
		}
		if md.Issuer != "https://mcp.example.com" {
			t.Errorf("%s: issuer = %q", path, md.Issuer)
		}
		if len(md.TokenEndpointAuthMethodsSupported) != 1 || md.TokenEndpointAuthMethodsSupported[0] != authorization.AuthMethodNone {
			t.Errorf("%s: token endpoint auth methods = %v, want [none] (public clients)", path, md.TokenEndpointAuthMethodsSupported)
		}
	}
}

func TestMCPEndpointChallengesUnauthenticated(t *testing.T) {
	srv, _ := newTestServer(t)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp, err := http.Post(ts.URL+pathMCP, "application/json", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
	// The challenge must be parseable by the client-side helper claude.ai uses.
	scheme, _ := authorization.ParseChallenge(resp.Header.Get("WWW-Authenticate"))
	if scheme != authorization.SchemeBearer {
		t.Fatalf("challenge scheme = %q", scheme)
	}
	rmURL := authorization.ResourceMetadataURL(resp.Header.Get("WWW-Authenticate"))
	if rmURL != "https://mcp.example.com"+wellKnownPRM+pathMCP {
		t.Fatalf("resource_metadata URL = %q", rmURL)
	}
}

func TestHealthz(t *testing.T) {
	srv, _ := newTestServer(t)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	resp, err := http.Get(ts.URL + pathHealthz)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("healthz status %d", resp.StatusCode)
	}
}

func TestSigningKeyMissingFatalWithoutAutogen(t *testing.T) {
	dir := t.TempDir()
	cfg := validConfig()
	cfg.StateDir = dir
	cfg.AuditLog = filepath.Join(dir, "audit.jsonl")
	cfg.SigningKey = filepath.Join(dir, "absent.json")
	_, err := New(cfg, Options{AuditWriter: &bytes.Buffer{}})
	if err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("expected fatal missing-key error, got %v", err)
	}
}

func TestSigningKeyAutogenPersists(t *testing.T) {
	dir := t.TempDir()
	cfg := validConfig()
	cfg.StateDir = dir
	cfg.AuditLog = filepath.Join(dir, "audit.jsonl")
	cfg.SigningKey = filepath.Join(dir, "gen.json")
	cfg.SigningKeyAutogen = true
	if _, err := New(cfg, Options{AuditWriter: &bytes.Buffer{}}); err != nil {
		t.Fatalf("autogen New: %v", err)
	}
	if _, err := os.Stat(cfg.SigningKey); err != nil {
		t.Fatalf("signing key not persisted: %v", err)
	}
	// A second construction loads the same key (no autogen needed).
	cfg.SigningKeyAutogen = false
	if _, err := New(cfg, Options{AuditWriter: &bytes.Buffer{}}); err != nil {
		t.Fatalf("reload persisted key: %v", err)
	}
}

// TestBuildTLSConfigFilesMode exercises the files-mode TLS path end to end by
// generating a self-signed cert and serving one real HTTPS request.
func TestBuildTLSConfigFilesMode(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := writeSelfSignedCert(t, dir)

	cfg := validConfig()
	cfg.StateDir = dir
	cfg.AuditLog = filepath.Join(dir, "audit.jsonl")
	cfg.SigningKey = filepath.Join(dir, "key.json")
	cfg.SigningKeyAutogen = true
	cfg.TLS = TLSConfig{CertFile: certFile, KeyFile: keyFile}

	srv, err := New(cfg, Options{AuditWriter: &bytes.Buffer{}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	tlsConf, acme, err := srv.buildTLSConfig()
	if err != nil {
		t.Fatalf("buildTLSConfig: %v", err)
	}
	if acme != nil {
		t.Fatal("files mode must not produce an acme runtime")
	}
	if len(tlsConf.Certificates) != 1 {
		t.Fatalf("expected one certificate, got %d", len(tlsConf.Certificates))
	}

	// Serve one HTTPS request through the built TLS config.
	httpsServer := httptest.NewUnstartedServer(srv.Handler())
	httpsServer.TLS = tlsConf
	httpsServer.StartTLS()
	defer httpsServer.Close()
	resp, err := httpsServer.Client().Get(httpsServer.URL + pathHealthz)
	if err != nil {
		t.Fatalf("https get: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("https healthz status %d", resp.StatusCode)
	}
}

// TestACMERuntimeNilSafe verifies the acme runtime lifecycle helpers are safe
// on the nil (tls-alpn-01 / files-mode) path, where no challenge server exists.
// The live ManageSync path is exercised only in deployment, not in unit tests
// (it would reach the ACME network).
func TestACMERuntimeNilSafe(t *testing.T) {
	var nilRT *acmeRuntime
	nilRT.start() // must not panic
	nilRT.stop(nil)

	rt := &acmeRuntime{} // tls-alpn-01: no challenge server
	rt.start()
	rt.stop(nil)
}

func writeSelfSignedCert(t *testing.T, dir string) (certFile, keyFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certFile = filepath.Join(dir, "cert.pem")
	keyFile = filepath.Join(dir, "key.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}
