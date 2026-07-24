package edge

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"time"

	"github.com/caddyserver/certmagic"
)

// acmeRuntime holds the pieces an ACME-mode edge needs beyond the TLS config:
// the certmagic config (for management) and, in http-01 mode, the challenge
// HTTP server that must run on the challenge port for the lifetime of the edge.
type acmeRuntime struct {
	issuer       *certmagic.ACMEIssuer
	httpChallSrv *http.Server // non-nil only in http-01 mode
}

// buildACMETLSConfig configures certmagic with an explicit config (never the
// package globals), obtains/loads the certificate synchronously, and returns a
// ready *tls.Config. ManageSync failing is fatal at startup — the edge never
// starts with a lazy first-handshake certificate error.
func (s *Server) buildACMETLSConfig() (*tls.Config, *acmeRuntime, error) {
	ac := s.cfg.TLS.ACME
	cacheDir := ac.CacheDir
	if cacheDir == "" {
		cacheDir = filepath.Join(s.cfg.StateDir, "acme")
	}

	var cfg *certmagic.Config
	cache := certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: func(certmagic.Certificate) (*certmagic.Config, error) {
			return cfg, nil
		},
	})
	cfg = certmagic.New(cache, certmagic.Config{
		Storage: &certmagic.FileStorage{Path: cacheDir},
	})

	ca := ac.CA
	if ca == "" {
		ca = certmagic.LetsEncryptProductionCA
	}
	issuer := certmagic.NewACMEIssuer(cfg, certmagic.ACMEIssuer{
		CA:                      ca,
		Email:                   ac.Email,
		Agreed:                  true,
		DisableHTTPChallenge:    ac.Challenge != ChallengeHTTP01,
		DisableTLSALPNChallenge: ac.Challenge != ChallengeTLSALPN01,
		AltHTTPPort:             ac.HTTPPort,
	})
	cfg.Issuers = []certmagic.Issuer{issuer}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := cfg.ManageSync(ctx, ac.Domains); err != nil {
		return nil, nil, fmt.Errorf("edge: acme certificate management for %v failed at startup: %w", ac.Domains, err)
	}

	tlsConf := cfg.TLSConfig()
	tlsConf.MinVersion = tls.VersionTLS12
	// Ensure ALPN advertises HTTP as well as the acme-tls/1 protocol certmagic adds.
	tlsConf.NextProtos = appendUnique(tlsConf.NextProtos, "h2", "http/1.1")

	rt := &acmeRuntime{issuer: issuer}
	if ac.Challenge == ChallengeHTTP01 {
		rt.httpChallSrv = &http.Server{
			Addr:              fmt.Sprintf(":%d", ac.HTTPPort),
			Handler:           issuer.HTTPChallengeHandler(http.HandlerFunc(http.NotFound)),
			ReadHeaderTimeout: 10 * time.Second,
		}
	}
	return tlsConf, rt, nil
}

// buildBeaconACMETLSConfig provisions the gateway's certificate for its derived
// public name via ACME DNS-01, brokered through the beacon: the injected
// dns01Provider publishes the challenge TXT over the tunnel and the beacon's
// authoritative DNS serves it, so NO inbound challenge port is opened. The
// certificate for cfg.PublicURL's host is obtained synchronously at startup
// (fatal on failure — never a lazy first-handshake error).
func (s *Server) buildBeaconACMETLSConfig() (*tls.Config, *acmeRuntime, error) {
	ac := s.cfg.Beacon.AutoCert
	if s.dns01Provider == nil {
		return nil, nil, fmt.Errorf("edge: beacon.auto_cert requires a DNS-01 provider (internal wiring error)")
	}
	pu, err := url.Parse(s.cfg.PublicURL)
	if err != nil || pu.Hostname() == "" {
		return nil, nil, fmt.Errorf("edge: beacon public_url %q is not a valid URL: %w", s.cfg.PublicURL, err)
	}
	host := pu.Hostname()

	cacheDir := ac.CacheDir
	if cacheDir == "" {
		cacheDir = filepath.Join(s.cfg.StateDir, "acme")
	}

	var cfg *certmagic.Config
	cache := certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: func(certmagic.Certificate) (*certmagic.Config, error) { return cfg, nil },
	})
	cfg = certmagic.New(cache, certmagic.Config{
		Storage: &certmagic.FileStorage{Path: cacheDir},
	})

	ca := ac.CA
	if ca == "" {
		ca = certmagic.LetsEncryptProductionCA
	}
	issuer := certmagic.NewACMEIssuer(cfg, certmagic.ACMEIssuer{
		CA:     ca,
		Email:  ac.Email,
		Agreed: true,
		// DNS-01 only: no inbound challenge port on the gateway.
		DisableHTTPChallenge:    true,
		DisableTLSALPNChallenge: true,
		DNS01Solver: &certmagic.DNS01Solver{
			DNSManager: certmagic.DNSManager{DNSProvider: s.dns01Provider},
		},
	})
	cfg.Issuers = []certmagic.Issuer{issuer}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	if err := cfg.ManageSync(ctx, []string{host}); err != nil {
		return nil, nil, fmt.Errorf("edge: beacon ACME DNS-01 provisioning for %s failed at startup: %w", host, err)
	}

	tlsConf := cfg.TLSConfig()
	tlsConf.MinVersion = tls.VersionTLS12
	tlsConf.NextProtos = appendUnique(tlsConf.NextProtos, "h2", "http/1.1")
	return tlsConf, &acmeRuntime{issuer: issuer}, nil
}

// start launches any auxiliary listeners (the http-01 challenge server). It is
// a no-op in tls-alpn-01 mode.
func (rt *acmeRuntime) start() {
	if rt == nil || rt.httpChallSrv == nil {
		return
	}
	go func() { _ = rt.httpChallSrv.ListenAndServe() }()
}

// stop shuts down auxiliary listeners.
func (rt *acmeRuntime) stop(ctx context.Context) {
	if rt == nil || rt.httpChallSrv == nil {
		return
	}
	_ = rt.httpChallSrv.Shutdown(ctx)
}

func appendUnique(base []string, add ...string) []string {
	seen := map[string]bool{}
	for _, b := range base {
		seen[b] = true
	}
	out := append([]string(nil), base...)
	for _, a := range add {
		if !seen[a] {
			out = append(out, a)
			seen[a] = true
		}
	}
	return out
}
