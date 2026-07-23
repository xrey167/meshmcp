package edge

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
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
