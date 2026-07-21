package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/xrey167/meshmcp/policy"
)

// cmdMarket implements "meshmcp market <keygen|publish|list|verify|install>" —
// the governed plugin marketplace (F14). It is a thin flag-parsing shell over
// the signing primitive in policy (ManifestClaims / ManifestVerifier) and the
// file-backed manifestStore; all trust logic lives in the library so it is
// covered by -race tests.
func cmdMarket(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: meshmcp market <keygen|publish|list|verify|install> [flags]")
	}
	switch args[0] {
	case "keygen":
		return marketKeygen(args[1:])
	case "publish":
		return marketPublish(args[1:])
	case "list":
		return marketList(args[1:])
	case "verify":
		return marketVerify(args[1:])
	case "install":
		return marketInstall(args[1:])
	default:
		return fmt.Errorf("market: unknown subcommand %q (want keygen|publish|list|verify|install)", args[0])
	}
}

// marketKeygen mints the Ed25519 authority key a publisher signs manifests with
// and consumers pin. Same key format as `capability keygen`.
func marketKeygen(args []string) error {
	fs := flag.NewFlagSet("market keygen", flag.ContinueOnError)
	out := fs.String("out", "market-key.json", "path to write the marketplace authority key (0600)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	s, err := policy.GenerateSigner()
	if err != nil {
		return err
	}
	if err := s.SaveSigner(*out); err != nil {
		return err
	}
	fmt.Printf("wrote marketplace authority key to %s\n", *out)
	fmt.Printf("public key: %s\n", s.PubKeyHex())
	fmt.Printf("\nconsumers pin it: meshmcp market install --pubkey %s ...\n", s.PubKeyHex())
	return nil
}

// marketPublish hashes a bundle, signs a manifest for it, and writes it to the
// catalog directory (and prints the token to stdout).
func marketPublish(args []string) error {
	fs := flag.NewFlagSet("market publish", flag.ContinueOnError)
	key := fs.String("key", "", "marketplace authority key file (from `market keygen`)")
	name := fs.String("name", "", "logical bundle name")
	kind := fs.String("kind", "", "bundle kind: policy-pack|tool-backend|decision-hook|audit-sink")
	bundle := fs.String("bundle", "", "path to the bundle file to hash and bind")
	version := fs.String("bundle-version", "0.0.0", "publisher's bundle version string")
	issuer := fs.String("issuer", "", "issuer label (defaults to the authority public key)")
	summary := fs.String("summary", "", "one-line description")
	cost := fs.Int("cost", 0, "metering units charged per install (rolls up in `meshmcp budget`)")
	ttl := fs.Duration("ttl", 0, "optional expiry (0 = never expires)")
	dir := fs.String("dir", "", "catalog directory to publish into (optional; token still printed)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *key == "" || *name == "" || *kind == "" || *bundle == "" {
		return fmt.Errorf("market publish needs --key, --name, --kind, and --bundle")
	}
	signer, err := policy.LoadSigner(*key)
	if err != nil {
		return err
	}
	content, err := os.ReadFile(*bundle)
	if err != nil {
		return fmt.Errorf("read bundle: %w", err)
	}
	claims := policy.ManifestClaims{
		Issuer: *issuer, Name: *name, Kind: *kind, BundleVersion: *version,
		ContentHash: policy.HashBundle(content), Summary: *summary, Cost: *cost,
	}
	if claims.Issuer == "" {
		claims.Issuer = signer.PubKeyHex()
	}
	now := time.Now()
	if *ttl > 0 {
		claims.ExpiresAt = now.Add(*ttl).Unix()
	}
	token, err := signer.IssueManifest(claims, now)
	if err != nil {
		return err
	}
	if *dir != "" {
		store, err := newManifestStore(*dir)
		if err != nil {
			return err
		}
		if err := store.Publish(*name, token); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "published %q (%s v%s) to %s\n", *name, *kind, *version, *dir)
	}
	fmt.Fprintln(os.Stdout, token)
	return nil
}

// marketList shows the catalog. Listing is advertising, not authorizing, so it
// decodes manifests without verifying a signature (mirroring how the federation
// boundary advertises without auditing).
func marketList(args []string) error {
	fs := flag.NewFlagSet("market list", flag.ContinueOnError)
	dir := fs.String("dir", "", "catalog directory to list")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dir == "" {
		return fmt.Errorf("market list needs --dir")
	}
	store, err := newManifestStore(*dir)
	if err != nil {
		return err
	}
	tokens, err := store.List()
	if err != nil {
		return err
	}
	if len(tokens) == 0 {
		fmt.Fprintln(os.Stderr, "catalog is empty")
		return nil
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tKIND\tVERSION\tCOST\tISSUER\tID")
	for _, tok := range tokens {
		c, err := decodeManifestUnverified(tok)
		if err != nil {
			continue
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%s\t%s\n", c.Name, c.Kind, c.BundleVersion, c.Cost, shortHex(c.Issuer), c.ID)
	}
	return tw.Flush()
}

// marketVerify checks a manifest against pinned authority keys, and — when the
// bundle is provided — that the bundle bytes match the signed content hash.
func marketVerify(args []string) error {
	fs := flag.NewFlagSet("market verify", flag.ContinueOnError)
	var pubkeys stringList
	fs.Var(&pubkeys, "pubkey", "a trusted authority public key (hex); repeatable")
	manifest := fs.String("manifest", "-", "manifest token file (or '-' for stdin)")
	bundle := fs.String("bundle", "", "optional bundle file to check against the content hash")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(pubkeys) == 0 {
		return fmt.Errorf("market verify needs at least one --pubkey to pin trust")
	}
	token, err := readToken(*manifest)
	if err != nil {
		return err
	}
	v, err := policy.NewManifestVerifier(pubkeys, time.Now)
	if err != nil {
		return err
	}
	c, err := v.Verify(token)
	if err != nil {
		return fmt.Errorf("VERIFY FAILED: %w", err)
	}
	if *bundle != "" {
		content, err := os.ReadFile(*bundle)
		if err != nil {
			return fmt.Errorf("read bundle: %w", err)
		}
		if err := c.VerifyContent(policy.HashBundle(content)); err != nil {
			return fmt.Errorf("VERIFY FAILED: %w", err)
		}
	}
	fmt.Printf("OK: %q (%s v%s) signed by %s, id %s\n", c.Name, c.Kind, c.BundleVersion, shortHex(c.PubKey), c.ID)
	return nil
}

// marketInstall verifies a manifest AND its bundle, then records an audited,
// metered grant — "every install is a mintable grant and every use is
// attributable." It never loads code: the plugin is already compiled in.
func marketInstall(args []string) error {
	fs := flag.NewFlagSet("market install", flag.ContinueOnError)
	var pubkeys stringList
	fs.Var(&pubkeys, "pubkey", "a trusted authority public key (hex); repeatable")
	manifest := fs.String("manifest", "", "manifest token file")
	bundle := fs.String("bundle", "", "bundle file the manifest is bound to (required)")
	audit := fs.String("audit", "", "audit ledger to append the install grant to (required)")
	as := fs.String("as", "local", "installer identity recorded in the audit grant")
	peerKey := fs.String("peer-key", "", "installer cryptographic key (optional)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(pubkeys) == 0 || *manifest == "" || *bundle == "" || *audit == "" {
		return fmt.Errorf("market install needs --pubkey, --manifest, --bundle, and --audit")
	}
	token, err := readToken(*manifest)
	if err != nil {
		return err
	}
	v, err := policy.NewManifestVerifier(pubkeys, time.Now)
	if err != nil {
		return err
	}
	c, err := v.Verify(token)
	if err != nil {
		return fmt.Errorf("install refused: %w", err)
	}
	content, err := os.ReadFile(*bundle)
	if err != nil {
		return fmt.Errorf("read bundle: %w", err)
	}
	if err := c.VerifyContent(policy.HashBundle(content)); err != nil {
		return fmt.Errorf("install refused: %w", err)
	}
	f, err := os.OpenFile(*audit, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	log := policy.NewAuditLog(f, func() string { return time.Now().UTC().Format(time.RFC3339) })
	if err := recordInstall(log, *as, *peerKey, c); err != nil {
		return fmt.Errorf("record install grant: %w", err)
	}
	fmt.Printf("installed %q (%s v%s), %d unit(s) charged to %s — grant %s recorded in %s\n",
		c.Name, c.Kind, c.BundleVersion, c.Cost, *as, c.ID, *audit)
	return nil
}

// decodeManifestUnverified decodes a manifest token for display WITHOUT checking
// its signature — for listing only; never trust these fields for admission.
func decodeManifestUnverified(token string) (policy.ManifestClaims, error) {
	var c policy.ManifestClaims
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(token))
	if err != nil {
		return c, err
	}
	err = json.Unmarshal(raw, &c)
	return c, err
}

// readToken reads a manifest token from a file, or stdin when path is "-".
func readToken(path string) (string, error) {
	if path == "-" {
		b, err := os.ReadFile("/dev/stdin")
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(b)), nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

// shortHex abbreviates a long hex identity for display.
func shortHex(s string) string {
	if len(s) <= 12 {
		return s
	}
	return s[:12] + "…"
}
