package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
)

// This is meshmcp's DNS profile for Agentic Resource Discovery (ARD legs 2–3):
// a peer that knows only a domain name can find a gateway's Air catalog from a
// DNS record, without being told the control address. meshmcp does not run DNS
// — an operator publishes the records `air dns` prints, and `air catalog
// --resolve <domain>` follows them. The pointer is a public-ish DNS record; the
// catalog it points to is still mesh-only and identity-gated (leg 1). The two
// records mirror the ARD toolkit's `_catalog._agents` (TXT) and an SRV leg.

// ardTXTName / ardSRVName are the ARD-profile record names under a domain.
func ardTXTName(domain string) string { return "_catalog._agents." + strings.Trim(domain, ".") }
func ardSRVName(domain string) string { return "_air._tcp." + strings.Trim(domain, ".") }

// catalogTXTValue builds the TXT record value that points at a catalog URL,
// tagged with the profile version so a resolver can validate what it parses.
func catalogTXTValue(catalogURL string) string {
	return "v=ard1; catalog=" + catalogURL
}

// parseCatalogTXT extracts the catalog URL from a `v=ard1; catalog=<url>` TXT
// value. It requires the version tag and an absolute http(s) URL, so a stray or
// malformed record is rejected rather than followed.
func parseCatalogTXT(txt string) (string, bool) {
	var version, catalog string
	for _, part := range strings.Split(txt, ";") {
		part = strings.TrimSpace(part)
		if v, ok := strings.CutPrefix(part, "v="); ok {
			version = v
		} else if c, ok := strings.CutPrefix(part, "catalog="); ok {
			catalog = c
		}
	}
	if version != "ard1" || catalog == "" {
		return "", false
	}
	u, err := url.Parse(catalog)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", false
	}
	return catalog, true
}

// airDNSRecords returns the DNS records an operator publishes so ARD-aware
// clients discover this gateway's catalog from `domain` alone: a TXT pointer to
// the well-known catalog URL and an SRV for the Air control endpoint. controlIP
// / controlPort address the gateway's control endpoint on the mesh; srvHost is
// the gateway's mesh FQDN (falls back to controlIP when empty).
func airDNSRecords(domain, controlIP string, controlPort int, srvHost string) []string {
	catalogURL := fmt.Sprintf("http://%s:%d%s", controlIP, controlPort, airCatalogPath)
	if srvHost == "" {
		srvHost = controlIP
	}
	return []string{
		fmt.Sprintf(`%s. 300 IN TXT "%s"`, ardTXTName(domain), catalogTXTValue(catalogURL)),
		fmt.Sprintf(`%s. 300 IN SRV 0 5 %d %s.`, ardSRVName(domain), controlPort, strings.Trim(srvHost, ".")),
	}
}

// txtLookup resolves TXT records for a name; injectable so resolveCatalogURL is
// testable offline. The default is the OS resolver (which on the mesh honours
// the mesh's DNS).
type txtLookup func(name string) ([]string, error)

// resolveCatalogURL follows ARD leg 2: resolve the domain's `_catalog._agents`
// TXT record and return the catalog URL it points to. A missing or malformed
// record is an error, never a silent fallback.
func resolveCatalogURL(lookup txtLookup, domain string) (string, error) {
	name := ardTXTName(domain)
	records, err := lookup(name)
	if err != nil {
		return "", fmt.Errorf("resolve %s: %w", name, err)
	}
	for _, txt := range records {
		if u, ok := parseCatalogTXT(txt); ok {
			return u, nil
		}
	}
	return "", fmt.Errorf("no ARD catalog TXT record at %s", name)
}

// cmdAirDNS prints the DNS records an operator publishes so a gateway's Air
// catalog is discoverable from a domain name (ARD legs 2–3).
func cmdAirDNS(args []string) error {
	fs := flag.NewFlagSet("air dns", flag.ExitOnError)
	control := fs.String("control", "", "the gateway's control endpoint on the mesh (mesh-ip:port)")
	srvHost := fs.String("srv-host", "", "the gateway's mesh FQDN for the SRV target (default: the control ip)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: meshmcp air dns <domain> --control <mesh-ip:port> [--srv-host fqdn]")
	}
	domain := fs.Arg(0)
	if *control == "" {
		return errors.New("air dns: --control <mesh-ip:port> is required")
	}
	host, portStr, err := net.SplitHostPort(*control)
	if err != nil {
		return fmt.Errorf("air dns: bad --control %q: %w", *control, err)
	}
	port, err := net.LookupPort("tcp", portStr)
	if err != nil {
		return fmt.Errorf("air dns: bad port in --control %q: %w", *control, err)
	}
	fmt.Fprintln(os.Stderr, dim("# publish these records so `air catalog --resolve "+domain+"` finds this gateway:"))
	for _, rec := range airDNSRecords(domain, host, port, *srvHost) {
		fmt.Println(rec)
	}
	return nil
}
