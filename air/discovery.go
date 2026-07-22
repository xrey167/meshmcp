package air

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// This file is meshmcp's DNS profile for Agentic Resource Discovery (ARD legs
// 2–3): a peer that knows only a domain name can find a gateway's Air catalog
// from a DNS record, without being told the control address. meshmcp does not
// run DNS — an operator publishes the records DNSRecords prints, and
// ResolveCatalog follows them. The pointer is a public-ish DNS record; the
// catalog it points to is still mesh-only and identity-gated (leg 1). The two
// records mirror the ARD toolkit's `_catalog._agents` (TXT) and an SRV leg.

// TXTName / SRVName are the ARD-profile record names under a domain.
func TXTName(domain string) string { return "_catalog._agents." + strings.Trim(domain, ".") }
func SRVName(domain string) string { return "_air._tcp." + strings.Trim(domain, ".") }

// ARDVersion is the meshmcp ARD profile version, tagged into the TXT record so
// a resolver can validate the profile it parses.
const ARDVersion = "ard1"

// maxCatalogURL bounds the catalog URL a TXT record may carry — a hostile or
// corrupt record cannot make a resolver buffer an unbounded string.
const maxCatalogURL = 2048

// CatalogTXTValue builds the TXT record value that points at a catalog URL,
// tagged with the profile version so a resolver can validate what it parses.
func CatalogTXTValue(catalogURL string) string {
	return "v=" + ARDVersion + "; catalog=" + catalogURL
}

// dnsRecordSafe reports whether s can be placed into a zone-file record without
// breaking its framing or injecting a second record — no quotes, semicolons,
// whitespace, or control characters. Used to validate the operator-supplied
// domain and hosts before DNSRecords emits them.
func dnsRecordSafe(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f || r == '"' || r == ';' || r == ' ' || r == '\t' {
			return false
		}
	}
	return true
}

// ParseCatalogTXT extracts the catalog URL from a `v=ard1; catalog=<url>` TXT
// value. It requires the version tag and an absolute http(s) URL of bounded
// length, so a stray, oversized, or malformed record is rejected rather than
// followed.
func ParseCatalogTXT(txt string) (string, bool) {
	if len(txt) > maxCatalogURL+64 { // version tag + url, generously
		return "", false
	}
	var version, catalog string
	for _, part := range strings.Split(txt, ";") {
		part = strings.TrimSpace(part)
		if v, ok := strings.CutPrefix(part, "v="); ok {
			version = v
		} else if c, ok := strings.CutPrefix(part, "catalog="); ok {
			catalog = c
		}
	}
	if version != ARDVersion || catalog == "" || len(catalog) > maxCatalogURL {
		return "", false
	}
	u, err := url.Parse(catalog)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", false
	}
	return catalog, true
}

// DNSRecords returns the DNS records an operator publishes so ARD-aware clients
// discover this gateway's catalog from `domain` alone: a TXT pointer to the
// well-known catalog URL and an SRV for the Air control endpoint. controlIP /
// controlPort address the gateway's control endpoint on the mesh; srvHost is
// the gateway's mesh FQDN (falls back to controlIP when empty). The domain and
// hosts are validated so a value containing quotes/whitespace/semicolons cannot
// break the zone-record framing or inject a second record.
func DNSRecords(domain, controlIP string, controlPort int, srvHost string) ([]string, error) {
	if controlPort <= 0 || controlPort > 65535 {
		return nil, fmt.Errorf("air: control port %d out of range", controlPort)
	}
	if srvHost == "" {
		srvHost = controlIP
	}
	for _, v := range []string{domain, controlIP, srvHost} {
		if !dnsRecordSafe(v) {
			return nil, fmt.Errorf("air: %q is not safe for a DNS record (no quotes, whitespace, semicolons, or control chars)", v)
		}
	}
	catalogURL := fmt.Sprintf("http://%s:%d%s", controlIP, controlPort, CatalogPath)
	return []string{
		fmt.Sprintf(`%s. 300 IN TXT "%s"`, TXTName(domain), CatalogTXTValue(catalogURL)),
		fmt.Sprintf(`%s. 300 IN SRV 0 5 %d %s.`, SRVName(domain), controlPort, strings.Trim(srvHost, ".")),
	}, nil
}

// TXTLookup resolves TXT records for a name; injectable so ResolveCatalogURL is
// testable offline. The default is net.LookupTXT (the OS/mesh resolver).
type TXTLookup func(name string) ([]string, error)

// SRVLookup resolves SRV records for a service; injectable so ResolveCatalogSRV
// is testable offline. The default is net.LookupSRV.
type SRVLookup func(service, proto, name string) (string, []*net.SRV, error)

// ResolveCatalogURL follows ARD leg 2: resolve the domain's `_catalog._agents`
// TXT record and return the catalog URL it points to. A missing or malformed
// record is an error, never a silent fallback.
func ResolveCatalogURL(lookup TXTLookup, domain string) (string, error) {
	name := TXTName(domain)
	records, err := lookup(name)
	if err != nil {
		return "", fmt.Errorf("resolve %s: %w", name, err)
	}
	for _, txt := range records {
		if u, ok := ParseCatalogTXT(txt); ok {
			return u, nil
		}
	}
	return "", fmt.Errorf("no ARD catalog TXT record at %s", name)
}

// ResolveCatalogSRV follows ARD leg 3: resolve the domain's `_air._tcp` SRV
// record and return the highest-priority target host:port of the control
// endpoint. The caller constructs the well-known catalog URL from it.
func ResolveCatalogSRV(lookup SRVLookup, domain string) (host string, port int, err error) {
	name := SRVName(domain)
	_, addrs, err := lookup("air", "tcp", strings.Trim(domain, "."))
	if err != nil {
		return "", 0, fmt.Errorf("resolve %s: %w", name, err)
	}
	if len(addrs) == 0 {
		return "", 0, fmt.Errorf("no SRV records at %s", name)
	}
	// net.LookupSRV returns records sorted by priority then weight; take the
	// first. A "." target is the RFC 2782 "service decidedly not available".
	a := addrs[0]
	target := strings.TrimSuffix(a.Target, ".")
	if target == "" || a.Target == "." {
		return "", 0, fmt.Errorf("SRV at %s has no usable target", name)
	}
	return target, int(a.Port), nil
}

// maxCatalogBody bounds a catalog response the client will buffer, so a hostile
// or misbehaving endpoint cannot force an unbounded read.
const maxCatalogBody = 1 << 20

// FetchCatalog fetches and parses a gateway's Air catalog from url using the
// given HTTP client — the caller wires the client to the mesh (or a test
// server), keeping this function transport-agnostic. It returns the parsed
// catalog and the raw response bytes (for a pass-through --json view). A non-200
// status or an unparseable body is an error; the body is length-bounded.
func FetchCatalog(hc *http.Client, url string) (Catalog, []byte, error) {
	resp, err := hc.Get(url)
	if err != nil {
		return Catalog{}, nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxCatalogBody))
	if resp.StatusCode != http.StatusOK {
		return Catalog{}, body, fmt.Errorf("%s: %s", resp.Status, bytes.TrimSpace(body))
	}
	var cat Catalog
	if err := json.Unmarshal(body, &cat); err != nil {
		return Catalog{}, body, fmt.Errorf("bad catalog response: %w", err)
	}
	normalized, err := cat.Normalized()
	if err != nil {
		return Catalog{}, body, fmt.Errorf("invalid catalog response: %w", err)
	}
	return normalized, body, nil
}

// ResolveCatalog performs ARD discovery from a domain: the TXT pointer (leg 2)
// is tried first because it carries the full catalog URL; if there is no TXT
// record it falls back to the SRV record (leg 3), building the well-known
// catalog URL from the resolved host:port. `via` reports which leg answered.
func ResolveCatalog(txt TXTLookup, srv SRVLookup, domain string) (catalogURL, via string, err error) {
	if u, e := ResolveCatalogURL(txt, domain); e == nil {
		return u, "TXT", nil
	}
	host, port, e := ResolveCatalogSRV(srv, domain)
	if e != nil {
		return "", "", fmt.Errorf("no ARD discovery record for %s (TXT and SRV both failed): %w", domain, e)
	}
	return fmt.Sprintf("http://%s:%d%s", host, port, CatalogPath), "SRV", nil
}
