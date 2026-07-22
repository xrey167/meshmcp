package main

import (
	"errors"
	"strings"
	"testing"
)

// TestAirDNSRecords covers the generated ARD DNS records: a TXT pointer to the
// well-known catalog URL and an SRV for the control endpoint.
func TestAirDNSRecords(t *testing.T) {
	recs := airDNSRecords("mesh.example.com", "100.64.0.2", 9600, "gateway.netbird.cloud")
	if len(recs) != 2 {
		t.Fatalf("want 2 records, got %d: %v", len(recs), recs)
	}
	txt, srv := recs[0], recs[1]
	if !strings.HasPrefix(txt, "_catalog._agents.mesh.example.com. ") || !strings.Contains(txt, "IN TXT") {
		t.Fatalf("bad TXT record: %q", txt)
	}
	if !strings.Contains(txt, "v=ard1; catalog=http://100.64.0.2:9600/.well-known/ai-catalog.json") {
		t.Fatalf("TXT missing catalog url: %q", txt)
	}
	if !strings.HasPrefix(srv, "_air._tcp.mesh.example.com. ") || !strings.Contains(srv, "IN SRV 0 5 9600 gateway.netbird.cloud.") {
		t.Fatalf("bad SRV record: %q", srv)
	}
}

// TestAirDNSRecordsSRVFallback proves the SRV target falls back to the control
// IP when no --srv-host is given.
func TestAirDNSRecordsSRVFallback(t *testing.T) {
	recs := airDNSRecords("x.io", "100.64.0.2", 9600, "")
	if !strings.Contains(recs[1], "9600 100.64.0.2.") {
		t.Fatalf("SRV should fall back to the control ip: %q", recs[1])
	}
}

// TestParseCatalogTXT covers accepting a well-formed record and rejecting
// version-less, empty, and non-http values.
func TestParseCatalogTXT(t *testing.T) {
	u, ok := parseCatalogTXT("v=ard1; catalog=http://100.64.0.2:9600/.well-known/ai-catalog.json")
	if !ok || u != "http://100.64.0.2:9600/.well-known/ai-catalog.json" {
		t.Fatalf("valid TXT not parsed: %q ok=%v", u, ok)
	}
	for _, bad := range []string{
		"catalog=http://x/y",         // no version
		"v=ard1;",                    // no catalog
		"v=ard2; catalog=http://x/y", // wrong version
		"v=ard1; catalog=ftp://x/y",  // non-http scheme
		"v=ard1; catalog=not-a-url",  // no host/scheme
		"random text",                // junk
	} {
		if _, ok := parseCatalogTXT(bad); ok {
			t.Fatalf("malformed TXT accepted: %q", bad)
		}
	}
	// Round-trips with the builder.
	if _, ok := parseCatalogTXT(catalogTXTValue("https://host:1/.well-known/ai-catalog.json")); !ok {
		t.Fatal("builder output must parse")
	}
}

// TestResolveCatalogURL covers resolution over an injected lookup: it picks the
// valid record among decoys, and errors on missing / all-malformed records.
func TestResolveCatalogURL(t *testing.T) {
	var asked string
	lookup := func(name string) ([]string, error) {
		asked = name
		return []string{"some other txt", "v=ard1; catalog=http://100.64.0.2:9600/.well-known/ai-catalog.json"}, nil
	}
	u, err := resolveCatalogURL(lookup, "mesh.example.com")
	if err != nil || u != "http://100.64.0.2:9600/.well-known/ai-catalog.json" {
		t.Fatalf("resolve failed: %q err=%v", u, err)
	}
	if asked != "_catalog._agents.mesh.example.com" {
		t.Fatalf("looked up the wrong name: %q", asked)
	}

	// A lookup error propagates.
	if _, err := resolveCatalogURL(func(string) ([]string, error) { return nil, errors.New("nxdomain") }, "x"); err == nil {
		t.Fatal("lookup error should propagate")
	}
	// No ARD record among the results is an error, not a silent empty.
	if _, err := resolveCatalogURL(func(string) ([]string, error) { return []string{"v=spf1 -all"}, nil }, "x"); err == nil {
		t.Fatal("missing ARD record should error")
	}
}
