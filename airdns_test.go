package main

import (
	"errors"
	"net"
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

// TestResolveCatalogSRV covers SRV resolution: the highest-priority target's
// host:port is returned, and empty/"." targets and lookup errors are rejected.
func TestResolveCatalogSRV(t *testing.T) {
	var askedSvc, askedProto, askedName string
	lookup := func(service, proto, name string) (string, []*net.SRV, error) {
		askedSvc, askedProto, askedName = service, proto, name
		return "", []*net.SRV{
			{Target: "gateway.netbird.cloud.", Port: 9600, Priority: 0, Weight: 5},
			{Target: "backup.netbird.cloud.", Port: 9600, Priority: 10, Weight: 5},
		}, nil
	}
	host, port, err := resolveCatalogSRV(lookup, "mesh.example.com")
	if err != nil || host != "gateway.netbird.cloud" || port != 9600 {
		t.Fatalf("srv resolve = %q:%d err=%v", host, port, err)
	}
	if askedSvc != "air" || askedProto != "tcp" || askedName != "mesh.example.com" {
		t.Fatalf("looked up wrong SRV: %s/%s/%s", askedSvc, askedProto, askedName)
	}

	// No records is an error.
	if _, _, err := resolveCatalogSRV(func(string, string, string) (string, []*net.SRV, error) {
		return "", nil, nil
	}, "x"); err == nil {
		t.Fatal("empty SRV set should error")
	}
	// A "." target (RFC 2782 "not available") is rejected.
	if _, _, err := resolveCatalogSRV(func(string, string, string) (string, []*net.SRV, error) {
		return "", []*net.SRV{{Target: ".", Port: 0}}, nil
	}, "x"); err == nil {
		t.Fatal(`"." SRV target should be rejected`)
	}
}

// TestResolveCatalogPrefersTXTThenSRV proves the combined resolver uses the TXT
// pointer when present, falls back to SRV when TXT is absent, and errors when
// neither answers.
func TestResolveCatalogPrefersTXTThenSRV(t *testing.T) {
	txtOK := func(string) ([]string, error) {
		return []string{"v=ard1; catalog=http://100.64.0.2:9600/.well-known/ai-catalog.json"}, nil
	}
	txtMissing := func(string) ([]string, error) { return []string{"v=spf1 -all"}, nil }
	srvOK := func(string, string, string) (string, []*net.SRV, error) {
		return "", []*net.SRV{{Target: "gateway.netbird.cloud.", Port: 9600}}, nil
	}
	srvNone := func(string, string, string) (string, []*net.SRV, error) { return "", nil, nil }

	// TXT present → via TXT, full URL from the record.
	u, via, err := resolveCatalog(txtOK, srvNone, "d")
	if err != nil || via != "TXT" || u != "http://100.64.0.2:9600/.well-known/ai-catalog.json" {
		t.Fatalf("TXT path: %q via=%q err=%v", u, via, err)
	}
	// TXT absent → fall back to SRV, URL built from host:port.
	u, via, err = resolveCatalog(txtMissing, srvOK, "d")
	if err != nil || via != "SRV" || u != "http://gateway.netbird.cloud:9600/.well-known/ai-catalog.json" {
		t.Fatalf("SRV fallback: %q via=%q err=%v", u, via, err)
	}
	// Neither → error.
	if _, _, err := resolveCatalog(txtMissing, srvNone, "d"); err == nil {
		t.Fatal("no TXT and no SRV should error")
	}
}
