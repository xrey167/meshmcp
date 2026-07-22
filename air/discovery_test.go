package air

import (
	"errors"
	"net"
	"strings"
	"testing"
)

// TestDNSRecords covers the generated ARD DNS records: a TXT pointer to the
// well-known catalog URL and an SRV for the control endpoint.
func TestDNSRecords(t *testing.T) {
	recs, err := DNSRecords("mesh.example.com", "100.64.0.2", 9600, "gateway.netbird.cloud")
	if err != nil || len(recs) != 2 {
		t.Fatalf("want 2 records, got %d (err=%v): %v", len(recs), err, recs)
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

// TestDNSRecordsSRVFallback proves the SRV target falls back to the control IP
// when no srvHost is given.
func TestDNSRecordsSRVFallback(t *testing.T) {
	recs, err := DNSRecords("x.io", "100.64.0.2", 9600, "")
	if err != nil || !strings.Contains(recs[1], "9600 100.64.0.2.") {
		t.Fatalf("SRV should fall back to the control ip: %v (err=%v)", recs, err)
	}
}

// TestDNSRecordsRejectsInjection proves a domain/host that could break the zone
// record framing (quotes, whitespace, semicolons, control chars) or an
// out-of-range port is refused rather than emitted.
func TestDNSRecordsRejectsInjection(t *testing.T) {
	bad := []struct {
		domain, ip, srv string
		port            int
	}{
		{`x.io" 300 IN TXT "evil`, "100.64.0.2", "", 9600},   // quote breaks TXT framing
		{"x.io", "100.64.0.2", "h;evil", 9600},               // semicolon starts a comment/second record
		{"x with space.io", "100.64.0.2", "", 9600},          // whitespace
		{"x.io", "100.64.0.2\nB.io. IN A 6.6.6.6", "", 9600}, // newline injects a record
		{"x.io", "100.64.0.2", "", 70000},                    // port out of range
		{"", "100.64.0.2", "", 9600},                         // empty domain
	}
	for _, c := range bad {
		if _, err := DNSRecords(c.domain, c.ip, c.port, c.srv); err == nil {
			t.Fatalf("unsafe input accepted: %+v", c)
		}
	}
}

// TestParseCatalogTXTRejectsOversized proves an absurdly long TXT value is
// rejected before it is parsed/followed.
func TestParseCatalogTXTRejectsOversized(t *testing.T) {
	huge := "v=ard1; catalog=http://x/" + strings.Repeat("a", maxCatalogURL+100)
	if _, ok := ParseCatalogTXT(huge); ok {
		t.Fatal("oversized catalog URL must be rejected")
	}
}

// TestCatalogEntry covers the name lookup helper.
func TestCatalogEntry(t *testing.T) {
	c := Catalog{Endpoints: []CatalogEntry{{Name: "fs", Address: "a:1"}, {Name: "kg", Address: "b:2"}}}
	if e, ok := c.Entry("kg"); !ok || e.Address != "b:2" {
		t.Fatalf("Entry(kg) = %+v ok=%v", e, ok)
	}
	if _, ok := c.Entry("missing"); ok {
		t.Fatal("Entry(missing) should not be found")
	}
}

// TestParseCatalogTXT covers accepting a well-formed record and rejecting
// version-less, empty, and non-http values.
func TestParseCatalogTXT(t *testing.T) {
	u, ok := ParseCatalogTXT("v=ard1; catalog=http://100.64.0.2:9600/.well-known/ai-catalog.json")
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
		if _, ok := ParseCatalogTXT(bad); ok {
			t.Fatalf("malformed TXT accepted: %q", bad)
		}
	}
	if _, ok := ParseCatalogTXT(CatalogTXTValue("https://host:1/.well-known/ai-catalog.json")); !ok {
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
	u, err := ResolveCatalogURL(lookup, "mesh.example.com")
	if err != nil || u != "http://100.64.0.2:9600/.well-known/ai-catalog.json" {
		t.Fatalf("resolve failed: %q err=%v", u, err)
	}
	if asked != "_catalog._agents.mesh.example.com" {
		t.Fatalf("looked up the wrong name: %q", asked)
	}
	if _, err := ResolveCatalogURL(func(string) ([]string, error) { return nil, errors.New("nxdomain") }, "x"); err == nil {
		t.Fatal("lookup error should propagate")
	}
	if _, err := ResolveCatalogURL(func(string) ([]string, error) { return []string{"v=spf1 -all"}, nil }, "x"); err == nil {
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
	host, port, err := ResolveCatalogSRV(lookup, "mesh.example.com")
	if err != nil || host != "gateway.netbird.cloud" || port != 9600 {
		t.Fatalf("srv resolve = %q:%d err=%v", host, port, err)
	}
	if askedSvc != "air" || askedProto != "tcp" || askedName != "mesh.example.com" {
		t.Fatalf("looked up wrong SRV: %s/%s/%s", askedSvc, askedProto, askedName)
	}
	if _, _, err := ResolveCatalogSRV(func(string, string, string) (string, []*net.SRV, error) {
		return "", nil, nil
	}, "x"); err == nil {
		t.Fatal("empty SRV set should error")
	}
	if _, _, err := ResolveCatalogSRV(func(string, string, string) (string, []*net.SRV, error) {
		return "", []*net.SRV{{Target: ".", Port: 0}}, nil
	}, "x"); err == nil {
		t.Fatal(`"." SRV target should be rejected`)
	}
}

// TestResolveCatalogPrefersTXTThenSRV proves the combined resolver uses TXT when
// present, falls back to SRV when TXT is absent, and errors when neither answers.
func TestResolveCatalogPrefersTXTThenSRV(t *testing.T) {
	txtOK := func(string) ([]string, error) {
		return []string{"v=ard1; catalog=http://100.64.0.2:9600/.well-known/ai-catalog.json"}, nil
	}
	txtMissing := func(string) ([]string, error) { return []string{"v=spf1 -all"}, nil }
	srvOK := func(string, string, string) (string, []*net.SRV, error) {
		return "", []*net.SRV{{Target: "gateway.netbird.cloud.", Port: 9600}}, nil
	}
	srvNone := func(string, string, string) (string, []*net.SRV, error) { return "", nil, nil }

	u, via, err := ResolveCatalog(txtOK, srvNone, "d")
	if err != nil || via != "TXT" || u != "http://100.64.0.2:9600/.well-known/ai-catalog.json" {
		t.Fatalf("TXT path: %q via=%q err=%v", u, via, err)
	}
	u, via, err = ResolveCatalog(txtMissing, srvOK, "d")
	if err != nil || via != "SRV" || u != "http://gateway.netbird.cloud:9600/.well-known/ai-catalog.json" {
		t.Fatalf("SRV fallback: %q via=%q err=%v", u, via, err)
	}
	if _, _, err := ResolveCatalog(txtMissing, srvNone, "d"); err == nil {
		t.Fatal("no TXT and no SRV should error")
	}
}
