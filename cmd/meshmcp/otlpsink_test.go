package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/xrey167/meshmcp/policy"
)

// otlpTestSink builds a sink against srvURL with fast test timings.
func otlpTestSink(srvURL string, all bool, batch int) *otlpSink {
	return newOTLPSink(&AuditOTLPConfig{
		Endpoint:             srvURL,
		All:                  all,
		BatchSize:            batch,
		FlushIntervalSeconds: 1,
		TimeoutSeconds:       2,
		QueueSize:            16,
	}, "test-version")
}

// decodeOTLP unmarshals a request body into a generic map so the test asserts
// the EXACT wire shape (camelCase keys, int64-as-string) a collector requires.
func decodeOTLP(t *testing.T, body []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("export body is not JSON: %v\n%s", err, body)
	}
	return m
}

func otlpPath(t *testing.T, m map[string]any, keys ...string) any {
	t.Helper()
	var cur any = m
	for _, k := range keys {
		switch v := cur.(type) {
		case map[string]any:
			cur = v[k]
		case []any:
			cur = v[0].(map[string]any)[k]
		default:
			t.Fatalf("path %v: unexpected node %T", keys, cur)
		}
	}
	return cur
}

func otlpAttrs(t *testing.T, node any) map[string]map[string]any {
	t.Helper()
	list, ok := node.([]any)
	if !ok {
		t.Fatalf("attributes are not a list: %T", node)
	}
	out := map[string]map[string]any{}
	for _, a := range list {
		kv := a.(map[string]any)
		out[kv["key"].(string)] = kv["value"].(map[string]any)
	}
	return out
}

// TestOTLPSinkExportsSchemaAndBatches proves N appended records arrive as ONE
// OTLP/HTTP JSON POST whose schema-critical fields are exactly what the OTLP
// spec's JSON encoding requires: camelCase keys, timeUnixNano/seq as STRING
// integers, severityNumber as an int enum — and that in default (deny/cosign
// only) mode an allow record is filtered out.
func TestOTLPSinkExportsSchemaAndBatches(t *testing.T) {
	bodies := make(chan []byte, 4)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/logs" {
			t.Errorf("expected POST /v1/logs, got %s", r.URL.Path)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("expected application/json, got %q", ct)
		}
		b, _ := io.ReadAll(r.Body)
		bodies <- b
		w.Write([]byte(`{"partialSuccess":{}}`))
	}))
	defer srv.Close()

	sink := otlpTestSink(srv.URL, false /* deny/cosign only */, 2)
	defer sink.Close()
	_ = sink.Append(policy.AuditRecord{Decision: "allow", Tool: "read"}) // filtered
	_ = sink.Append(policy.AuditRecord{
		Time: "2026-07-23T10:00:00Z", Backend: "payments", Peer: "agent.mesh",
		PeerKey: "PK", Method: "tools/call", Tool: "deploy", RPCID: "42",
		Decision: "deny", Reason: "no matching rule", Rule: -1,
		Seq: 7, PrevHash: "aa", Hash: "bb",
		PeerSpiffeID: "spiffe://mesh.example.org/peer/PK",
	})
	_ = sink.Append(policy.AuditRecord{
		Time: "2026-07-23T10:00:01Z", Backend: "payments", Tool: "refund",
		Decision: "cosign", Reason: "requires co-sign", Rule: 2, Seq: 8, Cost: 5,
	})

	var body []byte
	select {
	case body = <-bodies:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for the OTLP export")
	}

	m := decodeOTLP(t, body)
	// Resource + scope.
	resAttrs := otlpAttrs(t, otlpPath(t, m, "resourceLogs", "resource", "attributes"))
	if *strOf(t, resAttrs["service.name"]) != "meshmcp" || *strOf(t, resAttrs["service.version"]) != "test-version" {
		t.Fatalf("resource attributes wrong: %v", resAttrs)
	}
	if got := otlpPath(t, m, "resourceLogs", "scopeLogs", "scope", "name"); got != "meshmcp/audit" {
		t.Fatalf("scope name = %v", got)
	}
	// Batching: both surviving records in ONE request.
	logRecords := otlpPath(t, m, "resourceLogs", "scopeLogs", "logRecords").([]any)
	if len(logRecords) != 2 {
		t.Fatalf("expected 2 logRecords in one POST, got %d", len(logRecords))
	}
	lr := logRecords[0].(map[string]any)
	// timeUnixNano must be a STRING of digits (int64-as-string rule).
	tun, ok := lr["timeUnixNano"].(string)
	if !ok || !regexp.MustCompile(`^\d+$`).MatchString(tun) {
		t.Fatalf("timeUnixNano must be a digit string, got %#v", lr["timeUnixNano"])
	}
	want := time.Date(2026, 7, 23, 10, 0, 0, 0, time.UTC).UnixNano()
	if tun != "1784887200000000000" && tun != jsonInt(want) {
		t.Fatalf("timeUnixNano = %s, want %d", tun, want)
	}
	if n := lr["severityNumber"].(float64); n != 17 {
		t.Fatalf("deny severityNumber = %v, want 17", n)
	}
	if lr["severityText"] != "deny" {
		t.Fatalf("severityText = %v", lr["severityText"])
	}
	if got := lr["body"].(map[string]any)["stringValue"]; got != "no matching rule" {
		t.Fatalf("body = %v", got)
	}
	attrs := otlpAttrs(t, lr["attributes"])
	for k, want := range map[string]string{
		"backend": "payments", "peer": "agent.mesh", "peer_key": "PK",
		"method": "tools/call", "tool": "deploy", "rpc_id": "42",
		"decision": "deny", "hash": "bb", "prev_hash": "aa",
		"peer_spiffe_id": "spiffe://mesh.example.org/peer/PK",
	} {
		if got := strOf(t, attrs[k]); got == nil || *got != want {
			t.Fatalf("attribute %q = %v, want %q", k, attrs[k], want)
		}
	}
	// int attributes ride as intValue STRINGS.
	if got := attrs["seq"]["intValue"]; got != "7" {
		t.Fatalf(`seq intValue = %#v, want "7"`, got)
	}
	if got := attrs["rule"]["intValue"]; got != "-1" {
		t.Fatalf(`rule intValue = %#v, want "-1"`, got)
	}
	// Second record: cosign severity + cost attribute.
	lr2 := logRecords[1].(map[string]any)
	if n := lr2["severityNumber"].(float64); n != 13 {
		t.Fatalf("cosign severityNumber = %v, want 13", n)
	}
	if got := otlpAttrs(t, lr2["attributes"])["cost"]["intValue"]; got != "5" {
		t.Fatalf(`cost intValue = %#v, want "5"`, got)
	}
	// The filtered allow record must not produce a second request.
	select {
	case extra := <-bodies:
		t.Fatalf("unexpected second export: %s", extra)
	case <-time.After(300 * time.Millisecond):
	}
}

func strOf(t *testing.T, v map[string]any) *string {
	t.Helper()
	if v == nil {
		return nil
	}
	s, ok := v["stringValue"].(string)
	if !ok {
		return nil
	}
	return &s
}

func jsonInt(v int64) string { b, _ := json.Marshal(v); return string(b) }

// TestOTLPSeverityMapping documents the decision→severity mapping:
// allow → INFO(9), cosign → WARN(13), deny → ERROR(17).
func TestOTLPSeverityMapping(t *testing.T) {
	for decision, want := range map[string]int{"allow": 9, "cosign": 13, "deny": 17, "": 9} {
		lr := otlpLogRecordFrom(policy.AuditRecord{Decision: decision}, time.Now)
		if lr.SeverityNumber != want {
			t.Fatalf("%q → severityNumber %d, want %d", decision, lr.SeverityNumber, want)
		}
		if lr.SeverityText != decision {
			t.Fatalf("%q → severityText %q", decision, lr.SeverityText)
		}
	}
}

// TestOTLPSpiffeAttributeElidedWhenUnset proves peer_spiffe_id appears only
// when the record carries the label.
func TestOTLPSpiffeAttributeElidedWhenUnset(t *testing.T) {
	lr := otlpLogRecordFrom(policy.AuditRecord{Decision: "deny"}, time.Now)
	for _, a := range lr.Attributes {
		if a.Key == "peer_spiffe_id" {
			t.Fatal("peer_spiffe_id must be elided when the record has no label")
		}
	}
	lr = otlpLogRecordFrom(policy.AuditRecord{Decision: "deny", PeerSpiffeID: "spiffe://d/peer/k"}, time.Now)
	found := false
	for _, a := range lr.Attributes {
		if a.Key == "peer_spiffe_id" {
			found = true
		}
	}
	if !found {
		t.Fatal("peer_spiffe_id attribute missing when the record carries the label")
	}
}

// TestOTLPSinkDropsNotBlocks proves the observer contract: with the collector
// stalled and the queue full, Append stays fast (drop, never block) and drops
// are counted.
func TestOTLPSinkDropsNotBlocks(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release // stalled collector
	}))
	defer srv.Close()
	defer close(release)

	sink := newOTLPSink(&AuditOTLPConfig{
		Endpoint:             srv.URL,
		All:                  true,
		BatchSize:            1, // worker POSTs (and stalls) immediately
		FlushIntervalSeconds: 1,
		TimeoutSeconds:       1,
		QueueSize:            4,
	}, "v")

	start := time.Now()
	for i := 0; i < 5000; i++ {
		_ = sink.Append(policy.AuditRecord{Decision: "deny", Seq: i})
	}
	elapsed := time.Since(start)
	if elapsed > 500*time.Millisecond {
		t.Fatalf("5000 Appends against a stalled collector took %s — Append must never block", elapsed)
	}
	if sink.Dropped() == 0 {
		t.Fatal("expected dropped records with a stalled collector and a full queue")
	}
	sink.Close()
}

// TestOTLPSinkHeaderInjectionFromEnv proves extra headers (e.g. Authorization)
// come from a NAMED env var — the value never lives in config.
func TestOTLPSinkHeaderInjectionFromEnv(t *testing.T) {
	got := make(chan http.Header, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got <- r.Header.Clone()
	}))
	defer srv.Close()

	t.Setenv("MESHMCP_TEST_OTLP_HEADERS", "Authorization=Bearer sekrit, X-Org=acme")
	sink := newOTLPSink(&AuditOTLPConfig{
		Endpoint:             srv.URL,
		HeadersEnv:           "MESHMCP_TEST_OTLP_HEADERS",
		All:                  true,
		BatchSize:            1,
		FlushIntervalSeconds: 1,
		TimeoutSeconds:       2,
	}, "v")
	defer sink.Close()
	_ = sink.Append(policy.AuditRecord{Decision: "allow"})

	select {
	case h := <-got:
		if h.Get("Authorization") != "Bearer sekrit" || h.Get("X-Org") != "acme" {
			t.Fatalf("headers not injected from env: %v", h)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for the export")
	}
}

// TestOTLPCloseBoundedAndPostCloseCounted proves the shutdown drain is
// bounded (one failed export ends it — Close never hangs behind a dead
// collector), the abandoned records are counted as drops, and an Append after
// Close is counted rather than stranded in a dead queue.
func TestOTLPCloseBoundedAndPostCloseCounted(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release // stalled collector: every POST times out client-side
	}))
	defer srv.Close()
	// LIFO: release must close BEFORE srv.Close runs, or Close waits forever
	// for the stalled handler's still-active connection.
	defer close(release)

	sink := newOTLPSink(&AuditOTLPConfig{
		Endpoint:             srv.URL,
		All:                  true,
		BatchSize:            64, // never reached — no export before Close
		FlushIntervalSeconds: 60, // no ticker flush before Close
		TimeoutSeconds:       1,
		QueueSize:            16,
	}, "v")
	for i := 0; i < 16; i++ {
		_ = sink.Append(policy.AuditRecord{Decision: "deny", Seq: i})
	}

	start := time.Now()
	sink.Close()
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("Close took %s against a dead collector — the drain must be bounded", elapsed)
	}
	if got := sink.Dropped(); got != 16 {
		t.Fatalf("abandoned drain records dropped = %d, want 16", got)
	}
	_ = sink.Append(policy.AuditRecord{Decision: "deny", Seq: 99})
	if got := sink.Dropped(); got != 17 {
		t.Fatalf("post-Close Append dropped = %d, want 17", got)
	}
}

// TestOTLPPartialSuccessCountedAsDrops proves a 2xx response carrying
// partialSuccess.rejectedLogRecords is not treated as full success: the
// rejected count lands in the drop counter.
func TestOTLPPartialSuccessCountedAsDrops(t *testing.T) {
	posted := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"partialSuccess":{"rejectedLogRecords":"1","errorMessage":"attribute limit"}}`))
		posted <- struct{}{}
	}))
	defer srv.Close()

	sink := otlpTestSink(srv.URL, true, 2)
	defer sink.Close()
	_ = sink.Append(policy.AuditRecord{Decision: "deny", Seq: 1})
	_ = sink.Append(policy.AuditRecord{Decision: "deny", Seq: 2})

	select {
	case <-posted:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for the export")
	}
	deadline := time.Now().Add(2 * time.Second)
	for sink.Dropped() != 1 {
		if time.Now().After(deadline) {
			t.Fatalf("partial-success rejections dropped = %d, want 1", sink.Dropped())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestParsePartialSuccess covers the lenient decoding: the proto3 JSON string
// form, the plain-number form some collectors emit, and empty/absent bodies.
func TestParsePartialSuccess(t *testing.T) {
	for body, want := range map[string]int64{
		`{"partialSuccess":{"rejectedLogRecords":"3","errorMessage":"m"}}`: 3,
		`{"partialSuccess":{"rejectedLogRecords":2}}`:                      2,
		`{"partialSuccess":{}}`:                                            0,
		`{}`:                                                               0,
		``:                                                                 0,
		`not json`:                                                         0,
	} {
		if got, _ := parsePartialSuccess(strings.NewReader(body)); got != want {
			t.Fatalf("parsePartialSuccess(%q) = %d, want %d", body, got, want)
		}
	}
}

// TestOTLPLogsURL covers endpoint normalization: base URLs get /v1/logs
// appended; a full .../v1/logs URL is accepted as-is.
func TestOTLPLogsURL(t *testing.T) {
	for in, want := range map[string]string{
		"http://127.0.0.1:4318":         "http://127.0.0.1:4318/v1/logs",
		"http://127.0.0.1:4318/":        "http://127.0.0.1:4318/v1/logs",
		"https://otel.example/v1/logs":  "https://otel.example/v1/logs",
		"https://otel.example/v1/logs/": "https://otel.example/v1/logs",
	} {
		if got := otlpLogsURL(in); got != want {
			t.Fatalf("otlpLogsURL(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestConfigAuditOTLPValidation proves startup fails on a malformed endpoint
// or a missing shared ledger — and only on those (reachability is not checked).
func TestConfigAuditOTLPValidation(t *testing.T) {
	base := `
backends:
  - name: fs
    port: 9101
    stdio: ["echo"]
`
	cases := []struct {
		name, body, wantErr string
	}{
		{"requires audit_log", `
audit_otlp:
  endpoint: http://127.0.0.1:4318
` + base, "audit_otlp requires audit_log"},
		{"missing endpoint", `
audit_log: ./audit.jsonl
audit_otlp:
  batch_size: 8
` + base, "endpoint is required"},
		{"bad scheme", `
audit_log: ./audit.jsonl
audit_otlp:
  endpoint: ftp://collector:4318
` + base, "invalid endpoint url"},
		{"credentials in url", `
audit_log: ./audit.jsonl
audit_otlp:
  endpoint: https://user:secret@collector:4318
` + base, "must not embed credentials"},
		{"valid (unreachable is fine)", `
audit_log: ./audit.jsonl
audit_otlp:
  endpoint: http://127.0.0.1:4318
  headers_env: MESHMCP_OTLP_HEADERS
  timeout_seconds: 10
  all: true
  batch_size: 64
  flush_interval_seconds: 5
  queue_size: 1024
` + base, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := loadConfig(writeConfig(t, tc.body))
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("config should load: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("expected error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}
