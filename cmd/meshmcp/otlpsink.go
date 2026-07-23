package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xrey167/meshmcp/policy"
)

// otlpSink is an observer AuditSink (the F13/S41 seam) that exports committed
// audit records to an OTLP/HTTP logs endpoint (an OpenTelemetry collector's
// `:4318/v1/logs`) as OTLP JSON — the proto3 JSON mapping the OTLP 1.x spec
// defines for OTLP/HTTP, hand-rolled so the gateway stays dependency-free.
//
// It is best-effort by construction: Append never blocks (a full queue drops
// the record — from this stream, never from the ledger), a single worker
// batches records into one POST per batch, and drops are counted and logged
// periodically. The hash-chained ledger remains the control. Records carry
// decision METADATA only — never tool arguments, payloads, or secrets.
type otlpSink struct {
	logsURL  string // endpoint with /v1/logs applied
	headers  map[string]string
	denyOnly bool
	batch    int
	flush    time.Duration
	version  string // service.version resource attribute

	ch      chan policy.AuditRecord
	client  *http.Client
	dropped atomic.Uint64
	logged  uint64 // drops already reported (worker-only)

	quit      chan struct{}
	wg        sync.WaitGroup
	closeOnce sync.Once
	closed    atomic.Bool
	nowf      func() time.Time
}

// AuditOTLPConfig configures the OTLP/HTTP logs export sink. It requires the
// gateway-wide audit_log (the sink observes the shared ledger). The endpoint
// is validated at startup for FORM only — an unreachable collector is not a
// startup error, because an observer may come up after the gateway; records
// emitted meanwhile are dropped (counted), never buffered unboundedly.
type AuditOTLPConfig struct {
	// Endpoint is the collector base URL (http:// or https://); the sink
	// appends /v1/logs unless the URL already ends with it.
	Endpoint string `yaml:"endpoint"`
	// HeadersEnv names an ENVIRONMENT VARIABLE whose value is
	// "Key=Value,Key2=Value2" extra HTTP headers (e.g. Authorization). The
	// secret value itself never appears in the config file.
	HeadersEnv string `yaml:"headers_env"`
	// TimeoutSeconds bounds one export POST (default 10).
	TimeoutSeconds int `yaml:"timeout_seconds"`
	// All exports every record; default false = deny/cosign only (the
	// audit_webhook_all precedent).
	All bool `yaml:"all"`
	// BatchSize is how many records one POST carries at most (default 64).
	BatchSize int `yaml:"batch_size"`
	// FlushIntervalSeconds bounds how long a partial batch waits (default 5).
	FlushIntervalSeconds int `yaml:"flush_interval_seconds"`
	// QueueSize bounds the in-flight buffer; overflow drops + counts
	// (default 1024).
	QueueSize int `yaml:"queue_size"`
}

// validate checks the config's FORM at startup: a malformed endpoint URL is a
// startup error; reachability is deliberately not checked (observer contract —
// the collector may start later).
func (c *AuditOTLPConfig) validate() error {
	if c.Endpoint == "" {
		return fmt.Errorf("audit_otlp: endpoint is required")
	}
	u, err := url.Parse(c.Endpoint)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("audit_otlp: invalid endpoint url %q (want http:// or https://)", c.Endpoint)
	}
	if u.User != nil {
		// Credentials in the URL would be echoed verbatim into gateway logs on
		// every failed export; auth belongs in headers_env.
		return fmt.Errorf("audit_otlp: endpoint must not embed credentials (userinfo); use headers_env for auth headers")
	}
	return nil
}

// otlpLogsURL derives the /v1/logs export URL from the configured endpoint,
// accepting either a base URL or a full .../v1/logs URL.
func otlpLogsURL(endpoint string) string {
	if strings.HasSuffix(strings.TrimRight(endpoint, "/"), "/v1/logs") {
		return strings.TrimRight(endpoint, "/")
	}
	return strings.TrimRight(endpoint, "/") + "/v1/logs"
}

// parseHeadersEnv reads the named env var and parses "K=V,K2=V2" into headers.
// A named-but-unset variable is logged (the operator expected auth to apply)
// and yields no headers — observability config never fails the gateway open
// or closed, and the collector will reject unauthenticated exports visibly.
func parseHeadersEnv(name string) map[string]string {
	if name == "" {
		return nil
	}
	raw := os.Getenv(name)
	if raw == "" {
		log.Printf("audit_otlp: headers_env %s is not set — exporting without extra headers", name)
		return nil
	}
	h := map[string]string{}
	for _, pair := range strings.Split(raw, ",") {
		k, v, ok := strings.Cut(pair, "=")
		k = strings.TrimSpace(k)
		if !ok || k == "" {
			continue
		}
		h[k] = strings.TrimSpace(v)
	}
	return h
}

func newOTLPSink(cfg *AuditOTLPConfig, version string) *otlpSink {
	timeout := time.Duration(cfg.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	batch := cfg.BatchSize
	if batch <= 0 {
		batch = 64
	}
	flush := time.Duration(cfg.FlushIntervalSeconds) * time.Second
	if flush <= 0 {
		flush = 5 * time.Second
	}
	qsize := cfg.QueueSize
	if qsize <= 0 {
		qsize = 1024
	}
	s := &otlpSink{
		logsURL:  otlpLogsURL(cfg.Endpoint),
		headers:  parseHeadersEnv(cfg.HeadersEnv),
		denyOnly: !cfg.All,
		batch:    batch,
		flush:    flush,
		version:  version,
		ch:       make(chan policy.AuditRecord, qsize),
		quit:     make(chan struct{}),
		nowf:     time.Now,
		client: &http.Client{
			Timeout: timeout,
			// Never follow a redirect: the export may carry an Authorization
			// header that must not be re-sent to a host the operator did not
			// configure.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
	s.wg.Add(1)
	go s.loop()
	return s
}

// Append implements policy.AuditSink. It is non-blocking by contract: a full
// queue (collector down / slow) drops the record from the OTLP stream — never
// from the ledger — and counts the drop.
func (s *otlpSink) Append(rec policy.AuditRecord) error {
	if s.denyOnly && rec.Decision == "allow" {
		return nil
	}
	if s.closed.Load() {
		// The worker is gone; enqueueing would strand the record unexported
		// AND uncounted. Count it as a drop instead (visible via Dropped()).
		s.dropped.Add(1)
		return nil
	}
	select {
	case s.ch <- rec:
	default:
		s.dropped.Add(1)
	}
	return nil
}

// Dropped reports how many records were dropped due to a full queue.
func (s *otlpSink) Dropped() uint64 { return s.dropped.Load() }

// Close stops the worker after a best-effort final flush of already-queued
// records (bounded: one failed export or one client-timeout of wall clock ends
// the drain, counting the remainder as drops), and reports any drops. Records
// appended after Close are counted as drops. Safe to call more than once.
func (s *otlpSink) Close() {
	s.closeOnce.Do(func() {
		s.closed.Store(true)
		close(s.quit)
		s.wg.Wait()
		if d := s.Dropped(); d > 0 {
			log.Printf("audit OTLP sink: %d record(s) dropped in total (queue saturated; the ledger has every record)", d)
		}
	})
}

// loop is the single worker: it batches queued records by size and by age,
// exports each batch in one POST, and reports new drops on every flush tick
// so a saturated queue is never silent-forever.
func (s *otlpSink) loop() {
	defer s.wg.Done()
	ticker := time.NewTicker(s.flush)
	defer ticker.Stop()
	batch := make([]policy.AuditRecord, 0, s.batch)
	for {
		select {
		case rec := <-s.ch:
			batch = append(batch, rec)
			if len(batch) >= s.batch {
				s.export(batch)
				batch = batch[:0]
			}
		case <-ticker.C:
			if len(batch) > 0 {
				s.export(batch)
				batch = batch[:0]
			}
			if d := s.Dropped(); d > s.logged {
				log.Printf("audit OTLP sink: %d record(s) dropped since last report (queue saturated)", d-s.logged)
				s.logged = d
			}
		case <-s.quit:
			// Drain what is already queued (best-effort final flush), then stop.
			// The drain is BOUNDED so shutdown can never hang on a dead
			// collector: one failed export abandons the rest (they would only
			// time out again), and the whole drain gets one client-timeout of
			// wall clock. Abandoned records are counted as drops — the ledger
			// has every one of them.
			deadline := time.Now().Add(s.client.Timeout)
			for {
				select {
				case rec := <-s.ch:
					batch = append(batch, rec)
					if len(batch) >= s.batch {
						if !s.exportDrain(batch, deadline) {
							return
						}
						batch = batch[:0]
					}
				default:
					if len(batch) > 0 {
						s.exportDrain(batch, deadline)
					}
					return
				}
			}
		}
	}
}

// exportDrain is export during the shutdown drain: a batch past the deadline
// or after a failed POST is abandoned (counted as dropped) so Close never
// stalls the shutdown path behind a dead collector. Returns false once the
// drain should stop.
func (s *otlpSink) exportDrain(batch []policy.AuditRecord, deadline time.Time) bool {
	if time.Now().After(deadline) || !s.export(batch) {
		s.dropped.Add(uint64(len(batch) + len(s.ch)))
		return false
	}
	return true
}

// export POSTs one batch as an OTLP/HTTP JSON ExportLogsServiceRequest and
// reports whether the collector fully accepted it. Failures are logged (one
// line per batch, so a dead collector logs at most once per flush interval)
// and never surface anywhere near enforcement.
func (s *otlpSink) export(recs []policy.AuditRecord) bool {
	body, err := json.Marshal(s.buildRequest(recs))
	if err != nil {
		return false
	}
	req, err := http.NewRequest(http.MethodPost, s.logsURL, bytes.NewReader(body))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range s.headers {
		req.Header.Set(k, v)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		log.Printf("audit OTLP export %s: %v", s.logsURL, err)
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		log.Printf("audit OTLP export %s: collector returned %s", s.logsURL, resp.Status)
		return false
	}
	// A 2xx may still carry a partialSuccess: some records were rejected by
	// collector policy. Those are drops from this stream — count and log them.
	if rejected, msg := parsePartialSuccess(resp.Body); rejected > 0 {
		s.dropped.Add(uint64(rejected))
		log.Printf("audit OTLP export %s: collector rejected %d record(s) (partial success): %s", s.logsURL, rejected, msg)
	}
	return true
}

// parsePartialSuccess reads an ExportLogsServiceResponse and returns the
// rejectedLogRecords count. Lenient by design: the proto3 JSON mapping emits
// int64 as a string, but some collectors emit a plain number — accept both,
// and treat an unreadable body as full success (the status was 2xx).
func parsePartialSuccess(r io.Reader) (int64, string) {
	var body struct {
		PartialSuccess struct {
			RejectedLogRecords json.RawMessage `json:"rejectedLogRecords"`
			ErrorMessage       string          `json:"errorMessage"`
		} `json:"partialSuccess"`
	}
	if err := json.NewDecoder(io.LimitReader(r, 64<<10)).Decode(&body); err != nil {
		return 0, ""
	}
	raw := strings.Trim(string(body.PartialSuccess.RejectedLogRecords), `"`)
	if raw == "" {
		return 0, ""
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return 0, ""
	}
	return n, body.PartialSuccess.ErrorMessage
}

// --- OTLP/HTTP JSON encoding (proto3 JSON mapping of ExportLogsServiceRequest).
// Field names are camelCase and 64-bit integers are JSON STRINGS, per the
// OTLP spec's JSON encoding rules; enums (severityNumber) are plain ints.

type otlpAnyValue struct {
	StringValue *string         `json:"stringValue,omitempty"`
	IntValue    *string         `json:"intValue,omitempty"` // 64-bit int as string
	ArrayValue  *otlpArrayValue `json:"arrayValue,omitempty"`
}

type otlpArrayValue struct {
	Values []otlpAnyValue `json:"values"`
}

type otlpKeyValue struct {
	Key   string       `json:"key"`
	Value otlpAnyValue `json:"value"`
}

type otlpLogRecord struct {
	TimeUnixNano         string         `json:"timeUnixNano"`
	ObservedTimeUnixNano string         `json:"observedTimeUnixNano"`
	SeverityNumber       int            `json:"severityNumber"`
	SeverityText         string         `json:"severityText"`
	Body                 otlpAnyValue   `json:"body"`
	Attributes           []otlpKeyValue `json:"attributes"`
}

type otlpScope struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type otlpScopeLogs struct {
	Scope      otlpScope       `json:"scope"`
	LogRecords []otlpLogRecord `json:"logRecords"`
}

type otlpResource struct {
	Attributes []otlpKeyValue `json:"attributes"`
}

type otlpResourceLogs struct {
	Resource  otlpResource    `json:"resource"`
	ScopeLogs []otlpScopeLogs `json:"scopeLogs"`
}

type otlpExportRequest struct {
	ResourceLogs []otlpResourceLogs `json:"resourceLogs"`
}

func otlpStr(v string) otlpAnyValue          { return otlpAnyValue{StringValue: &v} }
func otlpInt(v int64) otlpAnyValue           { s := strconv.FormatInt(v, 10); return otlpAnyValue{IntValue: &s} }
func strAttr(k, v string) otlpKeyValue       { return otlpKeyValue{Key: k, Value: otlpStr(v)} }
func intAttr(k string, v int64) otlpKeyValue { return otlpKeyValue{Key: k, Value: otlpInt(v)} }

// otlpSeverity maps a policy decision to an OTLP severity: allow → INFO (9),
// cosign → WARN (13, a call held for human approval is notable), deny →
// ERROR (17, the security-interesting outcome). severityText carries the
// decision word itself so a collector can match on it directly.
func otlpSeverity(decision string) int {
	switch decision {
	case "deny":
		return 17 // SEVERITY_NUMBER_ERROR
	case "cosign":
		return 13 // SEVERITY_NUMBER_WARN
	default:
		return 9 // SEVERITY_NUMBER_INFO
	}
}

// buildRequest maps one batch to an ExportLogsServiceRequest: one resource
// (service.name/service.version), one scope (meshmcp/audit), one logRecord
// per audit record.
func (s *otlpSink) buildRequest(recs []policy.AuditRecord) otlpExportRequest {
	logs := make([]otlpLogRecord, 0, len(recs))
	for _, rec := range recs {
		logs = append(logs, otlpLogRecordFrom(rec, s.nowf))
	}
	return otlpExportRequest{ResourceLogs: []otlpResourceLogs{{
		Resource: otlpResource{Attributes: []otlpKeyValue{
			strAttr("service.name", "meshmcp"),
			strAttr("service.version", s.version),
		}},
		ScopeLogs: []otlpScopeLogs{{
			Scope:      otlpScope{Name: "meshmcp/audit", Version: "1"},
			LogRecords: logs,
		}},
	}}}
}

// otlpLogRecordFrom maps one committed audit record to an OTLP logRecord.
// Attributes are decision METADATA only — identity, tool name, decision, and
// the chain fields (seq/hash/prev_hash, so a collector can cross-check the
// tamper-evident chain) — never arguments, payloads, or secret values.
func otlpLogRecordFrom(rec policy.AuditRecord, nowf func() time.Time) otlpLogRecord {
	now := nowf()
	ts := now
	if t, err := time.Parse(time.RFC3339, rec.Time); err == nil {
		ts = t
	}
	body := rec.Reason
	if body == "" {
		body = "decision=" + rec.Decision
		if rec.Tool != "" {
			body += " tool=" + rec.Tool
		}
	}
	attrs := make([]otlpKeyValue, 0, 16)
	add := func(k, v string) {
		if v != "" {
			attrs = append(attrs, strAttr(k, v))
		}
	}
	add("backend", rec.Backend)
	add("peer", rec.Peer)
	add("peer_key", rec.PeerKey)
	add("peer_addr", rec.PeerAddr)
	add("method", rec.Method)
	add("tool", rec.Tool)
	add("rpc_id", rec.RPCID)
	add("decision", rec.Decision)
	attrs = append(attrs, intAttr("rule", int64(rec.Rule)))
	if rec.Cost > 0 {
		attrs = append(attrs, intAttr("cost", int64(rec.Cost)))
	}
	attrs = append(attrs, intAttr("seq", int64(rec.Seq)))
	add("hash", rec.Hash)
	add("prev_hash", rec.PrevHash)
	add("peer_spiffe_id", string(rec.PeerSpiffeID))
	if len(rec.Provenance) > 0 {
		vals := make([]otlpAnyValue, 0, len(rec.Provenance))
		for _, p := range rec.Provenance {
			vals = append(vals, otlpStr(p))
		}
		attrs = append(attrs, otlpKeyValue{Key: "provenance", Value: otlpAnyValue{ArrayValue: &otlpArrayValue{Values: vals}}})
	}
	return otlpLogRecord{
		TimeUnixNano:         strconv.FormatInt(ts.UnixNano(), 10),
		ObservedTimeUnixNano: strconv.FormatInt(now.UnixNano(), 10),
		SeverityNumber:       otlpSeverity(rec.Decision),
		SeverityText:         rec.Decision,
		Body:                 otlpStr(body),
		Attributes:           attrs,
	}
}
