package main

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/xrey167/meshmcp/policy"
)

// webhookSink is an observer AuditSink (the F13/S38 seam, S42) that POSTs
// selected audit records to an external URL — a SIEM ingest endpoint, a Slack
// incoming webhook, a PagerDuty event. It is best-effort by construction (the
// hash-chained ledger remains the control) and fires asynchronously so a slow
// endpoint never blocks the enforcement path. By default it forwards only deny
// and cosign records (the security-interesting ones).
type webhookSink struct {
	url      string
	denyOnly bool
	ch       chan policy.AuditRecord
	client   *http.Client
}

func newWebhookSink(url string, denyOnly bool) *webhookSink {
	s := &webhookSink{
		url:      url,
		denyOnly: denyOnly,
		ch:       make(chan policy.AuditRecord, 256),
		client:   &http.Client{Timeout: 10 * time.Second},
	}
	go s.loop()
	return s
}

// Append implements policy.AuditSink. It is non-blocking: if the buffer is full
// (endpoint down / slow), the record is dropped from the webhook stream — never
// from the ledger.
func (s *webhookSink) Append(rec policy.AuditRecord) error {
	if s.denyOnly && rec.Decision == "allow" {
		return nil
	}
	select {
	case s.ch <- rec:
	default:
		// buffer full — drop rather than block the enforcement path
	}
	return nil
}

func (s *webhookSink) loop() {
	for rec := range s.ch {
		body, err := json.Marshal(rec)
		if err != nil {
			continue
		}
		resp, err := s.client.Post(s.url, "application/json", bytes.NewReader(body))
		if err != nil {
			log.Printf("audit webhook %s: %v", s.url, err)
			continue
		}
		resp.Body.Close()
	}
}
