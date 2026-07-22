package main

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/xrey167/meshmcp/air"
	"github.com/xrey167/meshmcp/policy"
	"github.com/xrey167/meshmcp/session"
)

func TestRingLimiterRefillAndExhaust(t *testing.T) {
	l := newRingLimiter(6) // 6/min => 0.1/s, burst 6
	base := time.Date(2026, 7, 22, 14, 0, 0, 0, time.UTC)
	// Burst of 6 all at the same instant.
	for i := 0; i < 6; i++ {
		if !l.allow("KEY", base) {
			t.Fatalf("burst token %d should be allowed", i)
		}
	}
	// 7th at the same instant is over the burst.
	if l.allow("KEY", base) {
		t.Fatal("over-burst ring should be denied")
	}
	// After 60s, ~6 tokens refilled (rate 0.1/s * 60 = 6), so one more is allowed.
	if !l.allow("KEY", base.Add(60*time.Second)) {
		t.Fatal("refilled ring should be allowed after 60s")
	}
	// A different identity has its own bucket.
	if !l.allow("OTHER", base) {
		t.Fatal("a different identity should have its own tokens")
	}
}

func TestOnRingRendersAndAudits(t *testing.T) {
	old := colorOn
	colorOn = false
	defer func() { colorOn = old }()

	var auditBuf bytes.Buffer
	audit := policy.NewAuditLog(&auditBuf, func() string { return "2026-07-22T14:00:00Z" })
	limiter := newRingLimiter(6)
	meta := session.Meta{PeerFQDN: "laptop.mesh", PeerKey: "KEY"}

	var out bytes.Buffer
	onRing(air.Ring("build is red"), meta, limiter, audit, false, false, &out)
	if !strings.Contains(out.String(), "build is red") || !strings.Contains(out.String(), "laptop.mesh") {
		t.Fatalf("ring not rendered: %q", out.String())
	}
	if !strings.Contains(auditBuf.String(), `"backend":"ring"`) || !strings.Contains(auditBuf.String(), `"decision":"allow"`) {
		t.Fatalf("ring not audited as allow: %q", auditBuf.String())
	}
}

func TestOnRingRateLimitedAudited(t *testing.T) {
	var auditBuf bytes.Buffer
	audit := policy.NewAuditLog(&auditBuf, func() string { return "2026-07-22T14:00:00Z" })
	limiter := newRingLimiter(1) // 1/min, burst 1
	meta := session.Meta{PeerFQDN: "spammer.mesh", PeerKey: "K2"}

	var out bytes.Buffer
	onRing(air.Ring("one"), meta, limiter, audit, false, false, &out) // allowed
	onRing(air.Ring("two"), meta, limiter, audit, false, false, &out) // rate-limited
	if strings.Contains(out.String(), "two") {
		t.Fatalf("rate-limited ring should not render: %q", out.String())
	}
	if !strings.Contains(auditBuf.String(), "ring rate-limited") {
		t.Fatalf("rate-limit not audited: %q", auditBuf.String())
	}
}

func TestFormatRingRowSanitizesAndColors(t *testing.T) {
	old := colorOn
	colorOn = false
	defer func() { colorOn = old }()
	// A hostile message with an escape must be stripped.
	row := formatRingRow(air.Notice{Message: "evil\x1b[31m", Priority: air.PriorityUrgent}, "peer.mesh")
	if strings.ContainsRune(row, '\x1b') {
		t.Fatalf("escape not sanitized: %q", row)
	}
	if !strings.Contains(row, "URGENT") {
		t.Fatalf("urgent tag missing: %q", row)
	}
}
