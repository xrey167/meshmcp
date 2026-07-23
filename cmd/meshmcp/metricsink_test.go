package main

import (
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/xrey167/meshmcp/policy"
)

func scrapeMetrics(t *testing.T, m *metricsSink) string {
	t.Helper()
	rec := httptest.NewRecorder()
	m.ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Fatalf("content type = %q", ct)
	}
	return rec.Body.String()
}

func TestMetricsSinkAggregatesDecisionsToolsAndCost(t *testing.T) {
	m := newMetricsSink()
	for i := 0; i < 3; i++ {
		m.Append(policy.AuditRecord{Backend: "fs", Method: "tools/call", Tool: "read_file", Decision: "allow", Cost: 2, Seq: i + 1})
	}
	m.Append(policy.AuditRecord{Backend: "fs", Method: "tools/call", Tool: "rm", Decision: "deny", Seq: 4})
	m.Append(policy.AuditRecord{Backend: "billing", Method: "tools/list", Decision: "allow", Seq: 5})
	m.Append(policy.AuditRecord{Backend: "billing", Method: "tools/call", Tool: "transfer", Decision: "weird", Seq: 6})

	out := scrapeMetrics(t, m)
	for _, want := range []string{
		`meshmcp_audit_records_total{decision="allow"} 4`,
		`meshmcp_audit_records_total{decision="deny"} 1`,
		`meshmcp_audit_records_total{decision="_other"} 1`,
		`meshmcp_calls_total{backend="fs",method="tools/call",decision="allow"} 3`,
		`meshmcp_calls_total{backend="billing",method="tools/list",decision="allow"} 1`,
		`meshmcp_tool_calls_total{backend="fs",tool="read_file",decision="allow"} 3`,
		`meshmcp_tool_calls_total{backend="fs",tool="rm",decision="deny"} 1`,
		`meshmcp_cost_units_total{backend="fs"} 6`,
		`meshmcp_audit_chain_seq 6`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

// A peer identity must never appear in the exposition — labels are
// metadata-only by construction.
func TestMetricsSinkNeverExposesPeerIdentity(t *testing.T) {
	m := newMetricsSink()
	m.Append(policy.AuditRecord{
		Backend: "fs", Method: "tools/call", Tool: "read_file", Decision: "allow",
		Peer: "alice.mesh", PeerKey: "SECRETKEY", PeerAddr: "100.64.0.9:1",
		Reason: "matched rule with alice.mesh",
	})
	out := scrapeMetrics(t, m)
	for _, leak := range []string{"alice.mesh", "SECRETKEY", "100.64.0.9"} {
		if strings.Contains(out, leak) {
			t.Fatalf("exposition leaked %q:\n%s", leak, out)
		}
	}
}

func TestMetricsSinkEscapesLabelValues(t *testing.T) {
	m := newMetricsSink()
	m.Append(policy.AuditRecord{Backend: "b\"ad\\", Method: "tools/call", Tool: "t\nool", Decision: "allow"})
	out := scrapeMetrics(t, m)
	if !strings.Contains(out, `backend="b\"ad\\"`) {
		t.Errorf("backend not escaped:\n%s", out)
	}
	if !strings.Contains(out, `tool="t\nool"`) {
		t.Errorf("tool newline not escaped:\n%s", out)
	}
	if strings.Contains(out, "t\nool") {
		t.Errorf("raw newline leaked into exposition:\n%s", out)
	}
}

func TestMetricsSinkCapsToolSeries(t *testing.T) {
	m := newMetricsSink()
	for i := 0; i < maxToolSeries+50; i++ {
		m.Append(policy.AuditRecord{Backend: "fs", Method: "tools/call", Tool: fmt.Sprintf("tool-%04d", i), Decision: "allow"})
	}
	out := scrapeMetrics(t, m)
	if !strings.Contains(out, `meshmcp_tool_calls_total{backend="fs",tool="_other",decision="allow"} 50`) {
		t.Errorf("overflow series missing or wrong:\n%s", out)
	}
	m.mu.Lock()
	series := len(m.tools)
	m.mu.Unlock()
	if series > maxToolSeries+1 {
		t.Fatalf("tool series grew past the cap: %d", series)
	}
}
