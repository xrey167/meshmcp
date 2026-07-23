package main

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"

	"github.com/xrey167/meshmcp/policy"
)

// metricsSink is an observer AuditSink (the S41 seam) that aggregates
// committed audit records into Prometheus text-format counters served on
// GET /metrics. It is metadata-only by construction: labels carry backend,
// method, tool, and decision — never a peer identity, an argument, or a
// payload. The hash-chained ledger remains the control; this sink can drop
// or cap, never block or deny.
type metricsSink struct {
	mu sync.Mutex

	decisions map[string]uint64 // decision -> count
	calls     map[string]uint64 // backend|method|decision -> count
	tools     map[string]uint64 // backend|tool|decision -> count (capped)
	cost      map[string]uint64 // backend -> cost units
	chainSeq  int               // highest committed chain sequence seen

	toolOverflow bool // distinct tool label sets exceeded maxToolSeries
}

// maxToolSeries bounds the distinct {backend,tool,decision} series so a
// backend advertising unbounded tool names cannot grow this sink without
// limit; overflow lands in tool="_other".
const maxToolSeries = 1024

func newMetricsSink() *metricsSink {
	return &metricsSink{
		decisions: map[string]uint64{},
		calls:     map[string]uint64{},
		tools:     map[string]uint64{},
		cost:      map[string]uint64{},
	}
}

// Append implements policy.AuditSink. Errors never reach the enforcement
// path (observer contract), so it always returns nil.
func (m *metricsSink) Append(rec policy.AuditRecord) error {
	decision := rec.Decision
	switch decision {
	case "allow", "deny", "cosign":
	default:
		decision = "_other"
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.decisions[decision]++
	m.calls[labelKey(rec.Backend, rec.Method, decision)]++
	if rec.Tool != "" {
		tool := rec.Tool
		if _, seen := m.tools[labelKey(rec.Backend, tool, decision)]; !seen && len(m.tools) >= maxToolSeries {
			tool = "_other"
			m.toolOverflow = true
		}
		m.tools[labelKey(rec.Backend, tool, decision)]++
	}
	if rec.Cost > 0 {
		m.cost[rec.Backend] += uint64(rec.Cost)
	}
	if rec.Seq > m.chainSeq {
		m.chainSeq = rec.Seq
	}
	return nil
}

// ServeHTTP renders the Prometheus text exposition format (deterministically
// sorted so scrapes and tests are stable).
func (m *metricsSink) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

	var b strings.Builder
	b.WriteString("# HELP meshmcp_audit_records_total Committed audit records by decision.\n")
	b.WriteString("# TYPE meshmcp_audit_records_total counter\n")
	for _, k := range sortedKeys(m.decisions) {
		fmt.Fprintf(&b, "meshmcp_audit_records_total{decision=%q} %d\n", k, m.decisions[k])
	}
	b.WriteString("# HELP meshmcp_calls_total Governed calls by backend, method, and decision.\n")
	b.WriteString("# TYPE meshmcp_calls_total counter\n")
	for _, k := range sortedKeys(m.calls) {
		p := strings.SplitN(k, "\x00", 3)
		fmt.Fprintf(&b, "meshmcp_calls_total{backend=%q,method=%q,decision=%q} %d\n",
			p[0], p[1], p[2], m.calls[k])
	}
	b.WriteString("# HELP meshmcp_tool_calls_total tools/call records by backend, tool, and decision (bounded series; overflow in tool=\"_other\").\n")
	b.WriteString("# TYPE meshmcp_tool_calls_total counter\n")
	for _, k := range sortedKeys(m.tools) {
		p := strings.SplitN(k, "\x00", 3)
		fmt.Fprintf(&b, "meshmcp_tool_calls_total{backend=%q,tool=%q,decision=%q} %d\n",
			p[0], p[1], p[2], m.tools[k])
	}
	b.WriteString("# HELP meshmcp_cost_units_total Cost/quota units consumed per backend.\n")
	b.WriteString("# TYPE meshmcp_cost_units_total counter\n")
	for _, k := range sortedKeys(m.cost) {
		fmt.Fprintf(&b, "meshmcp_cost_units_total{backend=%q} %d\n", k, m.cost[k])
	}
	b.WriteString("# HELP meshmcp_audit_chain_seq Highest committed audit chain sequence number.\n")
	b.WriteString("# TYPE meshmcp_audit_chain_seq gauge\n")
	fmt.Fprintf(&b, "meshmcp_audit_chain_seq %d\n", m.chainSeq)
	_, _ = w.Write([]byte(b.String()))
}

func labelKey(parts ...string) string { return strings.Join(parts, "\x00") }

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
