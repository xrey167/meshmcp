package discover_test

import (
	"encoding/json"
	"testing"

	"github.com/xrey167/meshmcp/protocol/discover"
)

// serverCapabilityExamples are the official draft
// schema/draft/examples/ServerCapabilities fixtures. Each must decode into
// discover.ServerCapabilities without error and round-trip stably.
var serverCapabilityExamples = map[string]string{
	"completions":       `{"completions": {}}`,
	"extensions-tasks":  `{"extensions": {"io.modelcontextprotocol/tasks": {}}}`,
	"logging":           `{"logging": {}}`,
	"prompts-listchg":   `{"prompts": {"listChanged": true}}`,
	"prompts-baseline":  `{"prompts": {}}`,
	"resources-all":     `{"resources": {"subscribe": true, "listChanged": true}}`,
	"resources-listchg": `{"resources": {"listChanged": true}}`,
	"resources-base":    `{"resources": {}}`,
	"resources-sub":     `{"resources": {"subscribe": true}}`,
	"tools-listchg":     `{"tools": {"listChanged": true}}`,
	"tools-baseline":    `{"tools": {}}`,
}

func TestServerCapabilitiesConformance(t *testing.T) {
	for name, raw := range serverCapabilityExamples {
		t.Run(name, func(t *testing.T) {
			var c discover.ServerCapabilities
			if err := json.Unmarshal([]byte(raw), &c); err != nil {
				t.Fatalf("decode: %v", err)
			}
			out, err := json.Marshal(c)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			// Canonicalize and compare (presence of empty "{}" preserved).
			var a, b any
			_ = json.Unmarshal([]byte(raw), &a)
			_ = json.Unmarshal(out, &b)
			ab, _ := json.Marshal(a)
			bb, _ := json.Marshal(b)
			if string(ab) != string(bb) {
				t.Fatalf("round-trip changed JSON:\n in:  %s\n out: %s", ab, bb)
			}
		})
	}
}
