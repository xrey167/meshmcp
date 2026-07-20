package discover_test

import (
	"encoding/json"
	"testing"

	"github.com/xrey167/meshmcp/protocol/discover"
)

// roundTrip unmarshals a ClientCapabilities snippet and re-marshals it,
// asserting the JSON is byte-stable (presence of empty "{}" objects preserved).
func roundTrip(t *testing.T, in string) discover.ClientCapabilities {
	t.Helper()
	var c discover.ClientCapabilities
	if err := json.Unmarshal([]byte(in), &c); err != nil {
		t.Fatalf("unmarshal %s: %v", in, err)
	}
	out, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// Compare as canonicalized JSON.
	var a, b any
	_ = json.Unmarshal([]byte(in), &a)
	_ = json.Unmarshal(out, &b)
	ab, _ := json.Marshal(a)
	bb, _ := json.Marshal(b)
	if string(ab) != string(bb) {
		t.Fatalf("round-trip changed JSON:\n in:  %s\n out: %s", ab, bb)
	}
	return c
}

func TestClientCapabilitySnippets(t *testing.T) {
	// Each is a real draft ClientCapabilities fragment; all must round-trip.
	roundTrip(t, `{"elicitation": {"form": {}, "url": {}}}`)
	roundTrip(t, `{"elicitation": {}}`)
	roundTrip(t, `{"roots": {}}`)
	roundTrip(t, `{"sampling": {}}`)
	roundTrip(t, `{"sampling": {"context": {}}}`)
	roundTrip(t, `{"sampling": {"tools": {}}}`)
	roundTrip(t, `{"extensions": {"io.modelcontextprotocol/ui": {"mimeTypes": ["text/html;profile=mcp-app"]}}}`)
}

func TestClientCapabilityPresence(t *testing.T) {
	// An empty elicitation object must decode as present (non-nil), distinct
	// from an absent one.
	present := roundTrip(t, `{"elicitation": {}}`)
	if present.Elicitation == nil {
		t.Fatal("elicitation {} should decode as present")
	}

	absent := roundTrip(t, `{"sampling": {}}`)
	if absent.Elicitation != nil {
		t.Fatal("absent elicitation should be nil")
	}

	// Elicitation form/url and sampling sub-flags are preserved when present.
	full := roundTrip(t, `{"elicitation": {"form": {}, "url": {}}, "sampling": {"tools": {}}}`)
	if full.Elicitation.Form == nil || full.Elicitation.URL == nil {
		t.Fatalf("form/url lost: %+v", full.Elicitation)
	}
	if full.Sampling.Tools == nil || full.Sampling.Context != nil {
		t.Fatalf("sampling flags mismatch: %+v", full.Sampling)
	}

	// Extensions content is preserved.
	ext := roundTrip(t, `{"extensions": {"io.modelcontextprotocol/ui": {"mimeTypes": ["text/html;profile=mcp-app"]}}}`)
	ui, ok := ext.Extensions["io.modelcontextprotocol/ui"].(map[string]any)
	if !ok {
		t.Fatalf("ui extension lost: %+v", ext.Extensions)
	}
	if mt, _ := ui["mimeTypes"].([]any); len(mt) != 1 {
		t.Fatalf("mimeTypes lost: %v", ui["mimeTypes"])
	}
}
