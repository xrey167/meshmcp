package servercard_test

import (
	"encoding/json"
	"testing"

	"github.com/xrey167/meshmcp/protocol/servercard"
)

func TestServerCardRoundTrip(t *testing.T) {
	raw := `{
		"$schema": "https://static.modelcontextprotocol.io/schemas/v1/server-card.schema.json",
		"name": "example.com/weather",
		"version": "1.0.2",
		"description": "Weather data server",
		"repository": {"url": "https://github.com/example/weather", "source": "github"},
		"icons": [{"src": "https://example.com/i.png", "mimeType": "image/png", "theme": "light"}],
		"remotes": [{
			"type": "streamable-http",
			"url": "https://example.com/mcp",
			"headers": [{"name": "Authorization", "isSecret": true, "value": "Bearer {token}"}],
			"variables": {"token": {"isRequired": true, "isSecret": true}},
			"supportedProtocolVersions": ["2025-06-18"]
		}]
	}`

	var card servercard.ServerCard
	if err := json.Unmarshal([]byte(raw), &card); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if card.Schema != servercard.SchemaURI {
		t.Fatalf("$schema = %q", card.Schema)
	}
	if card.Name != "example.com/weather" || card.Version != "1.0.2" {
		t.Fatalf("identity mismatch: %+v", card)
	}
	if len(card.Remotes) != 1 || card.Remotes[0].Type != servercard.RemoteStreamableHTTP {
		t.Fatalf("remote mismatch: %+v", card.Remotes)
	}
	h := card.Remotes[0].Headers
	if len(h) != 1 || h[0].Name != "Authorization" || h[0].IsSecret == nil || !*h[0].IsSecret {
		t.Fatalf("header (embedded Input) mismatch: %+v", h)
	}

	// Re-marshal and ensure $schema and nested structures survive.
	out, err := json.Marshal(&card)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var probe map[string]any
	if err := json.Unmarshal(out, &probe); err != nil {
		t.Fatalf("re-unmarshal: %v", err)
	}
	if probe["$schema"] != servercard.SchemaURI {
		t.Fatalf("$schema lost on marshal: %v", probe["$schema"])
	}
}
