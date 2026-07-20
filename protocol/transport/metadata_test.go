package transport_test

import (
	"encoding/json"
	"testing"

	"github.com/xrey167/meshmcp/protocol/transport"
)

func TestRequestMetaAllFields(t *testing.T) {
	raw := `{
		"progressToken": "p-1",
		"io.modelcontextprotocol/protocolVersion": "2026-07-28",
		"io.modelcontextprotocol/clientInfo": {"name": "C", "version": "1.0.0"},
		"io.modelcontextprotocol/clientCapabilities": {},
		"io.modelcontextprotocol/logLevel": "debug"
	}`
	var m transport.RequestMeta
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if m.ProgressToken != "p-1" || m.ProtocolVersion != "2026-07-28" || m.LogLevel != "debug" {
		t.Fatalf("request meta fields lost: %+v", m)
	}
	if m.ClientInfo == nil || m.ClientInfo.Name != "C" {
		t.Fatalf("clientInfo lost: %+v", m.ClientInfo)
	}

	// Round-trip keeps the well-known keys verbatim.
	out, _ := json.Marshal(m)
	var probe map[string]any
	_ = json.Unmarshal(out, &probe)
	if probe["progressToken"] != "p-1" || probe[transport.MetaKeyLogLevel] != "debug" {
		t.Fatalf("meta keys not preserved: %v", probe)
	}
}

func TestResultAndNotificationMeta(t *testing.T) {
	var rm transport.ResultMeta
	if err := json.Unmarshal([]byte(`{"io.modelcontextprotocol/serverInfo":{"name":"S","version":"2"}}`), &rm); err != nil {
		t.Fatalf("result meta: %v", err)
	}
	if rm.ServerInfo == nil || rm.ServerInfo.Version != "2" {
		t.Fatalf("serverInfo lost: %+v", rm.ServerInfo)
	}

	var nm transport.NotificationMeta
	if err := json.Unmarshal([]byte(`{"io.modelcontextprotocol/subscriptionId":1}`), &nm); err != nil {
		t.Fatalf("notification meta: %v", err)
	}
	if nm.SubscriptionID == nil {
		t.Fatalf("subscriptionId lost: %+v", nm)
	}
}
