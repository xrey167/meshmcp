package apps_test

import (
	"encoding/json"
	"testing"

	"github.com/xrey167/meshmcp/protocol/apps"
)

func TestInitializeRoundTrip(t *testing.T) {
	req := `{
		"method": "ui/initialize",
		"params": {
			"appInfo": {"name": "weather-app", "version": "1.0.0"},
			"appCapabilities": {"tools": {"listChanged": true}, "availableDisplayModes": ["inline", "fullscreen"]},
			"protocolVersion": "2026-01-26"
		}
	}`
	var r apps.InitializeRequest
	if err := json.Unmarshal([]byte(req), &r); err != nil {
		t.Fatalf("request: %v", err)
	}
	if r.Method != apps.MethodInitialize || r.Params.AppInfo.Name != "weather-app" {
		t.Fatalf("request mismatch: %+v", r)
	}
	if r.Params.AppCapabilities.Tools == nil || !r.Params.AppCapabilities.Tools.ListChanged {
		t.Fatalf("app tools capability lost: %+v", r.Params.AppCapabilities)
	}
	if len(r.Params.AppCapabilities.AvailableDisplayModes) != 2 {
		t.Fatalf("display modes lost: %+v", r.Params.AppCapabilities.AvailableDisplayModes)
	}

	res := `{
		"protocolVersion": "2026-01-26",
		"hostInfo": {"name": "ExampleHost", "version": "2.0.0"},
		"hostCapabilities": {"openLinks": {}, "downloadFile": {}, "sampling": {"tools": {}}},
		"hostContext": {"theme": "dark", "displayMode": "inline", "platform": "web"}
	}`
	var hr apps.InitializeResult
	if err := json.Unmarshal([]byte(res), &hr); err != nil {
		t.Fatalf("result: %v", err)
	}
	if hr.HostContext.Theme != apps.ThemeDark || hr.HostContext.DisplayMode != apps.DisplayInline {
		t.Fatalf("host context mismatch: %+v", hr.HostContext)
	}
	if hr.HostCapabilities.OpenLinks == nil || hr.HostCapabilities.Sampling == nil || hr.HostCapabilities.Sampling.Tools == nil {
		t.Fatalf("host capabilities presence lost: %+v", hr.HostCapabilities)
	}
}

func TestOpenLinkAndDownload(t *testing.T) {
	var ol apps.OpenLinkRequest
	if err := json.Unmarshal([]byte(`{"method":"ui/open-link","params":{"url":"https://example.com"}}`), &ol); err != nil {
		t.Fatalf("open-link: %v", err)
	}
	if ol.Params.URL != "https://example.com" {
		t.Fatalf("url = %q", ol.Params.URL)
	}

	var df apps.DownloadFileRequest
	dl := `{"method":"ui/download-file","params":{"contents":[{"type":"text","text":"hi"}]}}`
	if err := json.Unmarshal([]byte(dl), &df); err != nil {
		t.Fatalf("download: %v", err)
	}
	if len(df.Params.Contents) != 1 {
		t.Fatalf("contents = %v", df.Params.Contents)
	}
}

func TestResourceMetaCsp(t *testing.T) {
	raw := `{
		"csp": {"connectDomains": ["https://api.weather.com"], "resourceDomains": ["https://cdn.jsdelivr.net"]},
		"permissions": {"geolocation": {}},
		"domain": "abc.claudemcpcontent.com",
		"prefersBorder": true
	}`
	var m apps.ResourceMeta
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if m.CSP == nil || len(m.CSP.ConnectDomains) != 1 {
		t.Fatalf("csp lost: %+v", m.CSP)
	}
	if m.Permissions == nil || m.Permissions.Geolocation == nil {
		t.Fatalf("permissions presence lost: %+v", m.Permissions)
	}
	if m.PrefersBorder == nil || !*m.PrefersBorder {
		t.Fatalf("prefersBorder = %v", m.PrefersBorder)
	}
}

func TestHostContextResponsiveDecisions(t *testing.T) {
	raw := `{
		"platform": "mobile",
		"userAgent": "ExampleHost/2.0",
		"deviceCapabilities": {"touch": true, "hover": false},
		"availableDisplayModes": ["inline", "fullscreen"]
	}`
	var c apps.HostContext
	if err := json.Unmarshal([]byte(raw), &c); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if c.Platform != apps.PlatformMobile || !c.IsMobile() || c.IsDesktop() {
		t.Fatalf("platform decisions wrong: %+v", c)
	}
	if !c.SupportsTouch() || c.SupportsHover() {
		t.Fatalf("device capability decisions wrong: %+v", c.DeviceCapabilities)
	}
	if !c.SupportsDisplayMode(apps.DisplayFullscreen) || c.SupportsDisplayMode(apps.DisplayPiP) {
		t.Fatalf("display-mode support wrong: %+v", c.AvailableDisplayModes)
	}

	// A web host with no device capabilities reports false, not a panic.
	web := apps.HostContext{Platform: apps.PlatformWeb}
	if !web.IsWeb() || web.SupportsTouch() {
		t.Fatalf("web host decisions wrong: %+v", web)
	}
}

// TestContentBlockParams covers the two apps params with a content-block union
// (ui/message and ui/update-model-context), each with its own UnmarshalJSON.
func TestContentBlockParams(t *testing.T) {
	var mp apps.MessageRequestParams
	if err := json.Unmarshal([]byte(`{"role":"user","content":[{"type":"text","text":"hi"},{"type":"image","data":"AAA","mimeType":"image/png"}]}`), &mp); err != nil {
		t.Fatalf("message params: %v", err)
	}
	if len(mp.Content) != 2 {
		t.Fatalf("message content = %d blocks", len(mp.Content))
	}

	var up apps.UpdateModelContextRequestParams
	if err := json.Unmarshal([]byte(`{"content":[{"type":"text","text":"ctx"}],"structuredContent":{"k":"v"}}`), &up); err != nil {
		t.Fatalf("update-context params: %v", err)
	}
	if len(up.Content) != 1 || up.StructuredContent["k"] != "v" {
		t.Fatalf("update-context mismatch: %+v", up)
	}
}

func TestClientCapabilityMimeType(t *testing.T) {
	var c apps.ClientCapabilities
	if err := json.Unmarshal([]byte(`{"mimeTypes":["text/html;profile=mcp-app"]}`), &c); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(c.MimeTypes) != 1 || c.MimeTypes[0] != apps.MimeType {
		t.Fatalf("mimeTypes = %v", c.MimeTypes)
	}
}
