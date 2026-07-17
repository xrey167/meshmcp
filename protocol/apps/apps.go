// Package apps models the MCP Apps extension protocol (ext-apps): the message
// bridge between a host and an embedded, sandboxed UI ("View"). It covers the
// ui/* requests, results and notifications, the host/app capabilities, host
// context, and the resource security metadata (CSP, permissions).
//
// Source of truth: modelcontextprotocol/ext-apps (src/spec.types.ts). This is
// an EXPERIMENTAL extension; clients advertise support via the MCP capability
// extensions map under the MCP Apps MIME type.
package apps

import (
	"encoding/json"

	"meshmcp/protocol/base"
	"meshmcp/protocol/content"
	"meshmcp/protocol/tool"
)

// ToolResultNotification carries a tool execution result (Host -> View).
type ToolResultNotification struct {
	Method string          `json:"method"` // MethodToolResult
	Params tool.CallResult `json:"params"`
}

// ProtocolVersion is the MCP Apps protocol version these models reflect.
const ProtocolVersion = "2026-01-26"

// MimeType is the resource MIME type that signals MCP Apps support; it must
// appear in McpUiClientCapabilities.MimeTypes.
const MimeType = "text/html;profile=mcp-app"

// ui/* method names.
const (
	MethodOpenLink             = "ui/open-link"
	MethodDownloadFile         = "ui/download-file"
	MethodMessage              = "ui/message"
	MethodSandboxProxyReady    = "ui/notifications/sandbox-proxy-ready"
	MethodSandboxResourceReady = "ui/notifications/sandbox-resource-ready"
	MethodSizeChanged          = "ui/notifications/size-changed"
	MethodToolInput            = "ui/notifications/tool-input"
	MethodToolInputPartial     = "ui/notifications/tool-input-partial"
	MethodToolResult           = "ui/notifications/tool-result"
	MethodToolCancelled        = "ui/notifications/tool-cancelled"
	MethodHostContextChanged   = "ui/notifications/host-context-changed"
	MethodRequestTeardown      = "ui/notifications/request-teardown"
	MethodResourceTeardown     = "ui/resource-teardown"
	MethodInitialize           = "ui/initialize"
	MethodInitialized          = "ui/notifications/initialized"
	MethodUpdateModelContext   = "ui/update-model-context"
	MethodRequestDisplayMode   = "ui/request-display-mode"
)

// Theme is the host color-theme preference.
type Theme string

const (
	ThemeLight Theme = "light"
	ThemeDark  Theme = "dark"
)

// DisplayMode is how the UI is presented.
type DisplayMode string

const (
	DisplayInline     DisplayMode = "inline"
	DisplayFullscreen DisplayMode = "fullscreen"
	DisplayPiP        DisplayMode = "pip"
)

// ToolVisibility is who can access a tool.
type ToolVisibility string

const (
	VisibilityModel ToolVisibility = "model"
	VisibilityApp   ToolVisibility = "app"
)

// Styles are CSS variables for theming apps, keyed by CSS custom-property name
// (e.g. "--color-background-primary"); values are CSS value strings.
type Styles = map[string]string

// present marks a presence-only "{}" capability flag; nil means absent.
type present = map[string]any

// OpenLinkRequest opens an external URL in the host's browser (View -> Host).
type OpenLinkRequest struct {
	Method string                `json:"method"` // MethodOpenLink
	Params OpenLinkRequestParams `json:"params"`
}

// OpenLinkRequestParams are the params of an OpenLinkRequest.
type OpenLinkRequestParams struct {
	URL string `json:"url"`
}

// OpenLinkResult is the result of opening a URL.
type OpenLinkResult struct {
	IsError bool `json:"isError,omitempty"`
}

// DownloadFileRequest triggers a host-mediated file download (View -> Host).
type DownloadFileRequest struct {
	Method string                    `json:"method"` // MethodDownloadFile
	Params DownloadFileRequestParams `json:"params"`
}

// DownloadFileRequestParams are the params of a DownloadFileRequest. Contents
// are embedded resources or resource links.
type DownloadFileRequestParams struct {
	Contents []content.Block `json:"contents"`
}

// UnmarshalJSON decodes the polymorphic contents blocks.
func (p *DownloadFileRequestParams) UnmarshalJSON(data []byte) error {
	var raw struct {
		Contents json.RawMessage `json:"contents"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	if raw.Contents == nil {
		return nil
	}
	blocks, err := content.DecodeBlocks(raw.Contents)
	if err != nil {
		return err
	}
	p.Contents = blocks
	return nil
}

// DownloadFileResult is the result of a file download request.
type DownloadFileResult struct {
	IsError bool `json:"isError,omitempty"`
}

// MessageRequest sends a message to the host's chat interface (View -> Host).
type MessageRequest struct {
	Method string               `json:"method"` // MethodMessage
	Params MessageRequestParams `json:"params"`
}

// MessageRequestParams are the params of a MessageRequest.
type MessageRequestParams struct {
	// Role is currently always "user".
	Role    base.Role       `json:"role"`
	Content []content.Block `json:"content"`
}

// UnmarshalJSON decodes the polymorphic content blocks.
func (p *MessageRequestParams) UnmarshalJSON(data []byte) error {
	var raw struct {
		Role    base.Role       `json:"role"`
		Content json.RawMessage `json:"content"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	p.Role = raw.Role
	if raw.Content != nil {
		blocks, err := content.DecodeBlocks(raw.Content)
		if err != nil {
			return err
		}
		p.Content = blocks
	}
	return nil
}

// MessageResult is the result of sending a message.
type MessageResult struct {
	IsError bool `json:"isError,omitempty"`
}

// SizeChangedNotification reports a UI size change (View -> Host).
type SizeChangedNotification struct {
	Method string                        `json:"method"` // MethodSizeChanged
	Params SizeChangedNotificationParams `json:"params"`
}

// SizeChangedNotificationParams are the params of a SizeChangedNotification.
type SizeChangedNotificationParams struct {
	Width  *float64 `json:"width,omitempty"`
	Height *float64 `json:"height,omitempty"`
}

// ToolInputNotification carries complete tool arguments (Host -> View).
type ToolInputNotification struct {
	Method string              `json:"method"` // MethodToolInput
	Params ToolArgumentsParams `json:"params"`
}

// ToolInputPartialNotification carries partial/streaming tool arguments.
type ToolInputPartialNotification struct {
	Method string              `json:"method"` // MethodToolInputPartial
	Params ToolArgumentsParams `json:"params"`
}

// ToolArgumentsParams carry tool call arguments.
type ToolArgumentsParams struct {
	Arguments map[string]any `json:"arguments,omitempty"`
}

// ToolCancelledNotification reports that tool execution was cancelled.
type ToolCancelledNotification struct {
	Method string                          `json:"method"` // MethodToolCancelled
	Params ToolCancelledNotificationParams `json:"params"`
}

// ToolCancelledNotificationParams are the params of a ToolCancelledNotification.
type ToolCancelledNotificationParams struct {
	Reason string `json:"reason,omitempty"`
}

// UpdateModelContextRequest updates the agent's context without a follow-up
// (View -> Host).
type UpdateModelContextRequest struct {
	Method string                          `json:"method"` // MethodUpdateModelContext
	Params UpdateModelContextRequestParams `json:"params"`
}

// UpdateModelContextRequestParams are the params of an UpdateModelContextRequest.
type UpdateModelContextRequestParams struct {
	Content           []content.Block `json:"content,omitempty"`
	StructuredContent map[string]any  `json:"structuredContent,omitempty"`
}

// UnmarshalJSON decodes the polymorphic content blocks.
func (p *UpdateModelContextRequestParams) UnmarshalJSON(data []byte) error {
	var raw struct {
		Content           json.RawMessage `json:"content"`
		StructuredContent map[string]any  `json:"structuredContent"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	p.StructuredContent = raw.StructuredContent
	if raw.Content != nil {
		blocks, err := content.DecodeBlocks(raw.Content)
		if err != nil {
			return err
		}
		p.Content = blocks
	}
	return nil
}

// RequestDisplayModeRequest asks the host to change the display mode.
type RequestDisplayModeRequest struct {
	Method string                          `json:"method"` // MethodRequestDisplayMode
	Params RequestDisplayModeRequestParams `json:"params"`
}

// RequestDisplayModeRequestParams are the params of a RequestDisplayModeRequest.
type RequestDisplayModeRequestParams struct {
	Mode DisplayMode `json:"mode"`
}

// RequestDisplayModeResult reports the display mode actually set.
type RequestDisplayModeResult struct {
	Mode DisplayMode `json:"mode"`
}

// ResourceTeardownRequest asks the View to shut down gracefully (Host -> View).
type ResourceTeardownRequest struct {
	Method string         `json:"method"` // MethodResourceTeardown
	Params map[string]any `json:"params"`
}

// ResourceTeardownResult is the result of a teardown request.
type ResourceTeardownResult struct{}

// RequestTeardownNotification is an app-initiated teardown request (View -> Host).
type RequestTeardownNotification struct {
	Method string         `json:"method"` // MethodRequestTeardown
	Params map[string]any `json:"params,omitempty"`
}

// SandboxProxyReadyNotification signals the sandbox proxy iframe is ready.
type SandboxProxyReadyNotification struct {
	Method string         `json:"method"` // MethodSandboxProxyReady
	Params map[string]any `json:"params"`
}

// SandboxResourceReadyNotification carries HTML for the sandbox proxy to load.
type SandboxResourceReadyNotification struct {
	Method string                                 `json:"method"` // MethodSandboxResourceReady
	Params SandboxResourceReadyNotificationParams `json:"params"`
}

// SandboxResourceReadyNotificationParams are the params of the notification.
type SandboxResourceReadyNotificationParams struct {
	HTML        string               `json:"html"`
	Sandbox     string               `json:"sandbox,omitempty"`
	CSP         *ResourceCsp         `json:"csp,omitempty"`
	Permissions *ResourcePermissions `json:"permissions,omitempty"`
}

// HostContextChangedNotification carries a partial host-context update.
type HostContextChangedNotification struct {
	Method string      `json:"method"` // MethodHostContextChanged
	Params HostContext `json:"params"`
}

// HostCss are CSS blocks apps can inject.
type HostCss struct {
	Fonts string `json:"fonts,omitempty"`
}

// HostStyles is the host theming configuration.
type HostStyles struct {
	Variables Styles   `json:"variables,omitempty"`
	Css       *HostCss `json:"css,omitempty"`
}

// ToolInfo identifies the tool call that instantiated an app.
type ToolInfo struct {
	// ID is the JSON-RPC id of the tools/call request.
	ID   base.RequestId `json:"id,omitempty"`
	Tool tool.Tool      `json:"tool"`
}

// DeviceCapabilities describe device input capabilities.
type DeviceCapabilities struct {
	Touch bool `json:"touch,omitempty"`
	Hover bool `json:"hover,omitempty"`
}

// SafeAreaInsets are mobile safe-area boundaries in pixels.
type SafeAreaInsets struct {
	Top    float64 `json:"top"`
	Right  float64 `json:"right"`
	Bottom float64 `json:"bottom"`
	Left   float64 `json:"left"`
}

// ContainerDimensions are the app container dimensions. Specify either the
// fixed or the max variant of each axis.
type ContainerDimensions struct {
	Height    *float64 `json:"height,omitempty"`
	MaxHeight *float64 `json:"maxHeight,omitempty"`
	Width     *float64 `json:"width,omitempty"`
	MaxWidth  *float64 `json:"maxWidth,omitempty"`
}

// HostContext is rich context about the host environment provided to views.
type HostContext struct {
	ToolInfo              *ToolInfo            `json:"toolInfo,omitempty"`
	Theme                 Theme                `json:"theme,omitempty"`
	Styles                *HostStyles          `json:"styles,omitempty"`
	DisplayMode           DisplayMode          `json:"displayMode,omitempty"`
	AvailableDisplayModes []DisplayMode        `json:"availableDisplayModes,omitempty"`
	ContainerDimensions   *ContainerDimensions `json:"containerDimensions,omitempty"`
	Locale                string               `json:"locale,omitempty"`
	TimeZone              string               `json:"timeZone,omitempty"`
	UserAgent             string               `json:"userAgent,omitempty"`
	// Platform is "web", "desktop" or "mobile".
	Platform           string              `json:"platform,omitempty"`
	DeviceCapabilities *DeviceCapabilities `json:"deviceCapabilities,omitempty"`
	SafeAreaInsets     *SafeAreaInsets     `json:"safeAreaInsets,omitempty"`
}

// SupportedContentBlockModalities declares which content-block modalities a
// host accepts. Each field is a presence-only flag.
type SupportedContentBlockModalities struct {
	Text              present `json:"text,omitempty"`
	Image             present `json:"image,omitempty"`
	Audio             present `json:"audio,omitempty"`
	Resource          present `json:"resource,omitempty"`
	ResourceLink      present `json:"resourceLink,omitempty"`
	StructuredContent present `json:"structuredContent,omitempty"`
}

// ListChangedCapability is a capability with a listChanged flag.
type ListChangedCapability struct {
	ListChanged bool `json:"listChanged,omitempty"`
}

// SandboxCapability is the host's applied sandbox configuration.
type SandboxCapability struct {
	Permissions *ResourcePermissions `json:"permissions,omitempty"`
	CSP         *ResourceCsp         `json:"csp,omitempty"`
}

// SamplingCapability declares host sampling support.
type SamplingCapability struct {
	Tools present `json:"tools,omitempty"`
}

// HostCapabilities are the capabilities supported by the host application.
type HostCapabilities struct {
	Experimental       present                          `json:"experimental,omitempty"`
	OpenLinks          present                          `json:"openLinks,omitempty"`
	DownloadFile       present                          `json:"downloadFile,omitempty"`
	ServerTools        *ListChangedCapability           `json:"serverTools,omitempty"`
	ServerResources    *ListChangedCapability           `json:"serverResources,omitempty"`
	Logging            present                          `json:"logging,omitempty"`
	Sandbox            *SandboxCapability               `json:"sandbox,omitempty"`
	UpdateModelContext *SupportedContentBlockModalities `json:"updateModelContext,omitempty"`
	Message            *SupportedContentBlockModalities `json:"message,omitempty"`
	Sampling           *SamplingCapability              `json:"sampling,omitempty"`
}

// AppCapabilities are the capabilities provided by the View.
type AppCapabilities struct {
	Experimental          present                `json:"experimental,omitempty"`
	Tools                 *ListChangedCapability `json:"tools,omitempty"`
	AvailableDisplayModes []DisplayMode          `json:"availableDisplayModes,omitempty"`
}

// InitializeRequest initializes the bridge (View -> Host).
type InitializeRequest struct {
	Method string                  `json:"method"` // MethodInitialize
	Params InitializeRequestParams `json:"params"`
}

// Implementation is the name/version of an app or host implementation.
type Implementation struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Title   string `json:"title,omitempty"`
}

// InitializeRequestParams are the params of an InitializeRequest.
type InitializeRequestParams struct {
	AppInfo         Implementation  `json:"appInfo"`
	AppCapabilities AppCapabilities `json:"appCapabilities"`
	ProtocolVersion string          `json:"protocolVersion"`
}

// InitializeResult is returned from Host to View.
type InitializeResult struct {
	ProtocolVersion  string           `json:"protocolVersion"`
	HostInfo         Implementation   `json:"hostInfo"`
	HostCapabilities HostCapabilities `json:"hostCapabilities"`
	HostContext      HostContext      `json:"hostContext"`
}

// InitializedNotification signals the View finished initialization.
type InitializedNotification struct {
	Method string         `json:"method"` // MethodInitialized
	Params map[string]any `json:"params,omitempty"`
}

// ResourceCsp is the Content Security Policy configuration for a UI resource.
type ResourceCsp struct {
	// ConnectDomains are origins for network requests (CSP connect-src).
	ConnectDomains []string `json:"connectDomains,omitempty"`
	// ResourceDomains are origins for static resources (img/script/style/font/media-src).
	ResourceDomains []string `json:"resourceDomains,omitempty"`
	// FrameDomains are origins for nested iframes (CSP frame-src).
	FrameDomains []string `json:"frameDomains,omitempty"`
	// BaseUriDomains are allowed document base URIs (CSP base-uri).
	BaseUriDomains []string `json:"baseUriDomains,omitempty"`
}

// ResourcePermissions are sandbox permissions requested by a UI resource. Each
// field is a presence-only flag mapping to a Permissions-Policy feature.
type ResourcePermissions struct {
	Camera         present `json:"camera,omitempty"`
	Microphone     present `json:"microphone,omitempty"`
	Geolocation    present `json:"geolocation,omitempty"`
	ClipboardWrite present `json:"clipboardWrite,omitempty"`
}

// ResourceMeta is UI resource metadata for security and rendering.
type ResourceMeta struct {
	CSP         *ResourceCsp         `json:"csp,omitempty"`
	Permissions *ResourcePermissions `json:"permissions,omitempty"`
	// Domain is a dedicated sandbox origin (host-defined format).
	Domain string `json:"domain,omitempty"`
	// PrefersBorder requests a visible border/background; nil lets the host decide.
	PrefersBorder *bool `json:"prefersBorder,omitempty"`
}

// ToolMeta is UI-related metadata for tools.
type ToolMeta struct {
	// ResourceURI is the UI resource to display for this tool, if any.
	ResourceURI string `json:"resourceUri,omitempty"`
	// Visibility is who can access this tool (default ["model","app"]).
	Visibility []ToolVisibility `json:"visibility,omitempty"`
}

// ClientCapabilities are the MCP Apps capability settings a client advertises
// via the MCP extensions field.
type ClientCapabilities struct {
	// MimeTypes are the supported UI resource MIME types; must include MimeType.
	MimeTypes []string `json:"mimeTypes,omitempty"`
}
