// Package subscriptions models the subscriptions/listen pattern, introduced in
// the DRAFT MCP revision. It opens a long-lived server-to-client notification
// stream and replaces the former resources/subscribe RPC and the HTTP GET
// stream endpoint.
//
// This is a draft-era pattern and is NOT part of the 2025-06-18 schema.ts the
// protocol/* base models are generated from. The dependency-free server
// framework in mcp/ serves this pattern (see mcp/subscriptions.go); these
// types are the canonical wire model it mirrors.
package subscriptions

import "github.com/xrey167/meshmcp/protocol/base"

// Method names in the subscriptions domain.
const (
	MethodListen       = "subscriptions/listen"
	MethodAcknowledged = "notifications/subscriptions/acknowledged"
)

// MetaKeySubscriptionID is the `_meta` key carrying the subscription's ID (the
// JSON-RPC id of the subscriptions/listen request) on the acknowledgment and
// every notification delivered on the stream.
const MetaKeySubscriptionID = "io.modelcontextprotocol/subscriptionId"

// ResultTypeComplete marks the empty result the server sends to close a
// subscription gracefully.
const ResultTypeComplete = "complete"

// Filter selects which notification types a subscription delivers. All fields
// are optional; an omitted field means "not subscribed" to that type. The
// server MUST NOT send notification types the client did not request.
type Filter struct {
	// ToolsListChanged requests notifications/tools/list_changed.
	ToolsListChanged bool `json:"toolsListChanged,omitempty"`
	// PromptsListChanged requests notifications/prompts/list_changed.
	PromptsListChanged bool `json:"promptsListChanged,omitempty"`
	// ResourcesListChanged requests notifications/resources/list_changed.
	ResourcesListChanged bool `json:"resourcesListChanged,omitempty"`
	// ResourceSubscriptions requests notifications/resources/updated for these
	// resource URIs.
	ResourceSubscriptions []string `json:"resourceSubscriptions,omitempty"`
}

// ListenRequest opens a long-lived notification stream.
type ListenRequest struct {
	Method string              `json:"method"` // MethodListen
	Params ListenRequestParams `json:"params"`
}

// ListenRequestParams are the params of a ListenRequest.
type ListenRequestParams struct {
	// Meta carries the request metadata (protocol version, client info, etc.).
	Meta base.Meta `json:"_meta,omitempty"`
	// Notifications is the filter of event types the client wants.
	Notifications Filter `json:"notifications"`
}

// ListenResult is the empty response the server sends to signal a graceful end
// of the subscription before closing the stream.
type ListenResult struct {
	base.Result
	// ResultType is always ResultTypeComplete.
	ResultType string `json:"resultType"`
}

// AcknowledgedNotification is the first message on the stream, echoing the
// subset of the filter the server agreed to honor and carrying the subscription
// ID in `_meta`.
type AcknowledgedNotification struct {
	Method string                         `json:"method"` // MethodAcknowledged
	Params AcknowledgedNotificationParams `json:"params"`
}

// AcknowledgedNotificationParams are the params of an AcknowledgedNotification.
type AcknowledgedNotificationParams struct {
	// Meta carries MetaKeySubscriptionID.
	Meta base.Meta `json:"_meta"`
	// Notifications reflects the subset of the requested filter the server
	// honors; unsupported types are omitted.
	Notifications Filter `json:"notifications"`
}
