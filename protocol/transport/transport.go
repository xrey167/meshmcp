// Package transport models the MCP transport layer — what a binding must
// provide to carry MCP messages — plus the well-known request-metadata keys
// shared by every binding. The concrete bindings live in the sub-packages
// stdio and streamablehttp.
//
// NOTE: transports are defined by the MCP specification prose (draft
// basic/transports), not by schema.ts, so this package holds constants and
// small helpers rather than generated wire types. It reflects the DRAFT
// revision (post-2025-06-18), which removed protocol-level HTTP sessions and
// server-initiated requests; see protocol/mrtr and protocol/subscriptions.
package transport

// MessageEncoding is the required character encoding for JSON-RPC messages on
// every transport.
const MessageEncoding = "UTF-8"

// Content types used to frame a response on HTTP-based transports.
const (
	// ContentTypeJSON is a single JSON-RPC object response.
	ContentTypeJSON = "application/json"
	// ContentTypeSSE is a request-scoped Server-Sent Events response stream.
	ContentTypeSSE = "text/event-stream"
)

// Well-known request-metadata keys. All protocol metadata travels in the
// message body under `_meta.io.modelcontextprotocol/*`; a binding MAY mirror
// selected fields into its envelope (e.g. HTTP headers), but the body remains
// the source of truth.
const (
	// MetaKeyProtocolVersion carries the request's protocol version.
	MetaKeyProtocolVersion = "io.modelcontextprotocol/protocolVersion"
	// MetaKeyClientInfo carries the client Implementation descriptor.
	MetaKeyClientInfo = "io.modelcontextprotocol/clientInfo"
	// MetaKeyClientCapabilities carries the per-request client capabilities.
	MetaKeyClientCapabilities = "io.modelcontextprotocol/clientCapabilities"
	// MetaKeyLogLevel carries the desired per-request log level (deprecated).
	MetaKeyLogLevel = "io.modelcontextprotocol/logLevel"
	// MetaKeyServerInfo carries the server Implementation descriptor on results.
	MetaKeyServerInfo = "io.modelcontextprotocol/serverInfo"
	// MetaKeySubscriptionID correlates a notification with its subscription.
	MetaKeySubscriptionID = "io.modelcontextprotocol/subscriptionId"
)

// MetaKeyProgressToken is the bare `_meta` key requesting out-of-band progress
// notifications for a request (not reverse-DNS prefixed).
const MetaKeyProgressToken = "progressToken"
