// Package base holds the foundational MCP protocol types shared across every
// other protocol/* package: the generic Request/Notification/Result envelopes,
// pagination primitives, common scalar types, and shared metadata.
//
// Generated from the Model Context Protocol schema.ts, revision 2025-06-18
// (https://github.com/modelcontextprotocol/modelcontextprotocol,
// schema/2025-06-18/schema.ts). One package per protocol domain.
package base

// ProtocolVersion is the MCP schema revision these models are generated from.
// Mirrors LATEST_PROTOCOL_VERSION in schema.ts.
const ProtocolVersion = "2025-06-18"

// Meta mirrors the open `_meta` object attached to requests, results and many
// protocol objects. See the spec's "General fields: _meta" notes.
type Meta = map[string]any

// ProgressToken associates progress notifications with the original request.
// In the schema it is `string | number`, so it is left dynamically typed.
type ProgressToken = any

// Cursor is an opaque token representing a pagination position.
type Cursor = string

// RequestId uniquely identifies a request in JSON-RPC. In the schema it is
// `string | number`, so it is left dynamically typed.
type RequestId = any

// Role is the sender or recipient of messages and data in a conversation.
type Role string

const (
	RoleUser      Role = "user"
	RoleAssistant Role = "assistant"
)

// RequestMeta is the `_meta` object carried on request params. It may request
// out-of-band progress notifications via ProgressToken.
type RequestMeta struct {
	// ProgressToken, if set, requests progress notifications for this request.
	ProgressToken ProgressToken `json:"progressToken,omitempty"`
}

// Request is the generic shape of any MCP request (schema `Request`).
// Concrete requests define their own typed params rather than embedding this.
type Request struct {
	Method string         `json:"method"`
	Params map[string]any `json:"params,omitempty"`
}

// Notification is the generic shape of any MCP notification (schema
// `Notification`). Concrete notifications define their own typed params.
type Notification struct {
	Method string         `json:"method"`
	Params map[string]any `json:"params,omitempty"`
}

// Result is the base of every response payload (schema `Result`). It carries
// the open `_meta` object and is embedded by concrete results.
type Result struct {
	Meta Meta `json:"_meta,omitempty"`
}

// EmptyResult is a response that indicates success but carries no data.
type EmptyResult = Result

// PaginatedParams are the params shared by every paginated request.
type PaginatedParams struct {
	// Cursor is an opaque token representing the current pagination position.
	Cursor Cursor `json:"cursor,omitempty"`
}

// PaginatedRequest is the generic shape of a paginated request.
type PaginatedRequest struct {
	Method string           `json:"method"`
	Params *PaginatedParams `json:"params,omitempty"`
}

// PaginatedResult is embedded by every paginated response. NextCursor, when
// present, indicates more results are available.
type PaginatedResult struct {
	Result
	NextCursor Cursor `json:"nextCursor,omitempty"`
}

// BaseMetadata is the name (identifier) / title (display name) pair shared by
// resources, prompts, tools and implementations.
type BaseMetadata struct {
	// Name is intended for programmatic or logical use.
	Name string `json:"name"`
	// Title is the human-readable display name. Falls back to Name when unset.
	Title string `json:"title,omitempty"`
}

// Annotations let the client inform how objects are used or displayed.
type Annotations struct {
	// Audience describes who the intended customer of this data is.
	Audience []Role `json:"audience,omitempty"`
	// Priority describes how important this data is, from 0 (least) to 1 (most).
	Priority *float64 `json:"priority,omitempty"`
	// LastModified is the ISO 8601 timestamp the resource was last modified.
	LastModified string `json:"lastModified,omitempty"`
}
