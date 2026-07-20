// Package tool holds the tool domain: tool definitions and annotations, and
// the tools/* request, result and notification types.
package tool

import (
	"encoding/json"

	"github.com/xrey167/meshmcp/protocol/base"
	"github.com/xrey167/meshmcp/protocol/content"
)

// Method names in the tool domain.
const (
	MethodList        = "tools/list"
	MethodCall        = "tools/call"
	MethodListChanged = "notifications/tools/list_changed"
)

// Schema is a convenience shape for building a simple object JSON Schema. Tool
// input/output schemas on the wire are arbitrary JSON Schema (2020-12), so the
// Tool fields keep them as raw JSON; use this type only when constructing a
// plain object schema.
type Schema struct {
	Type       string         `json:"type"` // typically "object"
	Properties map[string]any `json:"properties,omitempty"`
	Required   []string       `json:"required,omitempty"`
}

// Annotations are additional, hint-only properties describing a Tool. Clients
// should never make tool-use decisions based on annotations from untrusted
// servers.
type Annotations struct {
	// Title is a human-readable title for the tool.
	Title string `json:"title,omitempty"`
	// ReadOnlyHint: if true, the tool does not modify its environment.
	ReadOnlyHint *bool `json:"readOnlyHint,omitempty"`
	// DestructiveHint: if true, the tool may perform destructive updates.
	DestructiveHint *bool `json:"destructiveHint,omitempty"`
	// IdempotentHint: if true, repeated calls with the same args have no
	// additional effect.
	IdempotentHint *bool `json:"idempotentHint,omitempty"`
	// OpenWorldHint: if true, the tool interacts with an open world of external
	// entities.
	OpenWorldHint *bool `json:"openWorldHint,omitempty"`
}

// Tool is a definition for a tool the client can call.
type Tool struct {
	base.BaseMetadata
	// Description is a human-readable description of the tool.
	Description string `json:"description,omitempty"`
	// InputSchema is the tool's input JSON Schema (arbitrary JSON Schema 2020-12,
	// e.g. with oneOf/anyOf/items), kept as raw JSON.
	InputSchema json.RawMessage `json:"inputSchema"`
	// OutputSchema optionally defines the tool's structured output as arbitrary
	// JSON Schema (e.g. an array schema), kept as raw JSON.
	OutputSchema json.RawMessage `json:"outputSchema,omitempty"`
	// Annotations are optional additional tool information (hints).
	Annotations *Annotations `json:"annotations,omitempty"`
	// Meta is the open `_meta` object.
	Meta base.Meta `json:"_meta,omitempty"`
}

// ListRequest is sent from the client to request a list of tools.
type ListRequest struct {
	Method string                `json:"method"` // MethodList
	Params *base.PaginatedParams `json:"params,omitempty"`
}

// ListResult is the server's response to a tools/list request.
type ListResult struct {
	base.PaginatedResult
	Tools []Tool `json:"tools"`
}

// CallRequest is used by the client to invoke a tool provided by the server.
type CallRequest struct {
	Method string            `json:"method"` // MethodCall
	Params CallRequestParams `json:"params"`
}

// CallRequestParams are the params of a CallRequest.
type CallRequestParams struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments,omitempty"`
}

// CallResult is the server's response to a tool call.
type CallResult struct {
	base.Result
	// Content is the unstructured result of the tool call.
	Content []content.Block `json:"content"`
	// StructuredContent is the optional structured result. Its shape is defined
	// by the tool's outputSchema, not the protocol, so it is kept as raw JSON
	// (the draft revision types it as arbitrary JSON — object, array or scalar).
	StructuredContent json.RawMessage `json:"structuredContent,omitempty"`
	// IsError reports whether the tool call ended in an error. Tool-level errors
	// are reported here, not as MCP protocol-level errors.
	IsError bool `json:"isError,omitempty"`
}

// UnmarshalJSON decodes the polymorphic content block slice.
func (r *CallResult) UnmarshalJSON(data []byte) error {
	var raw struct {
		Meta              base.Meta         `json:"_meta"`
		Content           []json.RawMessage `json:"content"`
		StructuredContent json.RawMessage   `json:"structuredContent"`
		IsError           bool              `json:"isError"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	r.Meta = raw.Meta
	r.StructuredContent = raw.StructuredContent
	r.IsError = raw.IsError
	r.Content = make([]content.Block, 0, len(raw.Content))
	for _, item := range raw.Content {
		b, err := content.DecodeBlock(item)
		if err != nil {
			return err
		}
		r.Content = append(r.Content, b)
	}
	return nil
}

// ListChangedNotification informs the client that the list of tools changed.
type ListChangedNotification struct {
	Method string `json:"method"` // MethodListChanged
}
