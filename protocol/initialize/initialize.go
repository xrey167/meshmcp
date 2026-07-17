// Package initialize holds the connection-handshake types: the initialize
// request/result, the initialized notification, and the client/server
// capability and implementation descriptors (schema @category `initialize`).
package initialize

import "meshmcp/protocol/base"

// Method names in the initialization flow.
const (
	MethodInitialize  = "initialize"
	MethodInitialized = "notifications/initialized"
)

// Implementation describes the name and version of an MCP implementation, with
// an optional title for UI representation.
type Implementation struct {
	base.BaseMetadata
	Version string `json:"version"`
}

// ClientCapabilities are the capabilities a client may support. Known
// capabilities are defined here, but the set is open.
type ClientCapabilities struct {
	// Experimental holds non-standard capabilities the client supports.
	Experimental map[string]any `json:"experimental,omitempty"`
	// Roots is present if the client supports listing roots.
	Roots *RootsCapability `json:"roots,omitempty"`
	// Sampling is present if the client supports sampling from an LLM.
	Sampling map[string]any `json:"sampling,omitempty"`
	// Elicitation is present if the client supports elicitation from the server.
	Elicitation map[string]any `json:"elicitation,omitempty"`
}

// RootsCapability describes client support for listing roots.
type RootsCapability struct {
	// ListChanged reports whether the client emits notifications for changes to
	// the roots list.
	ListChanged bool `json:"listChanged,omitempty"`
}

// ServerCapabilities are the capabilities a server may support. Known
// capabilities are defined here, but the set is open.
type ServerCapabilities struct {
	// Experimental holds non-standard capabilities the server supports.
	Experimental map[string]any `json:"experimental,omitempty"`
	// Logging is present if the server supports sending log messages.
	Logging map[string]any `json:"logging,omitempty"`
	// Completions is present if the server supports argument autocompletion.
	Completions map[string]any `json:"completions,omitempty"`
	// Prompts is present if the server offers any prompt templates.
	Prompts *PromptsCapability `json:"prompts,omitempty"`
	// Resources is present if the server offers any resources to read.
	Resources *ResourcesCapability `json:"resources,omitempty"`
	// Tools is present if the server offers any tools to call.
	Tools *ToolsCapability `json:"tools,omitempty"`
}

// PromptsCapability describes server support for prompt templates.
type PromptsCapability struct {
	// ListChanged reports whether the server notifies on prompt-list changes.
	ListChanged bool `json:"listChanged,omitempty"`
}

// ResourcesCapability describes server support for resources.
type ResourcesCapability struct {
	// Subscribe reports whether the server supports subscribing to resource updates.
	Subscribe bool `json:"subscribe,omitempty"`
	// ListChanged reports whether the server notifies on resource-list changes.
	ListChanged bool `json:"listChanged,omitempty"`
}

// ToolsCapability describes server support for tools.
type ToolsCapability struct {
	// ListChanged reports whether the server notifies on tool-list changes.
	ListChanged bool `json:"listChanged,omitempty"`
}

// InitializeRequest is sent from the client to the server when it first
// connects, asking it to begin initialization.
type InitializeRequest struct {
	Method string                  `json:"method"` // MethodInitialize
	Params InitializeRequestParams `json:"params"`
}

// InitializeRequestParams are the params of an InitializeRequest.
type InitializeRequestParams struct {
	// ProtocolVersion is the latest MCP version the client supports.
	ProtocolVersion string             `json:"protocolVersion"`
	Capabilities    ClientCapabilities `json:"capabilities"`
	ClientInfo      Implementation     `json:"clientInfo"`
}

// InitializeResult is the server's response to an initialize request.
type InitializeResult struct {
	base.Result
	// ProtocolVersion is the MCP version the server wants to use.
	ProtocolVersion string             `json:"protocolVersion"`
	Capabilities    ServerCapabilities `json:"capabilities"`
	ServerInfo      Implementation     `json:"serverInfo"`
	// Instructions describe how to use the server and its features.
	Instructions string `json:"instructions,omitempty"`
}

// InitializedNotification is sent from the client to the server after
// initialization has finished.
type InitializedNotification struct {
	Method string `json:"method"` // MethodInitialized
}
