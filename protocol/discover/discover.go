// Package discover models the draft server/discover handshake, which replaces
// the initialize request/result of earlier revisions. The server advertises
// its supported protocol versions, capabilities and instructions; clients MAY
// call it but version negotiation can also happen inline via per-request _meta.
//
// Reflects the DRAFT revision (server/discover). Not part of 2025-06-18, whose
// handshake is modelled in protocol/initialize.
package discover

import (
	"encoding/json"

	"meshmcp/protocol/base"
)

// Method is the JSON-RPC method name for the discovery request.
const Method = "server/discover"

// Result-type discriminator values carried on a draft Result's resultType field.
const (
	ResultTypeComplete      = "complete"
	ResultTypeInputRequired = "input_required"
)

// CacheScope indicates the intended scope of a cached response (analogous to
// HTTP Cache-Control public vs private).
type CacheScope string

const (
	// CachePublic: the response holds no user-specific data and MAY be shared
	// across authorization contexts.
	CachePublic CacheScope = "public"
	// CachePrivate: the response MAY be reused only within the same
	// authorization context.
	CachePrivate CacheScope = "private"
)

// CacheableResult is the base of results that carry a client-side caching hint
// (draft CacheableResult, extending the draft Result with resultType).
type CacheableResult struct {
	// Meta is the open `_meta` object.
	Meta base.Meta `json:"_meta,omitempty"`
	// ResultType lets the client decide how to parse the result. Servers on this
	// revision MUST include it; an absent value is treated as "complete".
	ResultType string `json:"resultType"`
	// TTLMs is how long (ms) the client MAY cache this response. 0 means
	// immediately stale.
	TTLMs float64 `json:"ttlMs"`
	// CacheScope is the caching scope, "public" or "private".
	CacheScope CacheScope `json:"cacheScope"`
}

// DiscoverRequest asks the server to advertise its capabilities and metadata.
type DiscoverRequest struct {
	Method string         `json:"method"` // Method
	Params map[string]any `json:"params,omitempty"`
}

// DiscoverResult is the server's response to a server/discover request.
type DiscoverResult struct {
	CacheableResult
	// SupportedVersions are the MCP protocol versions this server supports; the
	// client should choose one for subsequent requests.
	SupportedVersions []string `json:"supportedVersions"`
	// Capabilities are the server's capabilities.
	Capabilities ServerCapabilities `json:"capabilities"`
	// Instructions is natural-language guidance describing the server and its
	// features, e.g. for inclusion in a system prompt.
	Instructions string `json:"instructions,omitempty"`
}

// ServerCapabilities are the capabilities a server may support (draft
// server/discover). The set is open; unknown capabilities are ignored.
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
	// Extensions are the MCP extensions the server supports, keyed by extension
	// identifier (reverse-DNS, following the _meta key naming rules).
	Extensions map[string]any `json:"extensions,omitempty"`
}

// PromptsCapability describes server support for prompt templates.
type PromptsCapability struct {
	ListChanged bool `json:"listChanged,omitempty"`
}

// ResourcesCapability describes server support for resources.
type ResourcesCapability struct {
	Subscribe   bool `json:"subscribe,omitempty"`
	ListChanged bool `json:"listChanged,omitempty"`
}

// ToolsCapability describes server support for tools.
type ToolsCapability struct {
	ListChanged bool `json:"listChanged,omitempty"`
}

// ClientCapabilities are the capabilities a client may support (draft
// server/discover). Presence-based capabilities are kept as raw JSON so that a
// present-but-empty object ("{}") is preserved distinctly from an absent one.
type ClientCapabilities struct {
	// Experimental holds non-standard capabilities the client supports.
	Experimental map[string]any `json:"experimental,omitempty"`
	// Roots is present if the client supports listing roots.
	//
	// Deprecated: deprecated as of protocol version 2026-07-28 (SEP-2577).
	Roots json.RawMessage `json:"roots,omitempty"`
	// Sampling is present if the client supports sampling from an LLM.
	Sampling *SamplingCapability `json:"sampling,omitempty"`
	// Elicitation is present if the client supports elicitation from the server.
	Elicitation *ElicitationCapability `json:"elicitation,omitempty"`
	// Extensions are the MCP extensions the client supports, keyed by extension
	// identifier (reverse-DNS, following the _meta key naming rules).
	Extensions map[string]any `json:"extensions,omitempty"`
}

// SamplingCapability describes client support for LLM sampling. A present-empty
// object signals baseline support; the sub-fields opt into optional features.
type SamplingCapability struct {
	// Context signals support for context inclusion via includeContext.
	Context json.RawMessage `json:"context,omitempty"`
	// Tools signals support for tool use via tools and toolChoice.
	Tools json.RawMessage `json:"tools,omitempty"`
}

// ElicitationCapability describes client support for elicitation modes. A
// present-empty object implies form mode only.
type ElicitationCapability struct {
	// Form signals support for form-mode elicitation.
	Form json.RawMessage `json:"form,omitempty"`
	// URL signals support for URL-mode elicitation.
	URL json.RawMessage `json:"url,omitempty"`
}
