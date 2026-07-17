// Package mcperror models the draft MCP error catalog: the JSON-RPC error
// object, the error-response envelope, the standard and MCP-reserved error
// codes, and the structured data payloads the MCP-defined errors carry.
//
// Reflects the DRAFT revision, which formalizes an error catalog and reserves
// the -32020..-32099 sub-range for MCP-defined codes. Not part of 2025-06-18.
package mcperror

// Standard JSON-RPC 2.0 error codes.
const (
	CodeParseError     = -32700
	CodeInvalidRequest = -32600
	CodeMethodNotFound = -32601
	CodeInvalidParams  = -32602
	CodeInternalError  = -32603
)

// MCP-reserved error codes. JSON-RPC reserves -32000..-32099 for
// implementation-defined server errors; MCP partitions -32020..-32099 for
// specification-defined codes, allocated sequentially from -32020.
const (
	// CodeHeaderMismatch: HTTP headers do not match the request body, or a
	// required header is missing or malformed (HTTP 400).
	CodeHeaderMismatch = -32020
	// CodeMissingRequiredClientCapability: the request requires a client
	// capability that was not declared in clientCapabilities (HTTP 400).
	CodeMissingRequiredClientCapability = -32021
	// CodeUnsupportedProtocolVersion: the request's protocol version is not
	// supported by the server (HTTP 400).
	CodeUnsupportedProtocolVersion = -32022
)

// Error is the JSON-RPC error object.
type Error struct {
	// Code is the error type that occurred.
	Code int `json:"code"`
	// Message is a short, single-sentence description of the error.
	Message string `json:"message"`
	// Data is optional, sender-defined additional information. For MCP-defined
	// errors it is one of the *Data types in this package.
	Data any `json:"data,omitempty"`
}

// Error implements the error interface.
func (e *Error) Error() string { return e.Message }

// New builds an Error with the given code, message and optional data.
func New(code int, message string, data any) *Error {
	return &Error{Code: code, Message: message, Data: data}
}

// ErrorResponse is a JSON-RPC error response. Per the draft, the id MAY be
// absent (e.g. a parse error before the id could be read).
type ErrorResponse struct {
	JSONRPC string `json:"jsonrpc"` // always "2.0"
	ID      any    `json:"id,omitempty"`
	Error   Error  `json:"error"`
}

// UnsupportedProtocolVersionData is the data payload of an
// UnsupportedProtocolVersion (-32022) error.
type UnsupportedProtocolVersionData struct {
	// Supported lists the protocol versions the server supports; the client
	// should choose a mutually supported version and retry.
	Supported []string `json:"supported"`
	// Requested is the protocol version the client asked for.
	Requested string `json:"requested"`
}

// MissingRequiredClientCapabilityData is the data payload of a
// MissingRequiredClientCapability (-32021) error.
type MissingRequiredClientCapabilityData struct {
	// RequiredCapabilities are the client capabilities the server needs to
	// process the request (a draft ClientCapabilities object).
	RequiredCapabilities map[string]any `json:"requiredCapabilities"`
}
