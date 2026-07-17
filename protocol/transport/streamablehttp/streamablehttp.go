// Package streamablehttp models the Streamable HTTP transport binding: each
// JSON-RPC message is an HTTP POST to a single MCP endpoint, and replies arrive
// as a JSON object or a request-scoped SSE stream.
//
// Reflects the DRAFT transports revision (2026-07-28 shape): no protocol-level
// sessions, no GET stream endpoint, no server-initiated requests — server-to-
// client interactions are embedded as input requests per MRTR
// (see protocol/mrtr).
package streamablehttp

import (
	"encoding/base64"
	"fmt"
	"strings"
)

// Standard request headers mirrored from the JSON-RPC body so intermediaries
// can route and inspect requests without parsing it.
const (
	// HeaderProtocolVersion MUST be present on every POST and match the body's
	// io.modelcontextprotocol/protocolVersion.
	HeaderProtocolVersion = "MCP-Protocol-Version"
	// HeaderMethod mirrors the JSON-RPC "method" and is required on all requests.
	HeaderMethod = "Mcp-Method"
	// HeaderName mirrors params.name or params.uri; required for tools/call,
	// resources/read and prompts/get.
	HeaderName = "Mcp-Name"
	// HeaderParamPrefix prefixes headers mirrored from tool parameters annotated
	// with x-mcp-header, e.g. "Mcp-Param-Region".
	HeaderParamPrefix = "Mcp-Param-"
	// HeaderAccelBuffering SHOULD be set to "no" when opening an SSE stream to
	// stop reverse proxies from buffering events.
	HeaderAccelBuffering = "X-Accel-Buffering"
)

// SchemaExtHeader is the tool inputSchema extension property that designates a
// parameter to be mirrored into an Mcp-Param-{name} header.
const SchemaExtHeader = "x-mcp-header"

// ParamHeaderName builds the header name for a parameter annotated with the
// given x-mcp-header name (e.g. "Region" -> "Mcp-Param-Region").
func ParamHeaderName(name string) string {
	return HeaderParamPrefix + name
}

// Protocol-defined JSON-RPC error codes surfaced by this transport.
const (
	// CodeHeaderMismatch is returned (with HTTP 400) when the HTTP headers do not
	// match the corresponding request-body values, or a required header is
	// missing or malformed.
	CodeHeaderMismatch = -32020
	// CodeMethodNotFound is returned (with HTTP 404) when the server does not
	// implement the requested RPC method.
	CodeMethodNotFound = -32601
)

// Base64 sentinel markers for header values that cannot be represented as plain
// ASCII (RFC 2047-style, lowercase and case-sensitive).
const (
	sentinelPrefix = "=?base64?"
	sentinelSuffix = "?="
)

// NeedsEncoding reports whether a header value must be Base64-sentinel encoded:
// when it contains non-ASCII or control characters, has leading or trailing
// whitespace, or would itself be mistaken for the sentinel format.
func NeedsEncoding(value string) bool {
	if strings.HasPrefix(value, sentinelPrefix) && strings.HasSuffix(value, sentinelSuffix) {
		return true
	}
	if value != strings.TrimSpace(value) {
		return true
	}
	for i := 0; i < len(value); i++ {
		if c := value[i]; c < 0x20 || c > 0x7e {
			return true
		}
	}
	return false
}

// EncodeHeaderValue returns a header-safe representation of value, applying the
// Base64 sentinel encoding only when required.
func EncodeHeaderValue(value string) string {
	if !NeedsEncoding(value) {
		return value
	}
	return sentinelPrefix + base64.StdEncoding.EncodeToString([]byte(value)) + sentinelSuffix
}

// DecodeHeaderValue reverses EncodeHeaderValue: a sentinel-wrapped value is
// Base64-decoded, any other value is returned unchanged. Servers MUST decode
// before comparing a header to the request body.
func DecodeHeaderValue(value string) (string, error) {
	if !(strings.HasPrefix(value, sentinelPrefix) && strings.HasSuffix(value, sentinelSuffix)) {
		return value, nil
	}
	encoded := value[len(sentinelPrefix) : len(value)-len(sentinelSuffix)]
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("streamablehttp: invalid base64 header value: %w", err)
	}
	return string(decoded), nil
}
