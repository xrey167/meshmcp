// Package servercard models the experimental MCP Server Card extension: a
// static metadata document describing a remote MCP server for pre-connection
// discovery (identity, transport, protocol versions).
//
// Source of truth: modelcontextprotocol/experimental-ext-server-card
// (schema.ts). This is an EXPERIMENTAL extension (Server Card WG, SEP-2127),
// not part of the core 2025-06-18 schema; fields are advisory, not
// authoritative for security decisions.
package servercard

import "github.com/xrey167/meshmcp/protocol/base"

// SchemaURI is the required $schema value a v1 Server Card must declare.
const SchemaURI = "https://static.modelcontextprotocol.io/schemas/v1/server-card.schema.json"

// RecommendedPath is the recommended discovery location relative to a remote
// server's Streamable HTTP URL: GET <streamable-http-url>/server-card.
const RecommendedPath = "/server-card"

// ServerCard is a static metadata document describing a remote MCP server. It
// declares only what is needed to discover and connect (identity, transport,
// protocol versions) and does not enumerate tools, resources or prompts.
type ServerCard struct {
	// Schema is the Server Card JSON Schema URI this document conforms to.
	// Must equal SchemaURI. Marshals to "$schema".
	Schema string `json:"$schema"`
	// Name is the server name in reverse-DNS format with exactly one slash
	// separating namespace from server name.
	Name string `json:"name"`
	// Version is the server version, SHOULD follow semantic versioning.
	Version string `json:"version"`
	// Description is a human-readable explanation of server functionality.
	Description string `json:"description"`
	// Title is an optional display name.
	Title string `json:"title,omitempty"`
	// WebsiteURL is an optional link to the server's homepage or docs.
	WebsiteURL string `json:"websiteUrl,omitempty"`
	// Repository is optional source-code repository metadata.
	Repository *Repository `json:"repository,omitempty"`
	// Icons is an optional set of sized icons for display.
	Icons []Icon `json:"icons,omitempty"`
	// Remotes is optional metadata for HTTP-based connections to this server.
	Remotes []Remote `json:"remotes,omitempty"`
	// Meta is extension metadata using reverse-DNS namespacing.
	Meta base.Meta `json:"_meta,omitempty"`
}

// Repository is source-code repository metadata for the MCP server.
type Repository struct {
	// URL for browsing source code and git clone.
	URL string `json:"url"`
	// Source is the hosting service identifier (e.g. "github").
	Source string `json:"source"`
	// Subfolder is an optional relative path to the server within a monorepo.
	Subfolder string `json:"subfolder,omitempty"`
	// ID is the optional forge-owned repository identifier, stable across renames.
	ID string `json:"id,omitempty"`
}

// RemoteType is the transport type of a remote endpoint.
type RemoteType string

const (
	RemoteStreamableHTTP RemoteType = "streamable-http"
	RemoteSSE            RemoteType = "sse"
)

// Remote is metadata for connecting to a remote (HTTP-based) MCP endpoint.
type Remote struct {
	// Type is the transport type for this remote endpoint.
	Type RemoteType `json:"type"`
	// URL is a template for the endpoint; {curly_braces} variables are
	// substituted from Variables before connecting.
	URL string `json:"url"`
	// Headers describes HTTP headers required or accepted for the connection.
	Headers []KeyValueInput `json:"headers,omitempty"`
	// Variables are the configuration variables referenced as {curly_braces}
	// placeholders in URL and header values.
	Variables map[string]Input `json:"variables,omitempty"`
	// SupportedProtocolVersions are the MCP versions this endpoint supports.
	SupportedProtocolVersions []string `json:"supportedProtocolVersions,omitempty"`
}

// InputFormat constrains how an Input value is interpreted.
type InputFormat string

const (
	InputString   InputFormat = "string"
	InputNumber   InputFormat = "number"
	InputBoolean  InputFormat = "boolean"
	InputFilepath InputFormat = "filepath"
)

// Input is a user-supplied or pre-set input value used for Remote URL variables
// and header values.
type Input struct {
	// Description is a human-readable explanation of the input.
	Description string `json:"description,omitempty"`
	// IsRequired reports whether the input must be supplied.
	IsRequired *bool `json:"isRequired,omitempty"`
	// IsSecret reports whether the input is a secret value.
	IsSecret *bool `json:"isSecret,omitempty"`
	// Format specifies the input format.
	Format InputFormat `json:"format,omitempty"`
	// Default is the default value for the input.
	Default string `json:"default,omitempty"`
	// Placeholder is example/guidance text shown during configuration.
	Placeholder string `json:"placeholder,omitempty"`
	// Value is a pre-set, non-user-configurable value; {curly_braces} identifiers
	// are substituted from the variables map.
	Value string `json:"value,omitempty"`
	// Choices, if set, restricts the input to one of these values.
	Choices []string `json:"choices,omitempty"`
}

// KeyValueInput is a named Input used for HTTP headers, whose Value may
// reference variables for substitution.
type KeyValueInput struct {
	Input
	// Name of the header.
	Name string `json:"name"`
	// Variables referenced by {curly_braces} identifiers in Value.
	Variables map[string]Input `json:"variables,omitempty"`
}

// IconTheme indicates the background an icon is designed for.
type IconTheme string

const (
	IconLight IconTheme = "light"
	IconDark  IconTheme = "dark"
)

// Icon is an optionally-sized icon that can be displayed in a user interface.
type Icon struct {
	// Src is a URI pointing to an icon resource (HTTP(S) URL or data: URI).
	Src string `json:"src"`
	// MimeType optionally overrides the source MIME type.
	MimeType string `json:"mimeType,omitempty"`
	// Sizes lists the sizes the icon can be used at ("WxH" or "any").
	Sizes []string `json:"sizes,omitempty"`
	// Theme optionally specifies the background theme ("light" or "dark").
	Theme IconTheme `json:"theme,omitempty"`
}
