package authorization

// ProtectedResourceMetadata is the OAuth 2.0 Protected Resource Metadata
// document (RFC 9728) an MCP server publishes so clients can locate its
// authorization servers. MCP requires AuthorizationServers to contain at least
// one entry.
type ProtectedResourceMetadata struct {
	// Resource is the protected resource's identifier (its resource URI).
	Resource string `json:"resource"`
	// AuthorizationServers lists the issuer identifiers of the authorization
	// servers that can issue tokens for this resource. MCP requires at least one.
	AuthorizationServers []string `json:"authorization_servers,omitempty"`
	// JWKSURI is the URL of the resource's JSON Web Key Set, if any.
	JWKSURI string `json:"jwks_uri,omitempty"`
	// ScopesSupported lists the scopes the resource recognizes.
	ScopesSupported []string `json:"scopes_supported,omitempty"`
	// BearerMethodsSupported lists how a bearer token may be presented
	// (e.g. "header", "body", "query").
	BearerMethodsSupported []string `json:"bearer_methods_supported,omitempty"`
	// ResourceDocumentation is a URL to human-readable resource documentation.
	ResourceDocumentation string `json:"resource_documentation,omitempty"`
}

// AuthorizationServerMetadata is the OAuth 2.0 Authorization Server Metadata
// document (RFC 8414), which is a superset compatible with OpenID Connect
// Discovery 1.0 Provider Metadata. Only the fields MCP relies on are modelled;
// unknown fields are ignored on decode.
type AuthorizationServerMetadata struct {
	// Issuer is the authorization server's identifier. It MUST equal the issuer
	// used to construct the discovery URL (RFC 8414 Section 3.3 validation).
	Issuer string `json:"issuer"`
	// AuthorizationEndpoint is the OAuth authorization endpoint URL.
	AuthorizationEndpoint string `json:"authorization_endpoint,omitempty"`
	// TokenEndpoint is the OAuth token endpoint URL.
	TokenEndpoint string `json:"token_endpoint,omitempty"`
	// RegistrationEndpoint is the Dynamic Client Registration endpoint (RFC 7591);
	// its presence signals DCR support.
	RegistrationEndpoint string `json:"registration_endpoint,omitempty"`
	// JWKSURI is the URL of the server's JSON Web Key Set.
	JWKSURI string `json:"jwks_uri,omitempty"`
	// ScopesSupported lists the scopes the server supports.
	ScopesSupported []string `json:"scopes_supported,omitempty"`
	// ResponseTypesSupported lists the supported OAuth response types.
	ResponseTypesSupported []string `json:"response_types_supported,omitempty"`
	// GrantTypesSupported lists the supported OAuth grant types.
	GrantTypesSupported []string `json:"grant_types_supported,omitempty"`
	// TokenEndpointAuthMethodsSupported lists the token-endpoint client
	// authentication methods the server supports.
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported,omitempty"`
	// CodeChallengeMethodsSupported lists the PKCE code-challenge methods. Its
	// absence means the server does not support PKCE, and MCP clients MUST refuse
	// to proceed.
	CodeChallengeMethodsSupported []string `json:"code_challenge_methods_supported,omitempty"`
	// ClientIDMetadataDocumentSupported is the MCP-relevant extension signalling
	// support for OAuth Client ID Metadata Documents.
	ClientIDMetadataDocumentSupported bool `json:"client_id_metadata_document_supported,omitempty"`
}

// SupportsPKCE reports whether the server advertises any PKCE code-challenge
// method. MCP clients MUST refuse to proceed when this is false.
func (m AuthorizationServerMetadata) SupportsPKCE() bool {
	return len(m.CodeChallengeMethodsSupported) > 0
}

// ClientIDMetadataDocument is the JSON document a client hosts at an HTTPS URL
// that doubles as its client_id (OAuth Client ID Metadata Document draft). The
// client_id value MUST equal the document's own URL. ClientID, ClientName and
// RedirectURIs are required.
type ClientIDMetadataDocument struct {
	// ClientID is the HTTPS URL identifying the client; MUST equal the document URL.
	ClientID string `json:"client_id"`
	// ClientName is the human-readable client name shown on the consent page.
	ClientName string `json:"client_name"`
	// RedirectURIs are the client's allowed redirect URIs.
	RedirectURIs []string `json:"redirect_uris"`
	// ClientURI is a URL to the client's homepage.
	ClientURI string `json:"client_uri,omitempty"`
	// LogoURI is a URL to the client's logo.
	LogoURI string `json:"logo_uri,omitempty"`
	// GrantTypes lists the grant types the client uses.
	GrantTypes []string `json:"grant_types,omitempty"`
	// ResponseTypes lists the response types the client uses.
	ResponseTypes []string `json:"response_types,omitempty"`
	// TokenEndpointAuthMethod is the client's token-endpoint auth method.
	TokenEndpointAuthMethod string `json:"token_endpoint_auth_method,omitempty"`
	// JWKSURI is the client's JSON Web Key Set URL (for private_key_jwt).
	JWKSURI string `json:"jwks_uri,omitempty"`
}

// ClientRegistrationRequest is an OAuth 2.0 Dynamic Client Registration request
// (RFC 7591). ApplicationType SHOULD be set to disambiguate native vs web
// redirect-URI handling under OIDC.
type ClientRegistrationRequest struct {
	// RedirectURIs are the client's redirect URIs.
	RedirectURIs []string `json:"redirect_uris,omitempty"`
	// ApplicationType is "native" or "web"; omitting it defaults to "web" (OIDC).
	ApplicationType string `json:"application_type,omitempty"`
	// ClientName is the human-readable client name.
	ClientName string `json:"client_name,omitempty"`
	// ClientURI is a URL to the client's homepage.
	ClientURI string `json:"client_uri,omitempty"`
	// LogoURI is a URL to the client's logo.
	LogoURI string `json:"logo_uri,omitempty"`
	// GrantTypes lists the requested grant types.
	GrantTypes []string `json:"grant_types,omitempty"`
	// ResponseTypes lists the requested response types.
	ResponseTypes []string `json:"response_types,omitempty"`
	// TokenEndpointAuthMethod is the requested token-endpoint auth method.
	TokenEndpointAuthMethod string `json:"token_endpoint_auth_method,omitempty"`
	// Scope is the space-delimited set of requested scopes.
	Scope string `json:"scope,omitempty"`
}

// ClientRegistrationResponse is the authorization server's response to a
// successful Dynamic Client Registration request (RFC 7591). It echoes the
// registered metadata and adds the issued credentials.
type ClientRegistrationResponse struct {
	ClientRegistrationRequest
	// ClientID is the issued client identifier.
	ClientID string `json:"client_id"`
	// ClientSecret is the issued client secret, if any (omitted for public clients).
	ClientSecret string `json:"client_secret,omitempty"`
	// ClientIDIssuedAt is the client_id issuance time (seconds since epoch).
	ClientIDIssuedAt int64 `json:"client_id_issued_at,omitempty"`
	// ClientSecretExpiresAt is the client_secret expiry (seconds since epoch),
	// or 0 if it never expires.
	ClientSecretExpiresAt int64 `json:"client_secret_expires_at,omitempty"`
	// RegistrationAccessToken authorizes subsequent registration management.
	RegistrationAccessToken string `json:"registration_access_token,omitempty"`
	// RegistrationClientURI is the client-configuration endpoint URL.
	RegistrationClientURI string `json:"registration_client_uri,omitempty"`
}
