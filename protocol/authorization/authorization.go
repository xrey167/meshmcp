// Package authorization models the MCP authorization layer (draft
// basic/authorization). MCP authorization is OAuth 2.1 layered on existing
// standards; this package holds the concrete wire structures and constants
// those specs define, plus the MCP-specific discovery helpers.
//
// The struct field sets come from the referenced RFCs — Protected Resource
// Metadata (RFC 9728), Authorization Server Metadata (RFC 8414) / OpenID
// Connect Discovery, Dynamic Client Registration (RFC 7591), and the OAuth
// Client ID Metadata Document draft — restricted to the fields MCP relies on.
// They are not an MCP-invented schema.
package authorization

// Well-known URI suffixes used for metadata discovery.
const (
	// WellKnownProtectedResource is the RFC 9728 suffix for Protected Resource
	// Metadata: /.well-known/oauth-protected-resource.
	WellKnownProtectedResource = "oauth-protected-resource"
	// WellKnownAuthorizationServer is the RFC 8414 suffix for OAuth 2.0
	// Authorization Server Metadata: /.well-known/oauth-authorization-server.
	WellKnownAuthorizationServer = "oauth-authorization-server"
	// WellKnownOpenIDConfiguration is the OpenID Connect Discovery 1.0 suffix:
	// /.well-known/openid-configuration.
	WellKnownOpenIDConfiguration = "openid-configuration"
)

// WWW-Authenticate challenge parameters MCP clients parse from a 401 response.
const (
	// ChallengeResourceMetadata carries the Protected Resource Metadata URL
	// (RFC 9728 Section 5.1).
	ChallengeResourceMetadata = "resource_metadata"
	// ChallengeScope carries the scopes required to access the resource.
	ChallengeScope = "scope"
	// ChallengeError carries an OAuth error code.
	ChallengeError = "error"
	// SchemeBearer is the WWW-Authenticate auth-scheme for bearer tokens.
	SchemeBearer = "Bearer"
)

// PKCECodeChallengeS256 is the code challenge method MCP clients MUST use when
// technically capable (OAuth 2.1). PKCE support is discovered via the
// authorization server metadata's code_challenge_methods_supported field.
const PKCECodeChallengeS256 = "S256"

// ApplicationType values for Dynamic Client Registration under OIDC.
const (
	// ApplicationTypeNative is for desktop, mobile, CLI, and localhost apps.
	ApplicationTypeNative = "native"
	// ApplicationTypeWeb is for remote browser-based apps (the OIDC default).
	ApplicationTypeWeb = "web"
)

// Common OAuth grant and response type values.
const (
	GrantAuthorizationCode = "authorization_code"
	GrantRefreshToken      = "refresh_token"
	ResponseTypeCode       = "code"
)

// Token endpoint client-authentication methods.
const (
	AuthMethodNone              = "none"
	AuthMethodClientSecretBasic = "client_secret_basic"
	AuthMethodClientSecretPost  = "client_secret_post"
	AuthMethodPrivateKeyJWT     = "private_key_jwt"
)

// OAuth error codes surfaced during registration and authorization.
const (
	ErrorInvalidClient  = "invalid_client"
	ErrorInvalidRequest = "invalid_request"
)
