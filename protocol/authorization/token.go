package authorization

import "net/url"

// OAuth grant types used at the token endpoint.
const (
	// GrantClientCredentials is the OAuth 2.0 client credentials grant.
	GrantClientCredentials = "client_credentials"
	// GrantJWTBearer is the RFC 7523 JWT bearer authorization grant.
	GrantJWTBearer = "urn:ietf:params:oauth:grant-type:jwt-bearer"
)

// ClientAssertionTypeJWTBearer is the client_assertion_type for private_key_jwt
// client authentication (RFC 7523).
const ClientAssertionTypeJWTBearer = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

// TokenRequest is an OAuth 2.0 token-endpoint request. It is sent
// form-encoded (application/x-www-form-urlencoded); use Form to build the body.
// Only the set (non-empty) fields are emitted.
type TokenRequest struct {
	// GrantType selects the grant (e.g. GrantClientCredentials,
	// GrantAuthorizationCode, GrantRefreshToken, GrantJWTBearer).
	GrantType string
	// Scope is the space-delimited set of requested scopes.
	Scope string
	// Resource is the RFC 8707 resource indicator(s) the token is requested for;
	// MCP clients MUST include the target MCP server.
	Resource []string
	// ClientID / ClientSecret for client_secret_* authentication.
	ClientID     string
	ClientSecret string
	// ClientAssertion / ClientAssertionType for private_key_jwt authentication.
	// ClientAssertionType is typically ClientAssertionTypeJWTBearer.
	ClientAssertion     string
	ClientAssertionType string
	// Assertion is the JWT for the jwt-bearer grant (GrantJWTBearer).
	Assertion string
	// Authorization-code grant fields.
	Code         string
	RedirectURI  string
	CodeVerifier string // PKCE
	// RefreshToken for the refresh_token grant.
	RefreshToken string
	// Extra carries any additional non-standard parameters.
	Extra url.Values
}

// Form encodes the request as OAuth token-endpoint form values, omitting empty
// fields.
func (r TokenRequest) Form() url.Values {
	v := url.Values{}
	set := func(key, val string) {
		if val != "" {
			v.Set(key, val)
		}
	}
	set("grant_type", r.GrantType)
	set("scope", r.Scope)
	for _, res := range r.Resource {
		if res != "" {
			v.Add("resource", res)
		}
	}
	set("client_id", r.ClientID)
	set("client_secret", r.ClientSecret)
	set("client_assertion", r.ClientAssertion)
	set("client_assertion_type", r.ClientAssertionType)
	set("assertion", r.Assertion)
	set("code", r.Code)
	set("redirect_uri", r.RedirectURI)
	set("code_verifier", r.CodeVerifier)
	set("refresh_token", r.RefreshToken)
	for key, vals := range r.Extra {
		for _, val := range vals {
			v.Add(key, val)
		}
	}
	return v
}

// TokenResponse is a successful OAuth 2.0 token-endpoint response
// (RFC 6749 Section 5.1), returned as JSON.
type TokenResponse struct {
	// AccessToken is the issued access token.
	AccessToken string `json:"access_token"`
	// TokenType is the token type (typically "Bearer").
	TokenType string `json:"token_type"`
	// ExpiresIn is the access token lifetime in seconds.
	ExpiresIn int64 `json:"expires_in,omitempty"`
	// RefreshToken is an optional refresh token.
	RefreshToken string `json:"refresh_token,omitempty"`
	// Scope is the granted scope, if it differs from the request.
	Scope string `json:"scope,omitempty"`
}

// TokenErrorResponse is an OAuth 2.0 token-endpoint error response
// (RFC 6749 Section 5.2), returned as JSON.
type TokenErrorResponse struct {
	// Error is the OAuth error code (e.g. ErrorInvalidClient, "invalid_grant").
	Error string `json:"error"`
	// ErrorDescription is a human-readable explanation.
	ErrorDescription string `json:"error_description,omitempty"`
	// ErrorURI is a URI to error documentation.
	ErrorURI string `json:"error_uri,omitempty"`
}
