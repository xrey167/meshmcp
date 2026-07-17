package authorization

import "net/url"

// OAuth grant types used at the token endpoint.
const (
	// GrantClientCredentials is the OAuth 2.0 client credentials grant.
	GrantClientCredentials = "client_credentials"
	// GrantJWTBearer is the RFC 7523 JWT bearer authorization grant.
	GrantJWTBearer = "urn:ietf:params:oauth:grant-type:jwt-bearer"
	// GrantTokenExchange is the RFC 8693 token exchange grant.
	GrantTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"
)

// ClientAssertionTypeJWTBearer is the client_assertion_type for private_key_jwt
// client authentication (RFC 7523).
const ClientAssertionTypeJWTBearer = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

// Token type identifiers for RFC 8693 token exchange (requested_token_type,
// subject_token_type, issued_token_type).
const (
	// TokenTypeIDJAG is the Identity Assertion Authorization Grant (ID-JAG) token
	// type used by the MCP cross-app-access flow.
	TokenTypeIDJAG = "urn:ietf:params:oauth:token-type:id-jag"
	// TokenTypeIDToken is an OpenID Connect ID token.
	TokenTypeIDToken = "urn:ietf:params:oauth:token-type:id_token"
	// TokenTypeAccessToken is an OAuth 2.0 access token.
	TokenTypeAccessToken = "urn:ietf:params:oauth:token-type:access_token"
	// TokenTypeJWT is a generic JWT.
	TokenTypeJWT = "urn:ietf:params:oauth:token-type:jwt"
)

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
	// Token-exchange grant fields (RFC 8693).
	// RequestedTokenType is the desired token type (e.g. TokenTypeIDJAG).
	RequestedTokenType string
	// Audience is the intended audience (the target authorization server).
	Audience string
	// SubjectToken is the security token being exchanged (e.g. an ID token).
	SubjectToken string
	// SubjectTokenType is the type of SubjectToken (e.g. TokenTypeIDToken).
	SubjectTokenType string
	// ActorToken / ActorTokenType represent the acting party, when delegation applies.
	ActorToken     string
	ActorTokenType string
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
	set("requested_token_type", r.RequestedTokenType)
	set("audience", r.Audience)
	set("subject_token", r.SubjectToken)
	set("subject_token_type", r.SubjectTokenType)
	set("actor_token", r.ActorToken)
	set("actor_token_type", r.ActorTokenType)
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

// TokenExchangeResponse is a successful RFC 8693 token-exchange response
// (Section 2.2), returned as JSON. For the MCP cross-app-access flow the
// issued AccessToken is the Identity Assertion Authorization Grant (ID-JAG),
// which is then presented as the assertion of a jwt-bearer grant.
type TokenExchangeResponse struct {
	// AccessToken is the security token issued by the exchange.
	AccessToken string `json:"access_token"`
	// IssuedTokenType is the type of the issued token (e.g. TokenTypeIDJAG).
	IssuedTokenType string `json:"issued_token_type"`
	// TokenType is how the token is to be used (e.g. "Bearer", or "N_A").
	TokenType string `json:"token_type"`
	// ExpiresIn is the token lifetime in seconds.
	ExpiresIn int64 `json:"expires_in,omitempty"`
	// Scope is the granted scope, if it differs from the request.
	Scope string `json:"scope,omitempty"`
	// RefreshToken is an optional refresh token.
	RefreshToken string `json:"refresh_token,omitempty"`
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
