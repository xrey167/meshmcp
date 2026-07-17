package authorization_test

import (
	"encoding/json"
	"testing"

	auth "meshmcp/protocol/authorization"
)

func TestTokenRequestClientCredentials(t *testing.T) {
	req := auth.TokenRequest{
		GrantType: auth.GrantClientCredentials,
		Scope:     "read write",
		Resource:  []string{"https://mcp.example.com"},
	}
	f := req.Form()
	if f.Get("grant_type") != "client_credentials" {
		t.Fatalf("grant_type = %q", f.Get("grant_type"))
	}
	if f.Get("scope") != "read write" {
		t.Fatalf("scope = %q", f.Get("scope"))
	}
	if f.Get("resource") != "https://mcp.example.com" {
		t.Fatalf("resource = %q", f.Get("resource"))
	}
	// Unset fields must be omitted.
	if _, ok := f["client_secret"]; ok {
		t.Fatal("empty client_secret should be omitted")
	}
}

func TestTokenRequestPrivateKeyJWT(t *testing.T) {
	req := auth.TokenRequest{
		GrantType:           auth.GrantClientCredentials,
		Scope:               "openid profile",
		ClientAssertion:     "eyJhbGciOi...",
		ClientAssertionType: auth.ClientAssertionTypeJWTBearer,
	}
	f := req.Form()
	if f.Get("client_assertion") != "eyJhbGciOi..." {
		t.Fatalf("client_assertion = %q", f.Get("client_assertion"))
	}
	if f.Get("client_assertion_type") != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
		t.Fatalf("client_assertion_type = %q", f.Get("client_assertion_type"))
	}
}

func TestTokenResponseDecode(t *testing.T) {
	raw := `{"access_token":"tok-123","token_type":"Bearer","expires_in":3600,"scope":"read write"}`
	var r auth.TokenResponse
	if err := json.Unmarshal([]byte(raw), &r); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if r.AccessToken != "tok-123" || r.TokenType != "Bearer" || r.ExpiresIn != 3600 {
		t.Fatalf("response mismatch: %+v", r)
	}
}

func TestTokenErrorDecode(t *testing.T) {
	raw := `{"error":"invalid_client","error_description":"bad credentials"}`
	var e auth.TokenErrorResponse
	if err := json.Unmarshal([]byte(raw), &e); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if e.Error != auth.ErrorInvalidClient || e.ErrorDescription != "bad credentials" {
		t.Fatalf("error mismatch: %+v", e)
	}
}
