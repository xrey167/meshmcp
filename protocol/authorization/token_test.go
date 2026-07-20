package authorization_test

import (
	"encoding/json"
	"testing"

	auth "github.com/xrey167/meshmcp/protocol/authorization"
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

func TestTokenExchangeRequestIDJAG(t *testing.T) {
	// The cross-app-access step 1: exchange an ID token for an ID-JAG.
	req := auth.TokenRequest{
		GrantType:          auth.GrantTokenExchange,
		RequestedTokenType: auth.TokenTypeIDJAG,
		Audience:           "https://auth.chat.example/",
		Resource:           []string{"https://mcp.chat.example/"},
		SubjectToken:       "eyJhbGciOiJS...",
		SubjectTokenType:   auth.TokenTypeIDToken,
		ClientID:           "my-idp-client",
		Scope:              "chat.read chat.history",
	}
	f := req.Form()
	checks := map[string]string{
		"grant_type":           "urn:ietf:params:oauth:grant-type:token-exchange",
		"requested_token_type": "urn:ietf:params:oauth:token-type:id-jag",
		"subject_token_type":   "urn:ietf:params:oauth:token-type:id_token",
		"audience":             "https://auth.chat.example/",
		"resource":             "https://mcp.chat.example/",
		"subject_token":        "eyJhbGciOiJS...",
		"scope":                "chat.read chat.history",
	}
	for k, want := range checks {
		if got := f.Get(k); got != want {
			t.Fatalf("%s = %q, want %q", k, got, want)
		}
	}
}

func TestTokenExchangeResponseDecode(t *testing.T) {
	raw := `{"access_token":"idjag-jwt...","issued_token_type":"urn:ietf:params:oauth:token-type:id-jag","token_type":"N_A","expires_in":300}`
	var r auth.TokenExchangeResponse
	if err := json.Unmarshal([]byte(raw), &r); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if r.AccessToken != "idjag-jwt..." || r.IssuedTokenType != auth.TokenTypeIDJAG || r.ExpiresIn != 300 {
		t.Fatalf("exchange response mismatch: %+v", r)
	}

	// Step 2: present the ID-JAG as a jwt-bearer assertion.
	step2 := auth.TokenRequest{GrantType: auth.GrantJWTBearer, Assertion: r.AccessToken}.Form()
	if step2.Get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" || step2.Get("assertion") != "idjag-jwt..." {
		t.Fatalf("step2 form mismatch: %v", step2)
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
