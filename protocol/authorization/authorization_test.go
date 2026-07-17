package authorization_test

import (
	"encoding/json"
	"reflect"
	"testing"

	auth "meshmcp/protocol/authorization"
)

func TestProtectedResourceMetadataURLs(t *testing.T) {
	got, err := auth.ProtectedResourceMetadataURLs("https://example.com/public/mcp")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"https://example.com/.well-known/oauth-protected-resource/public/mcp",
		"https://example.com/.well-known/oauth-protected-resource",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("sub-path case:\n got %v\nwant %v", got, want)
	}

	got, err = auth.ProtectedResourceMetadataURLs("https://example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "https://example.com/.well-known/oauth-protected-resource" {
		t.Fatalf("root case: %v", got)
	}
}

func TestAuthorizationServerMetadataURLs(t *testing.T) {
	got, err := auth.AuthorizationServerMetadataURLs("https://auth.example.com/tenant1")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"https://auth.example.com/.well-known/oauth-authorization-server/tenant1",
		"https://auth.example.com/.well-known/openid-configuration/tenant1",
		"https://auth.example.com/tenant1/.well-known/openid-configuration",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("path issuer:\n got %v\nwant %v", got, want)
	}

	got, err = auth.AuthorizationServerMetadataURLs("https://auth.example.com")
	if err != nil {
		t.Fatal(err)
	}
	want = []string{
		"https://auth.example.com/.well-known/oauth-authorization-server",
		"https://auth.example.com/.well-known/openid-configuration",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("bare issuer:\n got %v\nwant %v", got, want)
	}
}

func TestParseChallenge(t *testing.T) {
	header := `Bearer resource_metadata="https://example.com/.well-known/oauth-protected-resource", scope="a b", error="invalid_token"`
	scheme, params := auth.ParseChallenge(header)
	if scheme != auth.SchemeBearer {
		t.Fatalf("scheme = %q", scheme)
	}
	if got := auth.ResourceMetadataURL(header); got != "https://example.com/.well-known/oauth-protected-resource" {
		t.Fatalf("resource_metadata = %q", got)
	}
	if params["scope"] != "a b" || params["error"] != "invalid_token" {
		t.Fatalf("params = %v", params)
	}
}

func TestAuthorizationServerMetadataDecode(t *testing.T) {
	raw := `{
		"issuer": "https://auth.example.com",
		"authorization_endpoint": "https://auth.example.com/authorize",
		"token_endpoint": "https://auth.example.com/token",
		"registration_endpoint": "https://auth.example.com/register",
		"code_challenge_methods_supported": ["S256"],
		"client_id_metadata_document_supported": true,
		"some_unknown_field": 123
	}`
	var m auth.AuthorizationServerMetadata
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		t.Fatal(err)
	}
	if !m.SupportsPKCE() {
		t.Fatal("expected PKCE support")
	}
	if !m.ClientIDMetadataDocumentSupported {
		t.Fatal("expected CIMD support")
	}
	if m.RegistrationEndpoint == "" {
		t.Fatal("registration endpoint lost")
	}
}

func TestClientIDMetadataDocumentDecode(t *testing.T) {
	raw := `{
		"client_id": "https://app.example.com/oauth/client-metadata.json",
		"client_name": "Example MCP Client",
		"client_uri": "https://app.example.com",
		"redirect_uris": ["http://127.0.0.1:3000/callback", "http://localhost:3000/callback"],
		"grant_types": ["authorization_code"],
		"response_types": ["code"],
		"token_endpoint_auth_method": "none"
	}`
	var doc auth.ClientIDMetadataDocument
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.ClientID != "https://app.example.com/oauth/client-metadata.json" {
		t.Fatalf("client_id = %q", doc.ClientID)
	}
	if len(doc.RedirectURIs) != 2 || doc.TokenEndpointAuthMethod != auth.AuthMethodNone {
		t.Fatalf("doc mismatch: %+v", doc)
	}
}
