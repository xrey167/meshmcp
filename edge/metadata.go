package edge

import (
	"encoding/json"
	"net/http"

	"github.com/xrey167/meshmcp/protocol/authorization"
)

// Endpoint paths served by the edge. The MCP resource lives at /mcp; the OAuth
// authorization-server endpoints live under /oauth2.
const (
	pathMCP           = "/mcp"
	pathRegister      = "/oauth2/register"
	pathAuthorize     = "/oauth2/authorize"
	pathAuthorizeStat = "/oauth2/authorize/status"
	pathToken         = "/oauth2/token"
	pathHealthz       = "/healthz"

	wellKnownPRM  = "/.well-known/" + authorization.WellKnownProtectedResource
	wellKnownAS   = "/.well-known/" + authorization.WellKnownAuthorizationServer
	wellKnownOIDC = "/.well-known/" + authorization.WellKnownOpenIDConfiguration
)

// scopeMCP is the single OAuth scope the edge advertises and issues.
const scopeMCP = "mcp"

// protectedResourceMetadata builds the RFC 9728 document for this edge's MCP
// resource, pointing hosted clients at this same edge as its authorization
// server. The resource identifier is the MCP endpoint URL.
func (s *Server) protectedResourceMetadata() authorization.ProtectedResourceMetadata {
	return authorization.ProtectedResourceMetadata{
		Resource:               s.cfg.PublicURL + pathMCP,
		AuthorizationServers:   []string{s.cfg.PublicURL},
		ScopesSupported:        []string{scopeMCP},
		BearerMethodsSupported: []string{"header"},
		ResourceDocumentation:  s.cfg.PublicURL + "/",
	}
}

// authorizationServerMetadata builds the RFC 8414 document. PKCE S256 is
// advertised and required; the token endpoint authenticates public clients with
// "none" (client_id in the body + PKCE), which is what hosted MCP clients use.
func (s *Server) authorizationServerMetadata() authorization.AuthorizationServerMetadata {
	return authorization.AuthorizationServerMetadata{
		Issuer:                            s.cfg.PublicURL,
		AuthorizationEndpoint:             s.cfg.PublicURL + pathAuthorize,
		TokenEndpoint:                     s.cfg.PublicURL + pathToken,
		RegistrationEndpoint:              s.cfg.PublicURL + pathRegister,
		ScopesSupported:                   []string{scopeMCP},
		ResponseTypesSupported:            []string{authorization.ResponseTypeCode},
		GrantTypesSupported:               []string{authorization.GrantAuthorizationCode, authorization.GrantRefreshToken},
		TokenEndpointAuthMethodsSupported: []string{authorization.AuthMethodNone},
		CodeChallengeMethodsSupported:     []string{authorization.PKCECodeChallengeS256},
	}
}

// handleProtectedResourceMetadata serves the RFC 9728 document. It is a public,
// CORS-open GET (hosted clients and browser-based inspectors fetch it directly).
func (s *Server) handleProtectedResourceMetadata(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	writePublicJSON(w, s.protectedResourceMetadata())
}

// handleAuthorizationServerMetadata serves the RFC 8414 document (also under
// the openid-configuration alias, which some clients probe first).
func (s *Server) handleAuthorizationServerMetadata(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	writePublicJSON(w, s.authorizationServerMetadata())
}

// writePublicJSON writes a cacheable, CORS-open JSON document. CORS is opened
// only on the public metadata documents — never on the OAuth or MCP endpoints.
func writePublicJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_ = json.NewEncoder(w).Encode(v)
}

// writeJSON writes a non-cacheable JSON body with an explicit status.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// methodNotAllowed writes a 405 advertising the permitted method(s).
func methodNotAllowed(w http.ResponseWriter, allow ...string) {
	for _, a := range allow {
		w.Header().Add("Allow", a)
	}
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
}
