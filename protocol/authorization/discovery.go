package authorization

import (
	"net/url"
	"strings"
)

// origin returns scheme://host (including any port) for a parsed URL.
func origin(u *url.URL) string {
	return u.Scheme + "://" + u.Host
}

// ProtectedResourceMetadataURLs returns the candidate well-known URLs for a
// server's Protected Resource Metadata (RFC 9728), in the fallback order MCP
// clients MUST try after the WWW-Authenticate header: the path-insertion form
// first (when the MCP endpoint has a path), then the root form.
//
// For https://example.com/public/mcp this returns:
//
//	https://example.com/.well-known/oauth-protected-resource/public/mcp
//	https://example.com/.well-known/oauth-protected-resource
func ProtectedResourceMetadataURLs(mcpEndpoint string) ([]string, error) {
	u, err := url.Parse(mcpEndpoint)
	if err != nil {
		return nil, err
	}
	base := origin(u)
	root := base + "/.well-known/" + WellKnownProtectedResource
	path := strings.TrimSuffix(u.Path, "/")
	if path == "" {
		return []string{root}, nil
	}
	return []string{root + path, root}, nil
}

// AuthorizationServerMetadataURLs returns the candidate well-known URLs for an
// issuer's Authorization Server Metadata, in the priority order MCP clients
// MUST try (RFC 8414 Section 3.1 with OpenID Connect Discovery interop).
//
// For an issuer with a path component (https://auth.example.com/tenant1):
//
//	https://auth.example.com/.well-known/oauth-authorization-server/tenant1
//	https://auth.example.com/.well-known/openid-configuration/tenant1
//	https://auth.example.com/tenant1/.well-known/openid-configuration
//
// For an issuer without a path component (https://auth.example.com):
//
//	https://auth.example.com/.well-known/oauth-authorization-server
//	https://auth.example.com/.well-known/openid-configuration
func AuthorizationServerMetadataURLs(issuer string) ([]string, error) {
	u, err := url.Parse(issuer)
	if err != nil {
		return nil, err
	}
	base := origin(u)
	path := strings.TrimSuffix(u.Path, "/")
	if path == "" {
		return []string{
			base + "/.well-known/" + WellKnownAuthorizationServer,
			base + "/.well-known/" + WellKnownOpenIDConfiguration,
		}, nil
	}
	return []string{
		base + "/.well-known/" + WellKnownAuthorizationServer + path,
		base + "/.well-known/" + WellKnownOpenIDConfiguration + path,
		base + path + "/.well-known/" + WellKnownOpenIDConfiguration,
	}, nil
}

// ParseChallenge parses a WWW-Authenticate header value into its auth-scheme
// and the auth-param map (keys lower-cased). Quoted parameter values are
// unquoted. It handles a single challenge, which is the shape MCP servers emit
// on a 401.
func ParseChallenge(header string) (scheme string, params map[string]string) {
	header = strings.TrimSpace(header)
	params = map[string]string{}
	if header == "" {
		return "", params
	}
	// Split the auth-scheme from the parameter list.
	rest := header
	if i := strings.IndexByte(header, ' '); i >= 0 {
		scheme = header[:i]
		rest = strings.TrimSpace(header[i+1:])
	} else {
		return header, params
	}

	for i := 0; i < len(rest); {
		// Skip separators and whitespace.
		for i < len(rest) && (rest[i] == ',' || rest[i] == ' ' || rest[i] == '\t') {
			i++
		}
		// Read the key up to '='.
		start := i
		for i < len(rest) && rest[i] != '=' {
			i++
		}
		if i >= len(rest) {
			break
		}
		key := strings.ToLower(strings.TrimSpace(rest[start:i]))
		i++ // consume '='
		// Skip optional bad whitespace between '=' and the value (RFC 7235 BWS).
		for i < len(rest) && (rest[i] == ' ' || rest[i] == '\t') {
			i++
		}

		var value string
		if i < len(rest) && rest[i] == '"' {
			i++ // opening quote
			var b strings.Builder
			for i < len(rest) && rest[i] != '"' {
				if rest[i] == '\\' && i+1 < len(rest) {
					i++ // consume escape
				}
				b.WriteByte(rest[i])
				i++
			}
			i++ // closing quote
			value = b.String()
		} else {
			start = i
			for i < len(rest) && rest[i] != ',' {
				i++
			}
			value = strings.TrimSpace(rest[start:i])
		}
		if key != "" {
			params[key] = value
		}
	}
	return scheme, params
}

// ResourceMetadataURL extracts the Protected Resource Metadata URL advertised
// in a WWW-Authenticate header's resource_metadata parameter, or "" if absent.
func ResourceMetadataURL(header string) string {
	_, params := ParseChallenge(header)
	return params[ChallengeResourceMetadata]
}
