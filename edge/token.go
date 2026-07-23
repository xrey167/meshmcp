package edge

import (
	"net/http"
	"os"
	"time"

	"github.com/xrey167/meshmcp/policy"
	"github.com/xrey167/meshmcp/protocol/authorization"
)

// maxTokenBody bounds a token request body.
const maxTokenBody = 16 << 10

// refreshReplayGrace lets a benign network retry re-present a just-rotated
// refresh token without tripping family revocation: within this window the same
// successor is returned instead of revoking. Outside it, reuse is treated as
// theft.
const refreshReplayGrace = 30 * time.Second

// handleToken is the OAuth 2.1 token endpoint. It supports the authorization_code
// (+ PKCE) and refresh_token grants for public clients (auth method "none").
func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	if !s.preauthLimit.allow(clientIP(r)) {
		writeOAuthError(w, http.StatusTooManyRequests, "temporarily_unavailable", "rate limit exceeded")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxTokenBody)
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, authorization.ErrorInvalidRequest, "malformed form body")
		return
	}
	switch r.PostForm.Get("grant_type") {
	case authorization.GrantAuthorizationCode:
		s.tokenFromCode(w, r)
	case authorization.GrantRefreshToken:
		s.tokenFromRefresh(w, r)
	default:
		writeOAuthError(w, http.StatusBadRequest, "unsupported_grant_type", "only authorization_code and refresh_token are supported")
	}
}

// tokenFromCode handles the authorization_code grant with PKCE.
func (s *Server) tokenFromCode(w http.ResponseWriter, r *http.Request) {
	f := r.PostForm
	code := f.Get("code")
	if code == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "missing code")
		return
	}
	rec, err := s.codes.consume(code)
	if err != nil {
		if os.IsNotExist(err) {
			writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "code is unknown or already used")
			return
		}
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "could not read code")
		return
	}
	if s.now().After(rec.ExpiresAt) {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "code has expired")
		return
	}
	if f.Get("client_id") != rec.ClientID {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "client_id does not match the code")
		return
	}
	if f.Get("redirect_uri") != rec.RedirectURI {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "redirect_uri does not match the authorization request")
		return
	}
	if !pkceVerify(f.Get("code_verifier"), rec.CodeChallenge) {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "PKCE verification failed")
		return
	}
	if res := f.Get("resource"); res != "" && rec.Resource != "" && res != rec.Resource {
		writeOAuthError(w, http.StatusBadRequest, "invalid_target", "resource does not match the authorization request")
		return
	}
	// The client must still be approved at redemption time.
	client, err := s.clients.Get(rec.ClientID)
	if err != nil || client.Status != ClientApproved {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "client is no longer authorized")
		return
	}

	s.issueTokenSet(w, rec.ClientID, randHex(16) /*new family*/)
}

// tokenFromRefresh handles the refresh_token grant with rotation and reuse
// detection.
func (s *Server) tokenFromRefresh(w http.ResponseWriter, r *http.Request) {
	f := r.PostForm
	refresh := f.Get("refresh_token")
	if refresh == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "missing refresh_token")
		return
	}
	rec, err := s.tokens.getRefresh(refresh)
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "unknown refresh token")
		return
	}
	if f.Get("client_id") != "" && f.Get("client_id") != rec.ClientID {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "client_id does not match the refresh token")
		return
	}
	if s.now().After(rec.ExpiresAt) {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "refresh token has expired")
		return
	}

	// Serialize rotation of this specific refresh token so a concurrent retry
	// cannot race the reuse check.
	unlock := s.tokens.rotate.lock(sha256Hex(refresh))
	defer unlock()
	// Re-read under lock.
	rec, err = s.tokens.getRefresh(refresh)
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "unknown refresh token")
		return
	}
	if rec.RotatedTo != "" {
		// This token was already consumed. Within the replay-grace window we
		// treat a re-presentation as a benign network retry: return a soft error
		// (the client should retry with the newest token it received) WITHOUT
		// revoking. Only hashes of tokens are stored, so the original successor
		// cannot be re-emitted; the conservative soft error avoids nuking a
		// family on a lost-response retry. Beyond the grace window, a consumed
		// token reappearing is reuse — revoke the whole family (theft detection).
		if !rec.RotatedAt.IsZero() && s.now().Sub(rec.RotatedAt) <= refreshReplayGrace {
			writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "refresh token already rotated; retry with the newest token")
			return
		}
		_ = s.tokens.revokeFamily(rec.FamilyID)
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "refresh token reuse detected; the token family has been revoked")
		return
	}

	client, err := s.clients.Get(rec.ClientID)
	if err != nil || client.Status != ClientApproved {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "client is no longer authorized")
		return
	}

	// Mint the successor set in the SAME family, then mark this token rotated.
	access, refreshTok, err := s.mintTokenSet(rec.ClientID, rec.FamilyID, rec.Generation+1)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "could not issue tokens")
		return
	}
	if err := s.tokens.markRotated(refresh, sha256Hex(refreshTok), rec, s.now()); err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "could not rotate refresh token")
		return
	}
	s.writeTokenResponse(w, access, refreshTok)
}

// issueTokenSet mints a fresh access+refresh pair in a new family and writes the
// OAuth token response.
func (s *Server) issueTokenSet(w http.ResponseWriter, clientID, familyID string) {
	access, refresh, err := s.mintTokenSet(clientID, familyID, 0)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "could not issue tokens")
		return
	}
	s.writeTokenResponse(w, access, refresh)
}

// mintTokenSet mints the capability, the access token carrying it, and a refresh
// token, all bound to (clientID, familyID). It returns the raw access and
// refresh tokens.
func (s *Server) mintTokenSet(clientID, familyID string, generation int) (access, refresh string, err error) {
	now := s.now()
	ttl := s.cfg.OAuth.AccessTokenTTL.Std()
	capID := "edgecap-" + randHex(12)
	claims := policy.CapabilityClaims{
		ID:        capID,
		Issuer:    "edge:" + s.cfg.Backend.Name,
		Subject:   oauthIdentity(clientID),
		Audience:  s.cfg.Backend.Name,
		Tools:     s.cfg.Backend.Tools,
		ExpiresAt: now.Add(ttl).Unix(),
	}
	capTok, err := s.signer.IssueCapability(claims, now)
	if err != nil {
		return "", "", err
	}
	access, err = s.tokens.putAccess(accessRecord{
		ClientID:   clientID,
		FamilyID:   familyID,
		Capability: capTok,
		CapID:      capID,
		ExpiresAt:  now.Add(ttl),
	})
	if err != nil {
		return "", "", err
	}
	refresh, err = s.tokens.putRefresh(refreshRecord{
		ClientID:   clientID,
		FamilyID:   familyID,
		Generation: generation,
		ExpiresAt:  now.Add(s.cfg.OAuth.RefreshTokenTTL.Std()),
	})
	if err != nil {
		return "", "", err
	}
	return access, refresh, nil
}

func (s *Server) writeTokenResponse(w http.ResponseWriter, access, refresh string) {
	writeJSON(w, http.StatusOK, authorization.TokenResponse{
		AccessToken:  access,
		TokenType:    authorization.SchemeBearer,
		ExpiresIn:    int64(s.cfg.OAuth.AccessTokenTTL.Std().Seconds()),
		RefreshToken: refresh,
		Scope:        scopeMCP,
	})
}
