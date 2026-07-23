package edge

import (
	"fmt"
	"path/filepath"
	"time"

	"github.com/xrey167/meshmcp/policy"
)

// RevokeClientState performs the file-level revocation cascade for a client,
// callable from the operator CLI (a separate process from the daemon): it marks
// the client revoked, deletes every access/refresh token it holds, and adds the
// capabilities those tokens carried to the revocation store. In-memory sessions
// in a running daemon are not touched here, but they stop working immediately —
// every MCP request re-reads the client's status and denies a revoked client.
// It returns the number of access+refresh token records removed.
func RevokeClientState(stateDir, clientID, by string) (int, error) {
	clients, err := NewClientStore(filepath.Join(stateDir, "clients"), time.Now)
	if err != nil {
		return 0, err
	}
	if _, err := clients.Revoke(clientID, by); err != nil {
		return 0, fmt.Errorf("edge: revoke client: %w", err)
	}
	tokens, err := newTokenStore(filepath.Join(stateDir, "tokens"))
	if err != nil {
		return 0, err
	}
	before, _ := tokens.listAccess()
	capIDs, err := tokens.revokeClient(clientID)
	if err != nil {
		return 0, fmt.Errorf("edge: revoke tokens: %w", err)
	}
	rev, err := policy.NewFileRevocation(filepath.Join(stateDir, "revoked"))
	if err != nil {
		return 0, err
	}
	for _, id := range capIDs {
		_ = rev.Revoke(id)
	}
	return len(before), nil
}

// RevokeClient is the daemon-side cascade: it does the file-level revocation and
// additionally tears down the client's live in-memory sessions.
func (s *Server) RevokeClient(clientID, by string) error {
	if _, err := RevokeClientState(s.cfg.StateDir, clientID, by); err != nil {
		return err
	}
	s.sessions.deleteClient(clientID)
	return nil
}

// RevokeFamilyState revokes a single token family by id (operator CLI): it
// deletes the family's tokens and revokes their capabilities. It returns the
// number of token records removed.
func RevokeFamilyState(stateDir, familyID string) (int, error) {
	tokens, err := newTokenStore(filepath.Join(stateDir, "tokens"))
	if err != nil {
		return 0, err
	}
	// Collect cap IDs before deletion so they can be revoked.
	all, _ := tokens.listAccess()
	var capIDs []string
	n := 0
	for _, a := range all {
		if a.FamilyID == familyID {
			if a.CapID != "" {
				capIDs = append(capIDs, a.CapID)
			}
			n++
		}
	}
	if err := tokens.revokeFamily(familyID); err != nil {
		return 0, err
	}
	rev, err := policy.NewFileRevocation(filepath.Join(stateDir, "revoked"))
	if err != nil {
		return 0, err
	}
	for _, id := range capIDs {
		_ = rev.Revoke(id)
	}
	return n, nil
}

// TokenView is a CLI-facing summary of a live access token (never the raw token).
type TokenView struct {
	ClientID  string
	FamilyID  string
	CapID     string
	ExpiresAt time.Time
}

// ListTokens summarizes live access tokens in the state directory.
func ListTokens(stateDir string) ([]TokenView, error) {
	tokens, err := newTokenStore(filepath.Join(stateDir, "tokens"))
	if err != nil {
		return nil, err
	}
	recs, err := tokens.listAccess()
	if err != nil {
		return nil, err
	}
	out := make([]TokenView, 0, len(recs))
	for _, r := range recs {
		out = append(out, TokenView{ClientID: r.ClientID, FamilyID: r.FamilyID, CapID: r.CapID, ExpiresAt: r.ExpiresAt})
	}
	return out, nil
}
