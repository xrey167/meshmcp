package edge

import (
	"net/http"
	"testing"
)

func TestRevokeClientCascade(t *testing.T) {
	srv, ts, clientID, token := newMCPServer(t, nil)

	// The token works before revocation.
	resp := mcpPostReq(t, ts.URL, token, "", `{"jsonrpc":"2.0","id":1,"method":"initialize"}`)
	sid := resp.Header.Get(headerSessionID)
	resp.Body.Close()
	if sid == "" {
		t.Fatal("expected a working session before revocation")
	}

	// Revoke the client via the daemon-side cascade.
	if err := srv.RevokeClient(clientID, "op"); err != nil {
		t.Fatalf("RevokeClient: %v", err)
	}

	// The access token is now dead: the MCP endpoint 401s (client status recheck).
	r2 := mcpPostReq(t, ts.URL, token, sid, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"search_docs","arguments":{}}}`)
	r2.Body.Close()
	if r2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("revoked client's token must 401, got %d", r2.StatusCode)
	}

	// The token records are gone.
	if _, err := srv.tokens.getAccess(token); err == nil {
		t.Fatal("access token record should have been deleted by the cascade")
	}
}

func TestRevokeClientStateFileLevel(t *testing.T) {
	srv, ts, clientID, token := newMCPServer(t, nil)
	// Confirm the token is live.
	if _, err := srv.tokens.getAccess(token); err != nil {
		t.Fatalf("token should exist: %v", err)
	}

	// File-level cascade (as the CLI runs it, without touching the daemon).
	n, err := RevokeClientState(srv.cfg.StateDir, clientID, "cli")
	if err != nil {
		t.Fatalf("RevokeClientState: %v", err)
	}
	if n < 1 {
		t.Fatalf("expected at least one token invalidated, got %d", n)
	}
	if _, err := srv.tokens.getAccess(token); err == nil {
		t.Fatal("token record should be gone after file-level revoke")
	}

	// A fresh MCP request with the old token 401s.
	r := mcpPostReq(t, ts.URL, token, "", `{"jsonrpc":"2.0","id":1,"method":"initialize"}`)
	r.Body.Close()
	if r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("token after file-level revoke must 401, got %d", r.StatusCode)
	}
}

func TestListAndRevokeTokenFamily(t *testing.T) {
	srv, ts, clientID, token := newMCPServer(t, nil)

	toks, err := ListTokens(srv.cfg.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(toks) != 1 || toks[0].ClientID != clientID {
		t.Fatalf("expected one token for the client, got %+v", toks)
	}
	fam := toks[0].FamilyID

	n, err := RevokeFamilyState(srv.cfg.StateDir, fam)
	if err != nil {
		t.Fatal(err)
	}
	if n < 1 {
		t.Fatalf("expected the family's token invalidated, got %d", n)
	}
	r := mcpPostReq(t, ts.URL, token, "", `{"jsonrpc":"2.0","id":1,"method":"initialize"}`)
	r.Body.Close()
	if r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("token after family revoke must 401, got %d", r.StatusCode)
	}
}
