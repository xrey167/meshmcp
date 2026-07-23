package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/netbirdio/netbird/client/embed"

	"github.com/xrey167/meshmcp/policy"
	"github.com/xrey167/meshmcp/protocol/authorization"
)

// Doer is the subset of *http.Client the remote client needs (injectable for
// tests), mirroring control/netbird.go's Doer.
type Doer interface {
	Do(*http.Request) (*http.Response, error)
}

// remoteHTTPTimeout is the fixed outbound timeout for the remote backend's
// http.Client, matching control/netbird.go's convention: no retry layer, a
// bounded wait instead of a hung dial to an untrusted third party.
const remoteHTTPTimeout = 20 * time.Second

// remoteToken is the OAuth 2.1 token state a remoteClient holds for its
// backend: a DPoP-bound access token, its expiry, and the refresh token (if
// any) used to renew it without a full rediscovery.
type remoteToken struct {
	accessToken  string
	expiresAt    time.Time
	refreshToken string
}

// remoteClient is the outbound OAuth 2.1 + DPoP client for one "remote"
// backend (Feature B). It is built once per backend and shared across every
// mesh connection to it, so PRM/AS discovery happens at most once and the
// access token is reused/refreshed across calls.
type remoteClient struct {
	name         string
	endpoint     *url.URL
	clientID     string
	clientSecret string
	scope        string
	dpop         *policy.DPoPSigner
	httpClient   Doer
	now          func() time.Time

	secretsFile      string // "" if the backend has no file-backed secrets store (rotation is then in-memory only)
	refreshTokenName string

	mu            sync.Mutex
	tokenEndpoint string // "" until discovered via a 401 WWW-Authenticate round-trip
	tokenNonce    string // last DPoP-Nonce the AS's token endpoint issued
	resourceNonce string // last DPoP-Nonce the resource server issued
	tok           remoteToken
}

// buildRemoteClient resolves a remote backend's secrets (client_secret,
// refresh_token, and the DPoP key file PATH) through the existing
// secrets.Store — no new credential store — and loads the DPoP signing key.
// A missing or unloadable DPoP key file is returned as an error here, which
// the caller (cmdServe) treats as a fatal startup failure (S13 precedent):
// this backend never starts with a silently regenerated key.
func buildRemoteClient(b *Backend) (*remoteClient, error) {
	store, err := secretStore(b.Remote.Secrets)
	if err != nil {
		return nil, fmt.Errorf("backend %q: remote secrets store: %w", b.Name, err)
	}
	keyPath, ok := store.Get(b.Remote.DPoPKeyName)
	if !ok || keyPath == "" {
		return nil, fmt.Errorf("backend %q: remote dpop key secret %q not found — run the key generation step and point the secret at the resulting file", b.Name, b.Remote.DPoPKeyName)
	}
	dpopSigner, err := policy.LoadDPoPSigner(keyPath)
	if err != nil {
		return nil, fmt.Errorf("backend %q: load dpop key: %w", b.Name, err)
	}
	clientSecret, _ := store.Get(b.Remote.ClientSecretName) // optional: public clients have none
	refreshToken, _ := store.Get(b.Remote.RefreshTokenName) // optional: no prior grant yet

	rc := &remoteClient{
		name:             b.Name,
		endpoint:         b.remoteURL,
		clientID:         b.Remote.ClientID,
		clientSecret:     clientSecret,
		scope:            b.Remote.Scope,
		dpop:             dpopSigner,
		httpClient:       &http.Client{Timeout: remoteHTTPTimeout},
		now:              time.Now,
		secretsFile:      b.Remote.Secrets.File,
		refreshTokenName: b.Remote.RefreshTokenName,
	}
	rc.tok.refreshToken = refreshToken
	return rc, nil
}

// maxRemoteBody bounds a response body the client will buffer, mirroring
// maxHTTPBody (httppolicy.go).
const maxRemoteBody = 16 << 20

func readResp(resp *http.Response) (status int, body []byte, header http.Header, err error) {
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxRemoteBody))
	if err != nil {
		return 0, nil, nil, err
	}
	return resp.StatusCode, b, resp.Header.Clone(), nil
}

// dpopChallenge is what a DPoP-aware AS or resource server response signals
// via WWW-Authenticate (401) or a JSON error body (400) — RFC 9449 Section 8
// (nonce) and Section 4.3/5 (invalid proof).
type dpopChallenge struct {
	useNonce     bool
	invalidProof bool
	nonce        string
}

// parseDPoPChallenge inspects a response for a DPoP nonce or invalid-proof
// signal. It never returns or logs the response body's raw bytes — only the
// standard, non-secret OAuth "error" code is read out of it.
func parseDPoPChallenge(status int, header http.Header, body []byte) dpopChallenge {
	var c dpopChallenge
	c.nonce = header.Get("DPoP-Nonce")
	if wa := header.Get("WWW-Authenticate"); wa != "" {
		scheme, params := authorization.ParseChallenge(wa)
		if strings.EqualFold(scheme, "DPoP") {
			switch params[authorization.ChallengeError] {
			case "use_dpop_nonce":
				c.useNonce = true
			case "invalid_dpop_proof":
				c.invalidProof = true
			}
		}
	}
	if status == http.StatusBadRequest && len(body) > 0 {
		var te authorization.TokenErrorResponse
		if json.Unmarshal(body, &te) == nil {
			switch te.Error {
			case "use_dpop_nonce":
				c.useNonce = true
			case "invalid_dpop_proof":
				c.invalidProof = true
			}
		}
	}
	return c
}

// getJSON GETs the first candidate URL that returns 200 with a parseable
// body — the fallback order the protocol/authorization ...URLs helpers
// already encode is tried in order, never just the first entry.
func (rc *remoteClient) getJSON(candidates []string, into any) error {
	var lastErr error
	for _, u := range candidates {
		req, err := http.NewRequest(http.MethodGet, u, nil)
		if err != nil {
			lastErr = err
			continue
		}
		resp, err := rc.httpClient.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		status, body, _, err := readResp(resp)
		if err != nil {
			lastErr = err
			continue
		}
		if status != http.StatusOK {
			lastErr = fmt.Errorf("%s: status %d", u, status)
			continue
		}
		if err := json.Unmarshal(body, into); err != nil {
			lastErr = err
			continue
		}
		return nil
	}
	if lastErr == nil {
		lastErr = errors.New("no candidate metadata URLs")
	}
	return lastErr
}

// discover runs the MCP PRM/AS-metadata discovery dance off a 401's
// WWW-Authenticate header, using ONLY the existing protocol/authorization
// helpers (no duplicated discovery logic). Must be called with rc.mu held.
func (rc *remoteClient) discover(challengeHeader string) error {
	var candidates []string
	if prm := authorization.ResourceMetadataURL(challengeHeader); prm != "" {
		candidates = []string{prm}
	} else {
		var err error
		candidates, err = authorization.ProtectedResourceMetadataURLs(rc.endpoint.String())
		if err != nil {
			return fmt.Errorf("remote backend %q: %w", rc.name, err)
		}
	}
	var prm authorization.ProtectedResourceMetadata
	if err := rc.getJSON(candidates, &prm); err != nil {
		return fmt.Errorf("remote backend %q: protected resource metadata: %w", rc.name, err)
	}
	if len(prm.AuthorizationServers) == 0 {
		return fmt.Errorf("remote backend %q: protected resource metadata lists no authorization servers", rc.name)
	}
	asCandidates, err := authorization.AuthorizationServerMetadataURLs(prm.AuthorizationServers[0])
	if err != nil {
		return fmt.Errorf("remote backend %q: %w", rc.name, err)
	}
	var asMeta authorization.AuthorizationServerMetadata
	if err := rc.getJSON(asCandidates, &asMeta); err != nil {
		return fmt.Errorf("remote backend %q: authorization server metadata: %w", rc.name, err)
	}
	if asMeta.TokenEndpoint == "" {
		return fmt.Errorf("remote backend %q: authorization server metadata has no token_endpoint", rc.name)
	}
	rc.tokenEndpoint = asMeta.TokenEndpoint
	return nil
}

// postToken sends one token-endpoint request with the given DPoP proof
// attached, returning the raw status/body/header. Client authentication is
// client_secret_post (when a secret is configured) or none (public client).
func (rc *remoteClient) postToken(grant, proof string) (status int, body []byte, header http.Header, err error) {
	tr := authorization.TokenRequest{
		GrantType:    grant,
		ClientID:     rc.clientID,
		ClientSecret: rc.clientSecret,
		Scope:        rc.scope,
		Resource:     []string{rc.endpoint.String()},
	}
	if grant == authorization.GrantRefreshToken {
		tr.RefreshToken = rc.tok.refreshToken
	}
	req, err := http.NewRequest(http.MethodPost, rc.tokenEndpoint, strings.NewReader(tr.Form().Encode()))
	if err != nil {
		return 0, nil, nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("DPoP", proof)
	resp, err := rc.httpClient.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	return readResp(resp)
}

// rfc6749TokenErrorCodes is the closed set of token-endpoint error codes
// defined by RFC 6749 §5.2. Only a value in this set is ever surfaced into an
// error string; anything else — including a code with extra text appended, a
// non-standard code, or a free-form sentence — is dropped, because the AS is
// untrusted and its "error" field is otherwise a channel for it to reflect
// request material (a client secret, a refresh token) into our local logs.
var rfc6749TokenErrorCodes = map[string]bool{
	"invalid_request":        true,
	"invalid_client":         true,
	"invalid_grant":          true,
	"unauthorized_client":    true,
	"unsupported_grant_type": true,
	"invalid_scope":          true,
}

// tokenErrorFromBody builds an error from a non-200 token response using ONLY
// a whitelisted RFC 6749 §5.2 error code — never the raw response body or an
// unrecognized "error" value, which could (from a buggy or malicious AS) echo
// back request material such as a client secret into our own logs.
func (rc *remoteClient) tokenErrorFromBody(status int, body []byte) error {
	var te authorization.TokenErrorResponse
	_ = json.Unmarshal(body, &te)
	if rfc6749TokenErrorCodes[te.Error] {
		return fmt.Errorf("remote backend %q: token endpoint returned %d %s", rc.name, status, te.Error)
	}
	return fmt.Errorf("remote backend %q: token endpoint returned status %d", rc.name, status)
}

// applyTokenResponse stores a successful token response and, if the AS
// rotated the refresh token, persists the new one atomically. Must be called
// with rc.mu held.
func (rc *remoteClient) applyTokenResponse(body []byte) error {
	var tr authorization.TokenResponse
	if err := json.Unmarshal(body, &tr); err != nil || tr.AccessToken == "" {
		return fmt.Errorf("remote backend %q: token endpoint returned no usable access token", rc.name)
	}
	rc.tok.accessToken = tr.AccessToken
	ttl := time.Duration(tr.ExpiresIn) * time.Second
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	rc.tok.expiresAt = rc.now().Add(ttl)
	if tr.RefreshToken != "" {
		rc.tok.refreshToken = tr.RefreshToken
		if rc.secretsFile != "" {
			if err := rotateSecretInFile(rc.secretsFile, rc.refreshTokenName, tr.RefreshToken); err != nil {
				log.Printf("backend %q: persist rotated refresh token: %v", rc.name, err)
			}
		}
	}
	return nil
}

// fetchToken performs one token-endpoint round trip for grant, handling a
// single use_dpop_nonce retry (never a loop — RFC 9449 Section 8) and
// surfacing invalid_dpop_proof rather than retrying with the identical
// proof. Must be called with rc.mu held and rc.tokenEndpoint already set.
func (rc *remoteClient) fetchToken(grant string) error {
	if rc.tokenEndpoint == "" {
		return fmt.Errorf("remote backend %q: token endpoint not yet discovered", rc.name)
	}
	proof, err := rc.dpop.Proof(http.MethodPost, rc.tokenEndpoint, rc.now(), "", rc.tokenNonce)
	if err != nil {
		return fmt.Errorf("remote backend %q: build token proof: %w", rc.name, err)
	}
	status, body, header, err := rc.postToken(grant, proof)
	if err != nil {
		return fmt.Errorf("remote backend %q: token request: %w", rc.name, err)
	}
	chal := parseDPoPChallenge(status, header, body)
	if chal.useNonce {
		if chal.nonce == "" {
			return fmt.Errorf("remote backend %q: authorization server requested a DPoP nonce but supplied none", rc.name)
		}
		rc.tokenNonce = chal.nonce
		proof2, err := rc.dpop.Proof(http.MethodPost, rc.tokenEndpoint, rc.now(), "", rc.tokenNonce)
		if err != nil {
			return err
		}
		status, body, _, err = rc.postToken(grant, proof2)
		if err != nil {
			return fmt.Errorf("remote backend %q: token request retry: %w", rc.name, err)
		}
		if status != http.StatusOK {
			return rc.tokenErrorFromBody(status, body)
		}
		return rc.applyTokenResponse(body)
	}
	if chal.invalidProof {
		return fmt.Errorf("remote backend %q: authorization server rejected DPoP proof (invalid_dpop_proof)", rc.name)
	}
	if status != http.StatusOK {
		return rc.tokenErrorFromBody(status, body)
	}
	return rc.applyTokenResponse(body)
}

// ensureToken guarantees rc.tok holds an unexpired access token, refreshing
// via the refresh token when possible (no rediscovery — the token endpoint
// stays cached) and falling back to a fresh client_credentials grant.
func (rc *remoteClient) ensureToken() error {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	if rc.tok.accessToken != "" && rc.now().Before(rc.tok.expiresAt) {
		return nil
	}
	if rc.tok.refreshToken != "" {
		if err := rc.fetchToken(authorization.GrantRefreshToken); err == nil {
			return nil
		}
	}
	return rc.fetchToken(authorization.GrantClientCredentials)
}

// rawSend issues one HTTP request to the remote endpoint, attaching the
// DPoP-bound Authorization header and DPoP proof header when present.
func (rc *remoteClient) rawSend(method string, body []byte, accessToken, proof string) (*http.Response, error) {
	req, err := http.NewRequest(method, rc.endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if accessToken != "" {
		req.Header.Set("Authorization", "DPoP "+accessToken)
	}
	if proof != "" {
		req.Header.Set("DPoP", proof)
	}
	return rc.httpClient.Do(req)
}

// authenticatedCall makes one resource-server call with the current access
// token and a fresh DPoP proof (including ath, RFC 9449 Section 4.3),
// handling a single use_dpop_nonce retry and surfacing invalid_dpop_proof
// without retrying.
func (rc *remoteClient) authenticatedCall(method string, body []byte) (int, []byte, http.Header, error) {
	rc.mu.Lock()
	token := rc.tok.accessToken
	nonce := rc.resourceNonce
	rc.mu.Unlock()

	proof, err := rc.dpop.Proof(method, rc.endpoint.String(), rc.now(), token, nonce)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("remote backend %q: build proof: %w", rc.name, err)
	}
	resp, err := rc.rawSend(method, body, token, proof)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("remote backend %q: request: %w", rc.name, err)
	}
	status, respBody, header, err := readResp(resp)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("remote backend %q: read response: %w", rc.name, err)
	}
	chal := parseDPoPChallenge(status, header, respBody)
	if chal.useNonce {
		if chal.nonce == "" {
			return 0, nil, nil, fmt.Errorf("remote backend %q: resource server requested a DPoP nonce but supplied none", rc.name)
		}
		rc.mu.Lock()
		rc.resourceNonce = chal.nonce
		rc.mu.Unlock()
		proof2, err := rc.dpop.Proof(method, rc.endpoint.String(), rc.now(), token, chal.nonce)
		if err != nil {
			return 0, nil, nil, err
		}
		resp2, err := rc.rawSend(method, body, token, proof2)
		if err != nil {
			return 0, nil, nil, fmt.Errorf("remote backend %q: request retry: %w", rc.name, err)
		}
		return readResp(resp2)
	}
	if chal.invalidProof {
		return 0, nil, nil, fmt.Errorf("remote backend %q: resource server rejected DPoP proof (invalid_dpop_proof)", rc.name)
	}
	return status, respBody, header, nil
}

// resourceCall forwards one already-policy-approved mesh request to the
// remote MCP server. On the very first call (tokenEndpoint not yet known) it
// probes unauthenticated to trigger the server's 401 WWW-Authenticate
// challenge, discovers via protocol/authorization, then proceeds
// authenticated — matching the MCP authorization spec's discovery flow.
func (rc *remoteClient) resourceCall(method string, body []byte) (int, []byte, http.Header, error) {
	rc.mu.Lock()
	needDiscovery := rc.tokenEndpoint == ""
	rc.mu.Unlock()

	if needDiscovery {
		resp, err := rc.rawSend(method, body, "", "")
		if err != nil {
			return 0, nil, nil, fmt.Errorf("remote backend %q: discovery probe: %w", rc.name, err)
		}
		status, respBody, header, err := readResp(resp)
		if err != nil {
			return 0, nil, nil, fmt.Errorf("remote backend %q: discovery probe: %w", rc.name, err)
		}
		if status != http.StatusUnauthorized {
			// The server didn't challenge us — return its response as-is.
			return status, respBody, header, nil
		}
		rc.mu.Lock()
		err = rc.discover(header.Get("WWW-Authenticate"))
		rc.mu.Unlock()
		if err != nil {
			return 0, nil, nil, err
		}
	}

	if err := rc.ensureToken(); err != nil {
		return 0, nil, nil, fmt.Errorf("remote backend %q: token: %w", rc.name, err)
	}
	return rc.authenticatedCall(method, body)
}

// rotateSecretInFile atomically rewrites one name/value pair into a flat
// JSON secrets file (the same {"name":"value",...} shape secrets.FileStore
// reads), preserving every other entry, matching cmd/vault/main.go's
// rotate() (tmp file + os.Rename), so an interrupted rotation never leaves a
// half-written file in place of a good one.
func rotateSecretInFile(path, name, value string) error {
	m := map[string]string{}
	b, err := os.ReadFile(path)
	if err == nil {
		if len(b) > 0 {
			if err := json.Unmarshal(b, &m); err != nil {
				return fmt.Errorf("parse secrets file %s: %w", path, err)
			}
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	m[name] = value
	out, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, out, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// remoteHandler builds the mesh-facing handler for a "remote" backend: ACL,
// then (when set) the SAME httpEnforcer (F16) an http backend uses, so
// policy/audit/capability parity holds — the only difference is what happens
// on the outbound leg, which speaks OAuth 2.1 + DPoP to a real third-party
// server instead of reverse-proxying to a trusted local process. A denied
// tool call is answered inline and never reaches rc — no outbound HTTP
// request is made for it. identify is factored out (mirroring
// airControlHandler) so this handler is testable via httptest without a real
// mesh connection.
func remoteHandler(name string, checker acl, enf *httpEnforcer, rc *remoteClient, identify func(*http.Request) (pubKey, fqdn string)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pubKey, fqdn := identify(r)
		if !checker.allows(pubKey, fqdn) {
			log.Printf("backend %q: DENIED peer %s (%s)", name, fqdn, r.RemoteAddr)
			http.Error(w, "forbidden: mesh peer not in backend ACL", http.StatusForbidden)
			return
		}
		if enf != nil {
			ok, status, denial := enf.decide(fqdn, pubKey, r)
			if !ok {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(status)
				_, _ = w.Write(denial)
				return
			}
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, maxRemoteBody))
		r.Body.Close()
		if err != nil {
			http.Error(w, "read request body", http.StatusInternalServerError)
			return
		}
		status, respBody, header, err := rc.resourceCall(r.Method, body)
		if err != nil {
			// err is built only from status codes and standard OAuth error
			// codes (see tokenErrorFromBody/parseDPoPChallenge) — never from
			// raw request/response bytes or the Authorization/DPoP headers,
			// so client_secret/refresh_token/DPoP key material can never
			// surface here.
			log.Printf("backend %q: remote backend error: %v", name, err)
			http.Error(w, "remote backend unavailable", http.StatusBadGateway)
			return
		}
		for k, vs := range header {
			for _, v := range vs {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(status)
		_, _ = w.Write(respBody)
	})
}

// serveRemote exposes a "remote" backend on the mesh port ln.
func serveRemote(client *embed.Client, b *Backend, ln net.Listener, enf *httpEnforcer, rc *remoteClient) {
	checker := b.peerACL()
	identify := func(r *http.Request) (string, string) { return peerIdentityStr(client, r.RemoteAddr) }
	srv := &http.Server{Handler: remoteHandler(b.Name, checker, enf, rc, identify)}
	if err := srv.Serve(ln); err != nil &&
		!errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
		log.Printf("backend %q: serve: %v", b.Name, err)
	}
}
