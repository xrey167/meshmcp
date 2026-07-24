package edge

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xrey167/meshmcp/mcp"
)

// syncBuffer is an audit sink that is safe to read from the test goroutine
// while the server handler writes from its own.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

// newPaidServer builds an edge server whose backend prices tools per the
// supplied PaymentConfig, capturing the audit chain so tests can inspect the
// payment evidence. Mirrors newMCPServer's OAuth bootstrap.
func newPaidServer(t *testing.T, pay PaymentConfig) (*httptest.Server, string, *syncBuffer) {
	ts, tok, audit, _ := newPaidServerDial(t, pay, startBackend(t))
	return ts, tok, audit
}

// newPaidServerDial is newPaidServer with an injectable backend dial (so a test
// can observe backend invocations). Returns the server, an access token, the
// captured audit chain, and the constructed *Server.
func newPaidServerDial(t *testing.T, pay PaymentConfig, dial DialBackend) (*httptest.Server, string, *syncBuffer, *Server) {
	t.Helper()
	dir := t.TempDir()
	cfg := validConfig()
	cfg.StateDir = dir
	cfg.AuditLog = dir + "/audit.jsonl"
	cfg.SigningKey = dir + "/key.json"
	cfg.Limits.RegisterPerIPPerMin = 10000
	cfg.Limits.PreauthPerIPPerMin = 10000
	cfg.Limits.PerClientRPS = 10000
	cfg.Backend.Tools = []string{"search_*", "forbidden_tool"}
	cfg.Backend.Policy = policyAllowSearch()
	cfg.Backend.Payment = pay

	audit := &syncBuffer{}
	srv, err := New(cfg, Options{
		Now:         func() time.Time { return time.Now() },
		Signer:      mustSigner(t),
		AuditWriter: audit,
		DialBackend: dial,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	clientID := approvedClient(t, srv, ts, testRedirect)
	verifier, challenge := pkcePair()
	code := runAuthorize(t, srv, ts, clientID, testRedirect, challenge, "s")
	_, tok := postToken(t, ts.URL, url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "client_id": {clientID},
		"redirect_uri": {testRedirect}, "code_verifier": {verifier},
	})
	return ts, tok.AccessToken, audit, srv
}

// countingBackend is a DialBackend exposing search_docs that increments *calls
// each time the tool actually runs, so a test can prove whether the backend was
// invoked (e.g. that the dry-run route does NOT reach it).
func countingBackend(t testing.TB, calls *int64) DialBackend {
	t.Helper()
	build := func() *mcp.Server {
		srv := mcp.New("test-backend", "1.0")
		srv.AddTool(mcp.Tool{
			Name: "search_docs",
			Handler: func(ctx context.Context, args json.RawMessage) (mcp.ToolResult, error) {
				atomic.AddInt64(calls, 1)
				return mcp.ToolResult{Content: []mcp.Content{mcp.Text("found: " + string(args))}}, nil
			},
		})
		return srv
	}
	return func(ctx context.Context) (net.Conn, error) {
		clientSide, serverSide := net.Pipe()
		srv := build()
		go func() {
			_ = srv.Serve(context.Background(), serverSide, serverSide)
			serverSide.Close()
		}()
		return clientSide, nil
	}
}

// basicPayment enables payment with the dev verifier (test-only opt-in), pricing
// search_* and exposing the free dry-run route.
func basicPayment() PaymentConfig {
	return PaymentConfig{
		Enabled:             true,
		Network:             "base-sepolia",
		Asset:               "USDC",
		PayTo:               "0xServerPayToAddress",
		Prices:              map[string]string{"search_*": "1000"},
		FreeDryRun:          true,
		DevInsecureVerifier: true,
	}
}

// xPaymentHeader base64-encodes a dev-verifier payment payload.
func xPaymentHeader(amount, asset, payer string) string {
	b, _ := json.Marshal(map[string]string{
		"scheme": "x402", "asset": asset, "amount": amount,
		"payer": payer, "authorization": "signed-transfer-authorization",
	})
	return base64.StdEncoding.EncodeToString(b)
}

func callTool(t *testing.T, base, token, sid string, extra map[string]string) *http.Response {
	t.Helper()
	body := `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"search_docs","arguments":{"q":"hi"}}}`
	req, _ := http.NewRequest(http.MethodPost, base+pathMCP, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	if sid != "" {
		req.Header.Set(headerSessionID, sid)
	}
	for k, v := range extra {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func initSession(t *testing.T, base, token string) string {
	t.Helper()
	resp := mcpPostReq(t, base, token, "", `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
	sid := resp.Header.Get(headerSessionID)
	resp.Body.Close()
	if sid == "" {
		t.Fatal("initialize must issue a session id")
	}
	return sid
}

// A priced tool called WITHOUT a payment returns HTTP 402 with an x402
// requirements body — the payment challenge — and does not forward.
func TestPaymentRequiredChallenge(t *testing.T) {
	ts, token, audit := newPaidServer(t, basicPayment())
	sid := initSession(t, ts.URL, token)

	resp := callTool(t, ts.URL, token, sid, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusPaymentRequired {
		t.Fatalf("priced tool without payment → want 402, got %d", resp.StatusCode)
	}
	if got := resp.Header.Get("Accept-Payment"); got != "x402" {
		t.Fatalf("Accept-Payment header = %q, want x402", got)
	}
	var body struct {
		Error   string                `json:"error"`
		Accepts []PaymentRequirements `json:"accepts"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode 402 body: %v", err)
	}
	if body.Error != "payment_required" || len(body.Accepts) != 1 {
		t.Fatalf("unexpected 402 body: %+v", body)
	}
	req := body.Accepts[0]
	if req.MaxAmountRequired != "1000" || req.Asset != "USDC" || req.PayTo != "0xServerPayToAddress" {
		t.Fatalf("challenge requirements wrong: %+v", req)
	}
	if !req.FreeDryRun {
		t.Fatal("challenge should advertise the free dry-run route")
	}
	if !strings.Contains(audit.String(), "x402/require") {
		t.Fatalf("payment-required decision must be audited: %s", audit.String())
	}
}

// A valid X-PAYMENT lets the call through to the backend and records a payment
// receipt — carrying derived refs, NOT wallet details — on the same audit
// record as the caller's mesh identity.
func TestPaymentAcceptedForwardsAndRecordsEvidence(t *testing.T) {
	ts, token, audit := newPaidServer(t, basicPayment())
	sid := initSession(t, ts.URL, token)

	resp := callTool(t, ts.URL, token, sid, map[string]string{
		headerPayment: xPaymentHeader("1000", "USDC", "0xPayerWalletSecret"),
	})
	body := decodeRPC(t, resp)
	resp.Body.Close()
	if body["error"] != nil {
		t.Fatalf("paid call returned error: %v", body["error"])
	}
	res, _ := body["result"].(map[string]any)
	txt, _ := json.Marshal(res)
	if !strings.Contains(string(txt), "found:") {
		t.Fatalf("paid call did not reach backend (result=%v)", res)
	}

	// The settlement must be recorded with payment evidence and NO wallet leak.
	log := audit.String()
	settle := findAuditRecord(t, log, "x402/settle")
	pay, ok := settle["payment"].(map[string]any)
	if !ok {
		t.Fatalf("settle record missing payment evidence: %v", settle)
	}
	if pay["payment_ref"] == nil || pay["payer_ref"] == nil {
		t.Fatalf("evidence must carry derived refs: %v", pay)
	}
	if pay["scheme"] != "x402" || pay["asset"] != "USDC" || pay["amount"] != "1000" {
		t.Fatalf("evidence descriptors wrong: %v", pay)
	}
	if strings.Contains(log, "0xPayerWalletSecret") {
		t.Fatalf("audit log leaked the payer wallet: %s", log)
	}
	// The mesh identity sits on the SAME record as the payment evidence.
	if !strings.HasPrefix(settle["peer"].(string), "oauth:") {
		t.Fatalf("settle record must carry the caller's mesh identity: %v", settle["peer"])
	}
}

// A wrong payment amount is rejected and re-challenged (fail-closed verify).
func TestPaymentRejectedReChallenges(t *testing.T) {
	ts, token, _ := newPaidServer(t, basicPayment())
	sid := initSession(t, ts.URL, token)

	resp := callTool(t, ts.URL, token, sid, map[string]string{
		headerPayment: xPaymentHeader("1", "USDC", "0xPayer"), // underpaid
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusPaymentRequired {
		t.Fatalf("underpayment → want 402, got %d", resp.StatusCode)
	}
}

// The free dry-run route validates identity + policy and returns a synthetic
// result WITHOUT charging or invoking the backend, with dry-run-marked evidence.
func TestFreeDryRunRoute(t *testing.T) {
	ts, token, audit := newPaidServer(t, basicPayment())
	sid := initSession(t, ts.URL, token)

	resp := callTool(t, ts.URL, token, sid, map[string]string{headerDryRun: "1"})
	body := decodeRPC(t, resp)
	resp.Body.Close()
	if body["error"] != nil {
		t.Fatalf("dry-run returned error: %v", body["error"])
	}
	res, _ := body["result"].(map[string]any)
	blob, _ := json.Marshal(res)
	if strings.Contains(string(blob), "found:") {
		t.Fatal("dry-run must NOT invoke the backend")
	}
	if !strings.Contains(string(blob), "dry-run") {
		t.Fatalf("dry-run result should be the synthetic acknowledgement: %s", blob)
	}
	meta, _ := res["_meta"].(map[string]any)
	pay, _ := meta["meshmcp/payment"].(map[string]any)
	if pay == nil || pay["dry_run"] != true {
		t.Fatalf("dry-run result must carry dry-run-marked evidence in _meta: %v", meta)
	}
	rec := findAuditRecord(t, audit.String(), "x402/dry-run")
	if p, _ := rec["payment"].(map[string]any); p["dry_run"] != true {
		t.Fatalf("dry-run must be audited with dry-run evidence: %v", rec)
	}
}

// A tool that matches no price entry stays free even when payment is enabled.
func TestUnpricedToolIsFree(t *testing.T) {
	pay := basicPayment()
	pay.Prices = map[string]string{"premium_*": "1000"} // does not match search_docs
	ts, token, _ := newPaidServer(t, pay)
	sid := initSession(t, ts.URL, token)

	resp := callTool(t, ts.URL, token, sid, nil) // no X-PAYMENT
	body := decodeRPC(t, resp)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || body["error"] != nil {
		t.Fatalf("unpriced tool should forward freely, got status %d body %v", resp.StatusCode, body)
	}
	if res, _ := body["result"].(map[string]any); res == nil {
		t.Fatalf("unpriced tool should return the backend result: %v", body)
	}
}

// Enabling payment with no injected verifier and no explicit dev opt-in is a
// fail-closed construction error — never a silent downgrade to a verifier that
// accepts unsettled payments.
func TestPaymentEnabledWithoutVerifierFailsClosed(t *testing.T) {
	dir := t.TempDir()
	cfg := validConfig()
	cfg.StateDir = dir
	cfg.AuditLog = dir + "/audit.jsonl"
	cfg.SigningKey = dir + "/key.json"
	cfg.Backend.Payment = PaymentConfig{Enabled: true, Asset: "USDC", Prices: map[string]string{"search_*": "1000"}}
	// no PaymentVerifier injected, dev_insecure_verifier not set
	_, err := New(cfg, Options{
		Now: func() time.Time { return time.Now() }, Signer: mustSigner(t),
		AuditWriter: &discardWriter{}, DialBackend: startBackend(t),
	})
	if err == nil {
		t.Fatal("payment enabled without a verifier or dev opt-in must be a construction error")
	}
	if !strings.Contains(err.Error(), "requires a payment verifier") {
		t.Fatalf("error should explain the missing verifier and the next step, got: %v", err)
	}

	// With the explicit dev opt-in, construction succeeds.
	cfg.Backend.Payment.DevInsecureVerifier = true
	if _, err := New(cfg, Options{
		Now: func() time.Time { return time.Now() }, Signer: mustSigner(t),
		AuditWriter: &discardWriter{}, DialBackend: startBackend(t),
	}); err != nil {
		t.Fatalf("dev_insecure_verifier opt-in should allow construction: %v", err)
	}
}

// End-to-end proof that the free dry-run route never reaches the backend, while
// a paid call does — using a backend that counts invocations.
func TestDryRunDoesNotInvokeBackendButPaidDoes(t *testing.T) {
	var calls int64
	ts, token, _, _ := newPaidServerDial(t, basicPayment(), countingBackend(t, &calls))
	sid := initSession(t, ts.URL, token)

	// Dry-run: must not touch the backend.
	resp := callTool(t, ts.URL, token, sid, map[string]string{headerDryRun: "1"})
	resp.Body.Close()
	if got := atomic.LoadInt64(&calls); got != 0 {
		t.Fatalf("dry-run must not invoke the backend, but it ran %d time(s)", got)
	}

	// Paid: must reach the backend exactly once.
	resp = callTool(t, ts.URL, token, sid, map[string]string{
		headerPayment: xPaymentHeader("1000", "USDC", "0xPayer"),
	})
	resp.Body.Close()
	if got := atomic.LoadInt64(&calls); got != 1 {
		t.Fatalf("paid call should invoke the backend exactly once, got %d", got)
	}
}

// Overpayment (amount above the price ceiling) is accepted — maxAmountRequired
// is a ceiling the payer authorizes up to, not an exact match.
func TestOverpaymentAccepted(t *testing.T) {
	ts, token, _ := newPaidServer(t, basicPayment())
	sid := initSession(t, ts.URL, token)
	resp := callTool(t, ts.URL, token, sid, map[string]string{
		headerPayment: xPaymentHeader("2000", "USDC", "0xPayer"), // price is 1000
	})
	body := decodeRPC(t, resp)
	resp.Body.Close()
	if body["error"] != nil {
		t.Fatalf("overpayment should be accepted, got error: %v", body["error"])
	}
}

// The tolerant X-PAYMENT decoder accepts raw-URL base64 and raw JSON, not only
// std base64.
func TestPaymentHeaderDecodingVariants(t *testing.T) {
	raw, _ := json.Marshal(map[string]string{
		"scheme": "x402", "asset": "USDC", "amount": "1000",
		"payer": "0xPayer", "authorization": "auth",
	})
	variants := map[string]string{
		"raw-json":      string(raw),
		"base64-rawurl": base64.RawURLEncoding.EncodeToString(raw),
		"base64-std":    base64.StdEncoding.EncodeToString(raw),
	}
	for name, header := range variants {
		t.Run(name, func(t *testing.T) {
			ts, token, _ := newPaidServer(t, basicPayment())
			sid := initSession(t, ts.URL, token)
			resp := callTool(t, ts.URL, token, sid, map[string]string{headerPayment: header})
			body := decodeRPC(t, resp)
			resp.Body.Close()
			if body["error"] != nil {
				t.Fatalf("%s X-PAYMENT should be accepted, got error: %v", name, body["error"])
			}
		})
	}
}

// With the dry-run header set on an UNPRICED tool, the gate must NOT shadow the
// real (free) execution: the backend runs and returns its real result.
func TestDryRunHeaderOnUnpricedToolStillExecutes(t *testing.T) {
	pay := basicPayment()
	pay.Prices = map[string]string{"premium_*": "1000"} // search_docs is unpriced/free
	var calls int64
	ts, token, _, _ := newPaidServerDial(t, pay, countingBackend(t, &calls))
	sid := initSession(t, ts.URL, token)

	resp := callTool(t, ts.URL, token, sid, map[string]string{headerDryRun: "1"})
	body := decodeRPC(t, resp)
	resp.Body.Close()
	if body["error"] != nil {
		t.Fatalf("unpriced tool with dry-run header should still execute, got: %v", body["error"])
	}
	if atomic.LoadInt64(&calls) != 1 {
		t.Fatal("a free tool must actually execute even when the dry-run header is present")
	}
	blob, _ := json.Marshal(body["result"])
	if !strings.Contains(string(blob), "found:") {
		t.Fatalf("free tool should return the real backend result, not a synthetic dry-run: %s", blob)
	}
}

// The full x402 handshake in one session: unpaid → 402, then retry with payment
// → success, same session id.
func TestFullX402HandshakeSequence(t *testing.T) {
	ts, token, _ := newPaidServer(t, basicPayment())
	sid := initSession(t, ts.URL, token)

	// 1) Unpaid → 402.
	resp := callTool(t, ts.URL, token, sid, nil)
	status := resp.StatusCode
	resp.Body.Close()
	if status != http.StatusPaymentRequired {
		t.Fatalf("first call should be 402, got %d", status)
	}
	// 2) Retry with payment on the same session → success.
	resp = callTool(t, ts.URL, token, sid, map[string]string{
		headerPayment: xPaymentHeader("1000", "USDC", "0xPayer"),
	})
	body := decodeRPC(t, resp)
	resp.Body.Close()
	if body["error"] != nil || body["result"] == nil {
		t.Fatalf("paid retry should succeed, got: %v", body)
	}
}

// findAuditRecord returns the first audit record whose method matches, failing
// the test if none is present.
func findAuditRecord(t *testing.T, log, method string) map[string]any {
	t.Helper()
	for _, line := range strings.Split(strings.TrimSpace(log), "\n") {
		if line == "" {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("audit line not JSON: %v (%s)", err, line)
		}
		if rec["method"] == method {
			return rec
		}
	}
	t.Fatalf("no audit record with method %q in:\n%s", method, log)
	return nil
}
