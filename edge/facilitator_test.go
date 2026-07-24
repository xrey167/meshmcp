package edge

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// mockFacilitator is an httptest x402 facilitator. When reject is set it fails
// /verify; otherwise it verifies and settles with a fixed transaction.
func mockFacilitator(t *testing.T, reject *atomic.Bool) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/verify":
			if reject.Load() {
				_ = json.NewEncoder(w).Encode(verifyResponse{IsValid: false, InvalidReason: "invalid signature"})
				return
			}
			_ = json.NewEncoder(w).Encode(verifyResponse{IsValid: true})
		case "/settle":
			_ = json.NewEncoder(w).Encode(settleResponse{Success: true, Transaction: "0xtx-abc123", Payer: "0xpayer", Network: "base-sepolia"})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// The HTTP facilitator verifier settles an accepted payment (call forwards) and
// re-challenges a rejected one — end to end through the edge gate.
func TestHTTPFacilitatorVerifier(t *testing.T) {
	var reject atomic.Bool
	fac := mockFacilitator(t, &reject)
	pay := basicPayment()
	pay.DevInsecureVerifier = false
	pay.Facilitator = fac.URL
	ts, token, audit, _ := newPaidServerFull(t, pay, startBackend(t), NewHTTPFacilitatorVerifier(fac.URL), nil)
	sid := initSession(t, ts.URL, token)

	// Accepted → forwards to backend and records the facilitator's settlement.
	resp := callTool(t, ts.URL, token, sid, map[string]string{
		headerPayment: xPaymentHeader("1000", "USDC", "0xPayer"),
	})
	body := decodeRPC(t, resp)
	resp.Body.Close()
	if body["error"] != nil {
		t.Fatalf("facilitator-verified payment should forward: %v", body["error"])
	}
	if res, _ := body["result"].(map[string]any); res == nil {
		t.Fatalf("expected backend result: %v", body)
	}
	if !strings.Contains(audit.String(), "x402/settle") {
		t.Fatalf("settlement should be recorded: %s", audit.String())
	}

	// Rejected → 402 (a fresh payment each attempt; single-use is not the point here).
	reject.Store(true)
	resp = callTool(t, ts.URL, token, sid, map[string]string{
		headerPayment: xPaymentHeader("1000", "USDC", "0xPayer2"),
	})
	status := resp.StatusCode
	resp.Body.Close()
	if status != http.StatusPaymentRequired {
		t.Fatalf("facilitator-rejected payment should 402, got %d", status)
	}
}

// A facilitator that reports success but no transaction reference is treated as
// a failed settlement (fail-closed — no proof).
func TestHTTPFacilitatorNoTransactionFailsClosed(t *testing.T) {
	fac := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/verify":
			_ = json.NewEncoder(w).Encode(verifyResponse{IsValid: true})
		case "/settle":
			_ = json.NewEncoder(w).Encode(settleResponse{Success: true, Transaction: ""}) // no proof
		}
	}))
	t.Cleanup(fac.Close)
	pay := basicPayment()
	pay.DevInsecureVerifier = false
	pay.Facilitator = fac.URL
	ts, token, _, _ := newPaidServerFull(t, pay, startBackend(t), NewHTTPFacilitatorVerifier(fac.URL), nil)
	sid := initSession(t, ts.URL, token)
	resp := callTool(t, ts.URL, token, sid, map[string]string{
		headerPayment: xPaymentHeader("1000", "USDC", "0xP"),
	})
	status := resp.StatusCode
	resp.Body.Close()
	if status != http.StatusPaymentRequired {
		t.Fatalf("a settlement with no transaction must fail closed (402), got %d", status)
	}
}
