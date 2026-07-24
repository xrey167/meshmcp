package edge

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// HTTPFacilitatorVerifier is a production PaymentVerifier that delegates payment
// verification and settlement to an x402 facilitator over HTTP: it POSTs the
// presented payment and the requirements to the facilitator's /verify endpoint,
// and — only if valid — to /settle, returning the on-chain settlement reference.
// It is the "real verifier" a payment-enabled edge needs instead of the
// dev verifier; cmd/meshmcp wires it from backend.payment.facilitator.
//
// It performs NO on-chain work itself — the facilitator is the trusted collabo-
// rator that MUST verify payTo/network/asset/amount and the payment signature,
// and settle the authorization single-use (see the verifier contract in
// docs/spec/PAYMENT-EVIDENCE.md). meshmcp adds its own single-use, amount
// cross-check, and audit on top.
type HTTPFacilitatorVerifier struct {
	baseURL string
	client  *http.Client
}

// NewHTTPFacilitatorVerifier builds a verifier for the facilitator at baseURL.
// The HTTP client carries a bounded timeout (the gate also bounds the call).
func NewHTTPFacilitatorVerifier(baseURL string) *HTTPFacilitatorVerifier {
	return &HTTPFacilitatorVerifier{
		baseURL: strings.TrimRight(baseURL, "/"),
		client:  &http.Client{Timeout: paymentVerifyTimeout},
	}
}

// facilitatorRequest is the x402 facilitator request envelope for both /verify
// and /settle: the version, the decoded payment payload, and the requirements.
type facilitatorRequest struct {
	X402Version         int                 `json:"x402Version"`
	PaymentPayload      json.RawMessage     `json:"paymentPayload"`
	PaymentRequirements PaymentRequirements `json:"paymentRequirements"`
}

type verifyResponse struct {
	IsValid       bool   `json:"isValid"`
	InvalidReason string `json:"invalidReason"`
}

type settleResponse struct {
	Success     bool   `json:"success"`
	ErrorReason string `json:"errorReason"`
	Transaction string `json:"transaction"`
	Network     string `json:"network"`
	Payer       string `json:"payer"`
}

// VerifyPayment verifies then settles via the facilitator. Any transport error,
// a non-200 status, an invalid verification, or a failed settlement denies the
// call (fail-closed). Facilitator error text is returned to the gate, which
// keeps it out of the audit log and the process log.
func (f *HTTPFacilitatorVerifier) VerifyPayment(ctx context.Context, req PaymentRequirements, payment []byte) (Settlement, error) {
	body := facilitatorRequest{X402Version: 1, PaymentPayload: json.RawMessage(payment), PaymentRequirements: req}

	var vr verifyResponse
	if err := f.post(ctx, "/verify", body, &vr); err != nil {
		return Settlement{}, err
	}
	if !vr.IsValid {
		return Settlement{}, fmt.Errorf("facilitator rejected payment: %s", vr.InvalidReason)
	}

	var sr settleResponse
	if err := f.post(ctx, "/settle", body, &sr); err != nil {
		return Settlement{}, err
	}
	if !sr.Success {
		return Settlement{}, fmt.Errorf("facilitator settle failed: %s", sr.ErrorReason)
	}
	if sr.Transaction == "" {
		return Settlement{}, fmt.Errorf("facilitator settle returned no transaction reference")
	}
	resp, _ := json.Marshal(sr)
	return Settlement{Reference: sr.Transaction, Payer: sr.Payer, Amount: req.MaxAmountRequired, Response: resp}, nil
}

// post sends one JSON request to the facilitator endpoint and decodes a JSON
// response. A non-2xx status is an error (fail-closed). The response body is
// bounded so a hostile/broken facilitator cannot exhaust memory.
func (f *HTTPFacilitatorVerifier) post(ctx context.Context, path string, in, out any) error {
	buf, err := json.Marshal(in)
	if err != nil {
		return fmt.Errorf("facilitator: marshal %s: %w", path, err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, f.baseURL+path, bytes.NewReader(buf))
	if err != nil {
		return fmt.Errorf("facilitator: new request %s: %w", path, err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := f.client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("facilitator: %s: %w", path, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return fmt.Errorf("facilitator: read %s: %w", path, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("facilitator: %s returned status %d", path, resp.StatusCode)
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("facilitator: decode %s: %w", path, err)
	}
	return nil
}

// compile-time: HTTPFacilitatorVerifier is a PaymentVerifier.
var _ PaymentVerifier = (*HTTPFacilitatorVerifier)(nil)
