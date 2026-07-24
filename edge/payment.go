package edge

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"path"
	"sort"

	"github.com/xrey167/meshmcp/policy"
)

// x402 payment gating for the public edge.
//
// The edge already terminates identity (oauth:<client_id>), a deny-by-default
// policy engine + Ed25519 capability, and a fail-closed, hash-chained audit
// log. This file adds the one missing rail for a PAID public MCP: an HTTP 402
// payment challenge on priced tools, verification of a presented payment, and a
// payment-evidence receipt written into the SAME signed audit record that
// already carries the caller's mesh identity — so the log proves
// who-paid-for-which-call without ever storing a wallet. It also exposes an
// optional free dry-run route so a client can prove compatibility (and see the
// exact evidence shape) before paying. See docs/spec/PAYMENT-EVIDENCE.md.

const (
	// headerPayment carries the client's payment payload (base64-encoded JSON),
	// following the x402 convention.
	headerPayment = "X-PAYMENT"
	// headerPaymentResponse relays the facilitator's settlement response back to
	// the client on success.
	headerPaymentResponse = "X-PAYMENT-Response"
	// headerDryRun requests the free dry-run route (any non-empty value).
	headerDryRun = "X-Meshmcp-Dry-Run"
)

// PaymentRequirements is the challenge body returned with HTTP 402: what a
// client must pay, to whom, and where its payment will be verified. It is the
// x402 "payment required" descriptor for one tool call.
type PaymentRequirements struct {
	Scheme            string `json:"scheme"`
	Network           string `json:"network,omitempty"`
	Asset             string `json:"asset,omitempty"`
	MaxAmountRequired string `json:"maxAmountRequired"`
	PayTo             string `json:"payTo,omitempty"`
	Resource          string `json:"resource"`
	Description       string `json:"description,omitempty"`
	Facilitator       string `json:"facilitator,omitempty"`
	// FreeDryRun advertises that this resource has a free dry-run route, so a
	// client can test compatibility before paying.
	FreeDryRun bool `json:"freeDryRun,omitempty"`
}

// Settlement is what a PaymentVerifier returns for a verified payment. Reference
// and Payer are OPAQUE facilitator ids; the gate one-way hashes them into
// PaymentEvidence, so nothing reversible to a wallet is ever stored. Response,
// if set, is relayed to the client as the X-PAYMENT-Response body.
type Settlement struct {
	Reference string
	Payer     string
	Amount    string
	Response  []byte
}

// PaymentVerifier verifies a presented payment against the requirements for a
// call and, on success, returns settlement references. An error denies the call
// (the gate re-challenges with 402). Implementations MUST be fail-closed: any
// doubt about a payment is an error, never a pass. Production injects a client
// of a real x402 facilitator (verify + settle); tests and demos use the
// built-in dev verifier.
type PaymentVerifier interface {
	VerifyPayment(ctx context.Context, req PaymentRequirements, payment []byte) (Settlement, error)
}

// paymentGate is the resolved payment policy for the edge's single backend. A
// nil *paymentGate means payment is disabled and every tool is free.
type paymentGate struct {
	cfg      PaymentConfig
	verifier PaymentVerifier
	salt     string
}

// newPaymentGate builds the gate, or returns (nil, nil) when payment is
// disabled. When payment is enabled it REQUIRES a verifier: an injected one, or
// — only behind the explicit dev_insecure_verifier opt-in — the built-in dev
// verifier. Enabling payment with neither is a fail-closed construction error,
// never a silent downgrade to a verifier that accepts unsettled payments
// (mirrors the DPoP replay-store and signing-key precedents). The payer-hash
// salt defaults to the backend name.
func newPaymentGate(cfg PaymentConfig, backend string, v PaymentVerifier) (*paymentGate, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	if v == nil {
		if !cfg.DevInsecureVerifier {
			return nil, fmt.Errorf("edge: backend.payment.enabled requires a payment verifier, but none was supplied — inject one at construction (a real x402 facilitator client), or set backend.payment.dev_insecure_verifier: true for local testing only (it accepts unsettled payments and must never be used in production)")
		}
		v = devPaymentVerifier{}
	}
	salt := cfg.Salt
	if salt == "" {
		salt = backend
	}
	return &paymentGate{cfg: cfg, verifier: v, salt: salt}, nil
}

// priceFor returns the price for a tool and whether it is priced. Overlapping
// price globs are rejected at config Validate, so at most one entry matches;
// iterating patterns in sorted order makes the lookup deterministic regardless
// (Go map iteration order is randomized) — defense in depth so a pricing result
// can never depend on hash-seed luck even if an overlap ever slipped through.
func (g *paymentGate) priceFor(tool string) (string, bool) {
	patterns := make([]string, 0, len(g.cfg.Prices))
	for pattern := range g.cfg.Prices {
		patterns = append(patterns, pattern)
	}
	sort.Strings(patterns)
	for _, pattern := range patterns {
		if ok, _ := path.Match(pattern, tool); ok {
			return g.cfg.Prices[pattern], true
		}
	}
	return "", false
}

// requirements builds the 402 challenge for one priced tool.
func (g *paymentGate) requirements(tool, price, resourceBase string) PaymentRequirements {
	return PaymentRequirements{
		Scheme:            g.cfg.scheme(),
		Network:           g.cfg.Network,
		Asset:             g.cfg.Asset,
		MaxAmountRequired: price,
		PayTo:             g.cfg.PayTo,
		Resource:          resourceBase + tool,
		Description:       "meshmcp x402 paid tool call: " + tool,
		Facilitator:       g.cfg.Facilitator,
		FreeDryRun:        g.cfg.FreeDryRun,
	}
}

// gatePayment runs the payment step for an already-authorized (capability +
// policy allowed) tools/call. It returns proceed=true when the call should be
// forwarded to the backend; when it returns false it has already written the
// HTTP response (a 402 challenge, a free dry-run result, or a fail-closed
// error). Called only when s.payment != nil.
func (s *Server) gatePayment(w http.ResponseWriter, r *http.Request, au authed, sess *mcpSession, class policy.RPCClass) (proceed bool) {
	g := s.payment

	// An unpriced tool is free: the dry-run header is irrelevant (there is no
	// paid flow to rehearse), so proceed to the backend unchanged. Deciding this
	// BEFORE the dry-run branch keeps dry-run from shadowing real execution of a
	// free tool.
	price, priced := g.priceFor(class.Tool)
	if !priced {
		return true
	}

	// Free dry-run route (priced tools only): validate-only, never charge, never
	// invoke the backend. The caller sees a synthetic result plus dry-run-marked
	// evidence so it can rehearse the paid flow at no cost.
	if g.cfg.FreeDryRun && r.Header.Get(headerDryRun) != "" {
		ev := policy.DryRunEvidence(g.cfg.scheme(), g.cfg.Network, g.cfg.Asset, price)
		if err := s.auditPayment(au.clientID, class.Tool, "x402/dry-run", "allow", "free dry-run", &ev); err != nil {
			// Fail closed: an unrecorded decision is denied, even a free one.
			s.writeJSONRPC(w, jsonRPCErrorResponse(class.ID, -32002, "dry-run blocked: audit sink unavailable (fail-closed)"))
			return false
		}
		if sess != nil {
			w.Header().Set(headerSessionID, sess.id)
		}
		s.writeJSONRPC(w, dryRunResult(class.ID, class.Tool, ev))
		return false
	}

	req := g.requirements(class.Tool, price, s.cfg.PublicURL+pathMCP+"#")
	payload, ok := decodePaymentHeader(r.Header.Get(headerPayment))
	if !ok {
		_ = s.auditPayment(au.clientID, class.Tool, "x402/require", "deny", "payment required", nil)
		s.writePaymentRequired(w, req)
		return false
	}
	settle, err := g.verifier.VerifyPayment(r.Context(), req, payload)
	if err != nil {
		// The verifier's error may echo payload/settlement content (a real
		// facilitator client can build errors naming an address or token). Record
		// only a FIXED reason in the exportable, wallet-free audit log; the detail
		// goes to the operator's local log, never the shared chain.
		log.Printf("edge: payment verify rejected for %s tool %q: %v", oauthIdentity(au.clientID), class.Tool, err)
		_ = s.auditPayment(au.clientID, class.Tool, "x402/require", "deny", "payment rejected by verifier", nil)
		s.writePaymentRequired(w, req)
		return false
	}

	amount := settle.Amount
	if amount == "" {
		amount = price
	}
	ev := policy.NewPaymentEvidence(g.cfg.scheme(), g.cfg.Network, g.cfg.Asset, amount, settle.Reference, settle.Payer, g.salt)
	if err := s.auditPayment(au.clientID, class.Tool, "x402/settle", "allow", "x402 settled", &ev); err != nil {
		// Fail closed: a paid call whose evidence cannot be recorded is denied.
		// The client can retry — a real facilitator settles the same payment
		// authorization idempotently, so a retry re-derives the same reference
		// rather than double-charging. We do NOT forward on an unrecorded settlement.
		s.writeJSONRPC(w, jsonRPCErrorResponse(class.ID, -32002, "tool blocked: payment settled but the audit sink is unavailable (fail-closed) — retry, the settlement is idempotent"))
		return false
	}
	if len(settle.Response) > 0 {
		w.Header().Set(headerPaymentResponse, base64.StdEncoding.EncodeToString(settle.Response))
	}
	return true
}

// writePaymentRequired writes an HTTP 402 with the x402 requirements body and an
// Accept-Payment header naming the scheme, mirroring how authenticate writes a
// 401 bearer challenge.
func (s *Server) writePaymentRequired(w http.ResponseWriter, req PaymentRequirements) {
	w.Header().Set("Accept-Payment", req.Scheme)
	writeJSON(w, http.StatusPaymentRequired, map[string]any{
		"error":   "payment_required",
		"accepts": []PaymentRequirements{req},
	})
}

// auditPayment records a payment-lifecycle decision (require / settle / dry-run)
// under the client's synthetic identity, with the payment evidence (when any)
// on the SAME record as the mesh identity. Fail-closed like every edge write.
func (s *Server) auditPayment(clientID, tool, method, decision, reason string, ev *policy.PaymentEvidence) error {
	return s.audit.append(policy.AuditRecord{
		Backend:  "edge:" + s.cfg.Backend.Name,
		Peer:     oauthIdentity(clientID),
		PeerKey:  oauthIdentity(clientID),
		Method:   method,
		Tool:     tool,
		Decision: decision,
		Reason:   reason,
		Rule:     -1,
		Payment:  ev,
	})
}

// dryRunResult builds a well-formed tools/call result for the dry-run route: a
// text acknowledgement plus the dry-run payment evidence in _meta, so a client
// parses exactly the envelope (and evidence shape) it will see when paying.
func dryRunResult(id json.RawMessage, tool string, ev policy.PaymentEvidence) []byte {
	result, _ := json.Marshal(map[string]any{
		"content": []map[string]any{{
			"type": "text",
			"text": fmt.Sprintf("meshmcp dry-run: identity and policy checks passed for %q. No payment was charged and the backend was not invoked.", tool),
		}},
		"isError": false,
		"_meta": map[string]any{
			"meshmcp/dryRun":  true,
			"meshmcp/payment": ev,
		},
	})
	return jsonRPCResultResponse(id, result)
}

// decodePaymentHeader decodes the X-PAYMENT header into raw JSON payment bytes.
// Per x402 the value is base64-encoded JSON; a raw JSON value is also accepted
// (tolerant reader). Returns ok=false for an empty or undecodable header.
func decodePaymentHeader(v string) ([]byte, bool) {
	if v == "" {
		return nil, false
	}
	if b, err := base64.StdEncoding.DecodeString(v); err == nil && json.Valid(b) {
		return b, true
	}
	if b, err := base64.RawURLEncoding.DecodeString(v); err == nil && json.Valid(b) {
		return b, true
	}
	if json.Valid([]byte(v)) {
		return []byte(v), true
	}
	return nil, false
}

// devPaymentVerifier is a DEVELOPMENT / self-hosted verifier. It checks that a
// presented payload is well-formed and commits to the required amount/asset with
// a non-empty authorization, then treats the payment as settled and derives a
// deterministic settlement reference from the payload. It performs NO on-chain
// settlement and NO signature verification — it exists so the 402 → pay → retry
// handshake, the dry-run route, and the evidence pipeline are testable and
// demoable end to end. Production injects a real facilitator client via
// Options.PaymentVerifier.
type devPaymentVerifier struct{}

// devPayment is the payload the dev verifier accepts inside X-PAYMENT (the
// base64-decoded JSON), mirroring the essential x402 fields.
type devPayment struct {
	Scheme        string `json:"scheme"`
	Network       string `json:"network"`
	Asset         string `json:"asset"`
	Amount        string `json:"amount"`
	Payer         string `json:"payer"`
	Authorization string `json:"authorization"`
}

func (devPaymentVerifier) VerifyPayment(_ context.Context, req PaymentRequirements, payment []byte) (Settlement, error) {
	var p devPayment
	if err := json.Unmarshal(payment, &p); err != nil {
		return Settlement{}, fmt.Errorf("malformed payment payload: %w", err)
	}
	if p.Authorization == "" {
		return Settlement{}, fmt.Errorf("payment missing authorization")
	}
	// maxAmountRequired is a ceiling the payer authorizes up to, so accept any
	// amount that MEETS OR EXCEEDS the price; compare as integers (minor units),
	// never as strings ("9" > "1000" lexically).
	paid, okPaid := new(big.Int).SetString(p.Amount, 10)
	need, okNeed := new(big.Int).SetString(req.MaxAmountRequired, 10)
	if !okPaid {
		return Settlement{}, fmt.Errorf("payment amount %q is not an integer in minor units", p.Amount)
	}
	if !okNeed {
		return Settlement{}, fmt.Errorf("required amount %q is not an integer in minor units", req.MaxAmountRequired)
	}
	if paid.Sign() <= 0 {
		return Settlement{}, fmt.Errorf("payment amount %q must be positive", p.Amount)
	}
	if paid.Cmp(need) < 0 {
		return Settlement{}, fmt.Errorf("payment amount %q is below the required %q", p.Amount, req.MaxAmountRequired)
	}
	if req.Asset != "" && p.Asset != "" && p.Asset != req.Asset {
		return Settlement{}, fmt.Errorf("payment asset %q != required %q", p.Asset, req.Asset)
	}
	sum := sha256.Sum256(append([]byte("meshmcp-dev-settle\x00"), payment...))
	return Settlement{Reference: hex.EncodeToString(sum[:]), Payer: p.Payer, Amount: p.Amount}, nil
}
