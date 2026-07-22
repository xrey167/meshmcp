package federation

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// FuzzDCRRegisterMetadata fuzzes the RFC 7591 registration metadata parser
// (the JSON decode into registerRequestBody) — the untrusted body a registrant
// controls. It must never panic on any input. Upgraded from optional to
// required for C1 sign-off per OAUTH-STANDARDS-tests.md.
func FuzzDCRRegisterMetadata(f *testing.F) {
	f.Add([]byte(`{"client_name":"ok"}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"client_name":123}`))
	f.Add([]byte(`{"client_name":"` + strings.Repeat("a", 4096) + `"}`))
	f.Add([]byte(``))
	f.Add([]byte(`[not json`))
	f.Fuzz(func(t *testing.T, data []byte) {
		var meta registerRequestBody
		_ = json.Unmarshal(data, &meta) // must not panic
	})
}

// FuzzAuthorizationDetails fuzzes the RFC 9396 authorization_details parser
// (decodeAuthorizationDetails), the untrusted field a federation partner sends
// to the exchange endpoint. It must never panic. Upgraded to required for C2
// sign-off per OAUTH-STANDARDS-tests.md.
func FuzzAuthorizationDetails(f *testing.F) {
	f.Add(``)
	f.Add(`[{"type":"` + authDetailsType + `","actions":["read_file"],"locations":["backend-a"],"datatypes":["public"]}]`)
	f.Add(`not json`)
	f.Add(`[{"type":123}]`)
	f.Add(`[` + strings.Repeat(`{"type":"x"},`, 1000) + `{"type":"x"}]`)
	f.Fuzz(func(t *testing.T, s string) {
		_, _ = decodeAuthorizationDetails(s) // must not panic
	})
}

// TestExchange_OversizedBodyRejected is the C2 analogue of C1's
// TestDCR_MaxBytesReaderEnforced: a token-exchange body far exceeding
// exchangeMaxBodyBytes must be rejected, not fully buffered and parsed.
func TestExchange_OversizedBodyRejected(t *testing.T) {
	f := newExchangeFixture(t, Grant{Org: "acme", Tools: []string{"read_file"}})
	subject := f.validAcmeSubjectToken(t, "user-1")
	huge := strings.Repeat("a", exchangeMaxBodyBytes+8<<10)
	form := validExchangeForm(t, f, subject, huge)

	resp := doExchange(t, f, f.dpopProof(t), nil, form)
	if resp.StatusCode == http.StatusOK {
		t.Fatalf("oversized exchange body (%d bytes) must be rejected, got 200", len(huge))
	}
}
