package federation

import (
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/xrey167/meshmcp/policy"
	"github.com/xrey167/meshmcp/protocol/authorization"
)

// TestExchange_EmptyCorporaDeniesByDefault covers the C2 corpora-intersection
// fix. CapabilityClaims.AllowsCorpus treats an empty Corpora list as allow-all
// — right for a locally-issued capability, wrong for a cross-org one. When the
// org grants no corpus, or the partner requests none, the minted federation
// capability must reach NO corpus, not every corpus.
func TestExchange_EmptyCorporaDeniesByDefault(t *testing.T) {
	// Unit: the clamp itself is deny-by-default and pass-through otherwise.
	denied := clampCorpora(nil)
	if len(denied) == 0 {
		t.Fatal("clampCorpora(nil) must return a non-empty deny-all sentinel, not an empty (allow-all) list")
	}
	if (policy.CapabilityClaims{Corpora: denied}).AllowsCorpus("anything-at-all") {
		t.Fatal("a capability stamped with the deny-all sentinel must deny every corpus")
	}
	if got := clampCorpora([]string{"public"}); !equalStringSets(got, []string{"public"}) {
		t.Fatalf("clampCorpora must pass a non-empty intersection through unchanged, got %v", got)
	}

	// Integration: an org granted tools but NO corpora, hit with a tools-only
	// request, must mint a capability that reaches no corpus.
	f := newExchangeFixture(t, Grant{Org: "acme", Tools: []string{"read_file"}})
	subject := f.validAcmeSubjectToken(t, "user-1")
	details := rawAuthDetails(t, grantEntry([]string{"read_file"}, []string{"backend-a"}, nil))
	form := validExchangeForm(t, f, subject, details)

	resp := doExchange(t, f, f.dpopProof(t), nil, form)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 200, body=%s", resp.StatusCode, body)
	}
	var tr authorization.TokenExchangeResponse
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	claims := decodeCapabilityClaims(t, tr.AccessToken)
	if claims.AllowsCorpus("secret-corpus") {
		t.Fatalf("minted federation capability allows a corpus it was never granted (corpora=%v)", claims.Corpora)
	}
}
