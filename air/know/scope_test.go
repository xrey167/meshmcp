package know

import (
	"testing"

	"github.com/xrey167/meshmcp/policy"
)

func claims(corpora ...string) policy.CapabilityClaims {
	return policy.CapabilityClaims{Corpora: corpora}
}

func TestAllowed(t *testing.T) {
	cases := []struct {
		name   string
		claims policy.CapabilityClaims
		op     KnowOp
		want   bool
	}{
		// Deny-by-default overrides AllowsCorpus's empty=allow-all convention.
		{"empty-grant-denies-read", claims(), KnowOp{Corpus: "acme"}, false},
		{"empty-grant-denies-write", claims(), KnowOp{Corpus: "acme", Write: true}, false},

		// Unnamed corpus is never allowed, even with a wildcard grant.
		{"blank-corpus-denied-read", claims("*"), KnowOp{Corpus: ""}, false},
		{"blank-corpus-denied-write", claims("*"), KnowOp{Corpus: "", Write: true}, false},

		// Reads: exact, wildcard, and glob all grant visibility.
		{"read-exact-match", claims("acme"), KnowOp{Corpus: "acme"}, true},
		{"read-wildcard", claims("*"), KnowOp{Corpus: "acme"}, true},
		{"read-glob-match", claims("acme/*"), KnowOp{Corpus: "acme/product"}, true},
		{"read-unknown-corpus-denied", claims("acme/*"), KnowOp{Corpus: "globex/secret"}, false},

		// Writes are strictly narrower: only an EXACT literal grant authorizes.
		{"write-exact-match", claims("acme"), KnowOp{Corpus: "acme", Write: true}, true},
		{"write-wildcard-denied", claims("*"), KnowOp{Corpus: "acme", Write: true}, false},
		{"write-glob-denied", claims("acme/*"), KnowOp{Corpus: "acme/product", Write: true}, false},
		{"write-exact-among-many", claims("globex/*", "acme/product"), KnowOp{Corpus: "acme/product", Write: true}, true},

		// The same broad grant reads a corpus it cannot write — the read/write split.
		{"broad-grant-reads", claims("acme/*"), KnowOp{Corpus: "acme/product"}, true},
		{"broad-grant-cannot-write", claims("acme/*"), KnowOp{Corpus: "acme/product", Write: true}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Allowed(c.claims, c.op); got != c.want {
				t.Fatalf("Allowed(%v, %+v) = %v, want %v", c.claims.Corpora, c.op, got, c.want)
			}
		})
	}
}
