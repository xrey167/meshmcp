package streamablehttp_test

import (
	"testing"

	sh "meshmcp/protocol/transport/streamablehttp"
)

func TestHeaderValueRoundTrip(t *testing.T) {
	cases := []struct {
		name    string
		value   string
		encoded bool // whether encoding is expected to wrap the value
	}{
		{"plain ascii", "us-west1", false},
		{"non-ascii", "Hello, 世界", true},
		{"leading/trailing space", " padded ", true},
		{"embedded newline", "line1\nline2", true},
		{"sentinel literal", "=?base64?literal?=", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			enc := sh.EncodeHeaderValue(c.value)
			if c.encoded && enc == c.value {
				t.Fatalf("expected %q to be encoded, got unchanged", c.value)
			}
			if !c.encoded && enc != c.value {
				t.Fatalf("expected %q unchanged, got %q", c.value, enc)
			}
			got, err := sh.DecodeHeaderValue(enc)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if got != c.value {
				t.Fatalf("round-trip mismatch: want %q, got %q", c.value, got)
			}
		})
	}
}

func TestParamHeaderName(t *testing.T) {
	if got := sh.ParamHeaderName("Region"); got != "Mcp-Param-Region" {
		t.Fatalf("ParamHeaderName = %q", got)
	}
}

func TestDecodeInvalidBase64(t *testing.T) {
	if _, err := sh.DecodeHeaderValue("=?base64?!!!not-base64!!!?="); err == nil {
		t.Fatal("expected error for invalid base64")
	}
}
