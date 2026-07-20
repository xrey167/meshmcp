package elicitation_test

import (
	"testing"

	"github.com/xrey167/meshmcp/protocol/elicitation"
)

func TestDecodePrimitiveSchemaUnknownIsError(t *testing.T) {
	if _, err := elicitation.DecodePrimitiveSchema([]byte(`{"type":"array"}`)); err == nil {
		t.Fatal("expected error for unknown primitive schema type in the 2025-06-18 model")
	}
}
