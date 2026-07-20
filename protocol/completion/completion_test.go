package completion_test

import (
	"encoding/json"
	"testing"

	"github.com/xrey167/meshmcp/protocol/completion"
)

// TestDecodeReferenceResource covers the ref/resource branch (previously only
// ref/prompt was tested).
func TestDecodeReferenceResource(t *testing.T) {
	ref, err := completion.DecodeReference([]byte(`{"type":"ref/resource","uri":"file:///{path}"}`))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	rr, ok := ref.(*completion.ResourceTemplateReference)
	if !ok || rr.URI != "file:///{path}" || rr.RefType() != completion.TypeResourceRef {
		t.Fatalf("ref/resource wrong: %#v", ref)
	}
}

func TestDecodeReferenceUnknownIsError(t *testing.T) {
	if _, err := completion.DecodeReference([]byte(`{"type":"ref/bogus"}`)); err == nil {
		t.Fatal("expected error for unknown reference type")
	}
}

// TestCompleteRequestParamsResourceRef exercises the params UnmarshalJSON with a
// resource reference.
func TestCompleteRequestParamsResourceRef(t *testing.T) {
	raw := `{"ref":{"type":"ref/resource","uri":"file:///{p}"},"argument":{"name":"p","value":"x"}}`
	var p completion.CompleteRequestParams
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := p.Ref.(*completion.ResourceTemplateReference); !ok {
		t.Fatalf("ref not ResourceTemplateReference: %#v", p.Ref)
	}
}
