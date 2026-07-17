package resource_test

import (
	"testing"

	"meshmcp/protocol/resource"
)

func TestDecodeContents(t *testing.T) {
	text, err := resource.DecodeContents([]byte(`{"uri":"file:///a.txt","text":"hi"}`))
	if err != nil {
		t.Fatalf("text: %v", err)
	}
	if tc, ok := text.(*resource.TextResourceContents); !ok || tc.Text != "hi" {
		t.Fatalf("text wrong: %#v", text)
	}

	blob, err := resource.DecodeContents([]byte(`{"uri":"file:///a.bin","blob":"QUJD"}`))
	if err != nil {
		t.Fatalf("blob: %v", err)
	}
	if _, ok := blob.(*resource.BlobResourceContents); !ok {
		t.Fatalf("blob wrong: %#v", blob)
	}
}

func TestDecodeContentsNeitherIsError(t *testing.T) {
	if _, err := resource.DecodeContents([]byte(`{"uri":"file:///a"}`)); err == nil {
		t.Fatal("expected error when contents is neither text nor blob")
	}
}
