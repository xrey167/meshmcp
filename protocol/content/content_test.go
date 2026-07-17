package content_test

import (
	"encoding/json"
	"testing"

	"meshmcp/protocol/content"
	"meshmcp/protocol/resource"
)

// TestDecodeBlockAllTypes exercises every content-block discriminator, including
// the previously untested audio, resource_link and embedded-resource branches.
func TestDecodeBlockAllTypes(t *testing.T) {
	audio, err := content.DecodeBlock([]byte(`{"type":"audio","data":"AAA","mimeType":"audio/wav"}`))
	if err != nil {
		t.Fatalf("audio: %v", err)
	}
	if a, ok := audio.(*content.AudioContent); !ok || a.MimeType != "audio/wav" {
		t.Fatalf("audio wrong: %#v", audio)
	}

	link, err := content.DecodeBlock([]byte(`{"type":"resource_link","uri":"file:///a","name":"a"}`))
	if err != nil {
		t.Fatalf("resource_link: %v", err)
	}
	if rl, ok := link.(*content.ResourceLink); !ok || rl.URI != "file:///a" {
		t.Fatalf("resource_link wrong: %#v", link)
	}

	// EmbeddedResource has its own UnmarshalJSON that decodes the text/blob union.
	emb, err := content.DecodeBlock([]byte(`{"type":"resource","resource":{"uri":"file:///a.txt","text":"hi"}}`))
	if err != nil {
		t.Fatalf("embedded: %v", err)
	}
	er, ok := emb.(*content.EmbeddedResource)
	if !ok {
		t.Fatalf("not EmbeddedResource: %#v", emb)
	}
	if _, ok := er.Resource.(*resource.TextResourceContents); !ok {
		t.Fatalf("embedded resource not text: %#v", er.Resource)
	}

	// Blob variant of the embedded resource.
	embBlob, _ := content.DecodeBlock([]byte(`{"type":"resource","resource":{"uri":"file:///a.bin","blob":"QUJD"}}`))
	if _, ok := embBlob.(*content.EmbeddedResource).Resource.(*resource.BlobResourceContents); !ok {
		t.Fatalf("embedded resource not blob")
	}
}

func TestDecodeBlockUnknownIsError(t *testing.T) {
	if _, err := content.DecodeBlock([]byte(`{"type":"bogus"}`)); err == nil {
		t.Fatal("expected error for unknown content block type")
	}
	if _, err := content.DecodeBlocks([]byte(`[{"type":"text","text":"ok"},{"type":"bogus"}]`)); err == nil {
		t.Fatal("expected error from DecodeBlocks on unknown type")
	}
}

// TestContentBlockMarshalRoundTrip verifies the union marshals back to a value
// carrying its discriminator, so decoded blocks re-serialize faithfully.
func TestContentBlockMarshalRoundTrip(t *testing.T) {
	for _, raw := range []string{
		`{"type":"text","text":"hi"}`,
		`{"type":"image","data":"AAA","mimeType":"image/png"}`,
		`{"type":"resource","resource":{"uri":"file:///a.txt","text":"hi"}}`,
	} {
		b, err := content.DecodeBlock([]byte(raw))
		if err != nil {
			t.Fatalf("decode %s: %v", raw, err)
		}
		out, err := json.Marshal(b)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		var probe struct {
			Type string `json:"type"`
		}
		_ = json.Unmarshal(out, &probe)
		if probe.Type == "" {
			t.Fatalf("marshalled block lost its type: %s", out)
		}
	}
}
