package messages_test

import (
	"testing"

	"meshmcp/protocol/messages"
	"meshmcp/protocol/resource"
	"meshmcp/protocol/tool"
)

func TestDecodeClientRequest(t *testing.T) {
	raw := []byte(`{"method":"resources/read","params":{"uri":"file:///a.txt"}}`)
	req, err := messages.DecodeClientRequest(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	rr, ok := req.(*resource.ReadRequest)
	if !ok {
		t.Fatalf("want *resource.ReadRequest, got %T", req)
	}
	if rr.Params.URI != "file:///a.txt" {
		t.Fatalf("uri = %q", rr.Params.URI)
	}
}

func TestDecodeServerNotification(t *testing.T) {
	raw := []byte(`{"method":"notifications/tools/list_changed"}`)
	n, err := messages.DecodeServerNotification(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, ok := n.(*tool.ListChangedNotification); !ok {
		t.Fatalf("want *tool.ListChangedNotification, got %T", n)
	}
}

func TestDecodeUnknownMethod(t *testing.T) {
	if _, err := messages.DecodeClientRequest([]byte(`{"method":"bogus/method"}`)); err == nil {
		t.Fatal("expected error for unknown method")
	}
}
