package jsonrpc_test

import (
	"encoding/json"
	"testing"

	"meshmcp/protocol/jsonrpc"
	"meshmcp/protocol/tool"
)

func TestDecodeMessagePreservesResultBody(t *testing.T) {
	raw := []byte(`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"ok"}],"isError":false}}`)
	m, err := jsonrpc.DecodeMessage(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	resp, ok := m.(*jsonrpc.Response)
	if !ok {
		t.Fatalf("want *Response, got %T", m)
	}
	// The result body must survive as raw JSON (not collapsed to _meta only).
	if len(resp.Result) == 0 {
		t.Fatal("result body was dropped")
	}
	var cr tool.CallResult
	if err := json.Unmarshal(resp.Result, &cr); err != nil {
		t.Fatalf("decode result body: %v", err)
	}
	if len(cr.Content) != 1 {
		t.Fatalf("content lost: %+v", cr)
	}
}

func TestDecodeMessageDiscriminates(t *testing.T) {
	req, err := jsonrpc.DecodeMessage([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := req.(*jsonrpc.Request); !ok {
		t.Fatalf("want *Request, got %T", req)
	}

	note, err := jsonrpc.DecodeMessage([]byte(`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":"1"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := note.(*jsonrpc.Notification); !ok {
		t.Fatalf("want *Notification, got %T", note)
	}

	errFrame, err := jsonrpc.DecodeMessage([]byte(`{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"nope"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if e, ok := errFrame.(*jsonrpc.Error); !ok || e.Error.Code != -32601 {
		t.Fatalf("want *Error -32601, got %T", errFrame)
	}
}

func TestDecodeMessageGarbageIsError(t *testing.T) {
	// A frame that is neither request, notification, response nor error.
	if _, err := jsonrpc.DecodeMessage([]byte(`{"jsonrpc":"2.0","id":1}`)); err == nil {
		t.Fatal("expected error for a frame with no method/result/error")
	}
}
