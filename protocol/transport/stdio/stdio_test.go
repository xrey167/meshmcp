package stdio_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/xrey167/meshmcp/protocol/transport/stdio"
)

func TestFrame(t *testing.T) {
	out, err := stdio.Frame([]byte(`{"jsonrpc":"2.0"}`))
	if err != nil {
		t.Fatalf("frame: %v", err)
	}
	if !bytes.HasSuffix(out, []byte{'\n'}) {
		t.Fatalf("framed message not newline-terminated: %q", out)
	}
	if bytes.Count(out, []byte{'\n'}) != 1 {
		t.Fatalf("want exactly one newline, got %q", out)
	}
}

func TestFrameRejectsEmbeddedNewline(t *testing.T) {
	_, err := stdio.Frame([]byte("a\nb"))
	if !errors.Is(err, stdio.ErrEmbeddedNewline) {
		t.Fatalf("want ErrEmbeddedNewline, got %v", err)
	}
}
