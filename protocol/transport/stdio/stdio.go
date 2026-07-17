// Package stdio models the stdio transport binding: newline-delimited JSON-RPC
// messages over the standard streams of a client-launched subprocess.
//
// The client writes requests and notifications to the server's stdin and reads
// responses and notifications from its stdout, one message per line. The wire
// format (one newline-delimited JSON-RPC message per line over a reliable
// bidirectional byte stream) is reusable over Unix domain sockets or TCP; only
// the process-lifecycle rules are specific to standard streams.
//
// Reflects the DRAFT transports revision.
package stdio

import (
	"bytes"
	"errors"
)

// Delimiter separates messages on the wire. Each message is a single JSON-RPC
// object and MUST NOT contain an embedded newline.
const Delimiter = '\n'

// ErrEmbeddedNewline is returned when a message contains a newline, which the
// framing forbids.
var ErrEmbeddedNewline = errors.New("stdio: message contains an embedded newline")

// Frame appends the newline delimiter to a single serialized JSON-RPC message,
// producing one wire line. It rejects messages that already contain a newline,
// since embedded newlines would corrupt the framing.
func Frame(message []byte) ([]byte, error) {
	if bytes.ContainsRune(message, Delimiter) {
		return nil, ErrEmbeddedNewline
	}
	out := make([]byte, 0, len(message)+1)
	out = append(out, message...)
	out = append(out, Delimiter)
	return out, nil
}
