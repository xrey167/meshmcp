// Package ping holds the ping request, issued by either party to check that
// the other is still alive (schema @category `ping`).
package ping

// Method is the JSON-RPC method name for a ping.
const Method = "ping"

// PingRequest is a ping issued by either the server or the client. The
// receiver must promptly respond, or else may be disconnected.
type PingRequest struct {
	Method string `json:"method"` // Method
}
