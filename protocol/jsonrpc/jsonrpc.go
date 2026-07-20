// Package jsonrpc holds the JSON-RPC 2.0 envelope types that carry every MCP
// message on the wire (schema @category JSON-RPC).
package jsonrpc

import (
	"encoding/json"
	"errors"

	"github.com/xrey167/meshmcp/protocol/base"
)

// Version is the JSON-RPC version string used by every MCP message.
const Version = "2.0"

// Standard JSON-RPC error codes.
const (
	ParseError     = -32700
	InvalidRequest = -32600
	MethodNotFound = -32601
	InvalidParams  = -32602
	InternalError  = -32603
)

// Message is any valid JSON-RPC object decoded off the wire or encoded to be
// sent: a Request, Notification, Response or Error.
//
// Concrete implementers: *Request, *Notification, *Response, *Error.
type Message interface {
	isJSONRPCMessage()
}

// Request is a JSON-RPC request that expects a response.
type Request struct {
	base.Request
	JSONRPC string         `json:"jsonrpc"` // always Version
	ID      base.RequestId `json:"id"`
}

// Notification is a JSON-RPC notification that does not expect a response.
type Notification struct {
	base.Notification
	JSONRPC string `json:"jsonrpc"` // always Version
}

// Response is a successful (non-error) response to a request. Result is kept as
// raw JSON because the concrete result type depends on the originating request;
// decode it into the matching protocol type (e.g. tool.CallResult) using the
// request context.
type Response struct {
	JSONRPC string          `json:"jsonrpc"` // always Version
	ID      base.RequestId  `json:"id"`
	Result  json.RawMessage `json:"result"`
}

// Error is a response to a request that indicates an error occurred.
type Error struct {
	JSONRPC string         `json:"jsonrpc"` // always Version
	ID      base.RequestId `json:"id"`
	Error   ErrorObject    `json:"error"`
}

// ErrorObject carries the details of a JSON-RPC error.
type ErrorObject struct {
	// Code is the error type that occurred.
	Code int `json:"code"`
	// Message is a short, single-sentence description of the error.
	Message string `json:"message"`
	// Data is optional sender-defined additional information.
	Data any `json:"data,omitempty"`
}

func (*Request) isJSONRPCMessage()      {}
func (*Notification) isJSONRPCMessage() {}
func (*Response) isJSONRPCMessage()     {}
func (*Error) isJSONRPCMessage()        {}

// DecodeMessage discriminates a raw JSON-RPC frame into its concrete Message
// type based on the presence of the id, method, result and error fields.
func DecodeMessage(raw json.RawMessage) (Message, error) {
	var probe struct {
		ID     json.RawMessage `json:"id"`
		Method *string         `json:"method"`
		Result json.RawMessage `json:"result"`
		Error  json.RawMessage `json:"error"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return nil, err
	}
	switch {
	case probe.Error != nil:
		m := &Error{}
		return m, json.Unmarshal(raw, m)
	case probe.Result != nil:
		m := &Response{}
		return m, json.Unmarshal(raw, m)
	case probe.Method != nil && probe.ID != nil:
		m := &Request{}
		return m, json.Unmarshal(raw, m)
	case probe.Method != nil:
		m := &Notification{}
		return m, json.Unmarshal(raw, m)
	default:
		return nil, errors.New("jsonrpc: frame is not a request, notification, response or error")
	}
}
