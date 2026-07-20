package policy

import (
	"bytes"
	"encoding/json"
)

// RPCKind is how a single JSON-RPC line classifies for policy purposes.
type RPCKind int

const (
	RPCEmpty        RPCKind = iota // blank line: ignore
	RPCBatch                       // top-level array: reject (cannot authorize per-entry)
	RPCInvalid                     // protocol-invalid: reject (Reason set)
	RPCToolCall                    // a tools/call to authorize (Tool, ID, Args set)
	RPCNotification                // client notification (Method set, no id)
	RPCMethod                      // other request (Method, ID set)
)

// RPCClass is the shared classification of a JSON-RPC line. ClassifyRPC is the
// single source of truth used by BOTH the stdio Filter and the Streamable-HTTP
// enforcer, so the two transports cannot drift on which requests are rejected,
// which are governed as tool calls, and which pass through.
type RPCClass struct {
	Kind   RPCKind
	Method string
	Tool   string
	ID     json.RawMessage
	Args   json.RawMessage
	Reason string // set for RPCInvalid / RPCBatch
}

// ClassifyRPC parses and validates one JSON-RPC line under enforcement. It
// mirrors the invariants both transports must uphold:
//   - a top-level batch is rejected (cannot be authorized per-entry);
//   - an unparseable line is rejected (no parser differential to the backend);
//   - a duplicate security-relevant key is rejected (canonical parsing);
//   - a security-sensitive method (tools/call) is classified BY NAME before by
//     id, so an id-less tools/call cannot slip into notification handling;
//   - a tools/call without a valid (non-null) id, or without a non-empty
//     params.name, is protocol-invalid.
func ClassifyRPC(line []byte) RPCClass {
	trimmed := bytes.TrimSpace(line)
	if len(trimmed) == 0 {
		return RPCClass{Kind: RPCEmpty}
	}
	if trimmed[0] == '[' {
		return RPCClass{Kind: RPCBatch, Reason: "JSON-RPC batches are not supported by the mesh policy filter"}
	}
	var msg rpcPeek
	if json.Unmarshal(trimmed, &msg) != nil {
		return RPCClass{Kind: RPCInvalid, Reason: "unparseable JSON-RPC line rejected by mesh policy"}
	}
	if err := checkNoDuplicateKeys(trimmed); err != nil {
		return RPCClass{Kind: RPCInvalid, Reason: "ambiguous JSON-RPC (duplicate key) rejected by mesh policy"}
	}
	// Dispatch security-sensitive methods by NAME before classifying by id.
	if msg.Method == "tools/call" {
		if !validRequestID(msg.ID) {
			return RPCClass{Kind: RPCInvalid, Method: msg.Method, Tool: msg.Params.Name,
				Reason: "tools/call rejected: missing or null JSON-RPC id (invalid MCP request)"}
		}
		if msg.Params.Name == "" {
			return RPCClass{Kind: RPCInvalid, Method: msg.Method, ID: msg.ID,
				Reason: "tools/call rejected: missing or empty params.name"}
		}
		return RPCClass{Kind: RPCToolCall, Method: msg.Method, Tool: msg.Params.Name, ID: msg.ID, Args: msg.Params.Arguments}
	}
	if len(msg.ID) == 0 {
		return RPCClass{Kind: RPCNotification, Method: msg.Method}
	}
	return RPCClass{Kind: RPCMethod, Method: msg.Method, ID: msg.ID}
}
