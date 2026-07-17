// Package mrtr models the Multi Round-Trip Requests pattern, introduced in the
// DRAFT MCP revision. It replaces server-initiated requests: instead of the
// server sending its own JSON-RPC request (roots/list, sampling/createMessage,
// elicitation/create), it returns an InputRequiredResult, and the client
// retries the original request carrying the matching input responses.
//
// This is a draft-era pattern and is NOT part of the 2025-06-18 schema.ts the
// protocol/* base models are generated from.
package mrtr

import "meshmcp/protocol/base"

// Result-type discriminators carried on a draft Result via its "resultType"
// field.
const (
	// ResultTypeInputRequired marks an InputRequiredResult.
	ResultTypeInputRequired = "input_required"
	// ResultTypeComplete marks a normal, completed result.
	ResultTypeComplete = "complete"
)

// InputRequests is a map of server-initiated requests the client must fulfill.
// Keys are server-assigned identifiers, unique within the originating request.
// Values are request objects: one of elicitation.ElicitRequest,
// sampling.CreateMessageRequest, or roots.ListRequest.
type InputRequests = map[string]any

// InputResponses is a map of client responses to the server's InputRequests.
// Keys correspond to the InputRequests keys. Values are result objects: one of
// elicitation.ElicitResult, sampling.CreateMessageResult, or roots.ListResult.
type InputResponses = map[string]any

// InputRequiredResult is a Result indicating that additional input is needed
// before the originating request can be completed. Servers MAY return it only
// for prompts/get, resources/read and tools/call, and MUST include at least one
// of InputRequests or RequestState.
type InputRequiredResult struct {
	base.Result
	// ResultType is always ResultTypeInputRequired.
	ResultType string `json:"resultType"`
	// InputRequests are the server-initiated requests the client must fulfill.
	InputRequests InputRequests `json:"inputRequests,omitempty"`
	// RequestState is an opaque, server-owned string the client MUST echo back
	// verbatim on retry and MUST NOT inspect or modify. Servers MUST treat it as
	// attacker-controlled input and integrity-protect it (e.g. HMAC/AEAD).
	RequestState string `json:"requestState,omitempty"`
}
