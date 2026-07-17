// Package protocol is the umbrella for the Model Context Protocol data models,
// generated from the official TypeScript schema (schema.ts, revision
// 2025-06-18).
//
// The models are split one package per protocol domain:
//
//	base          shared envelopes, pagination, scalars, metadata
//	jsonrpc       JSON-RPC 2.0 request/notification/response/error frames
//	initialize    connection handshake and client/server capabilities
//	ping          liveness ping
//	progress      progress notifications
//	cancellation  request cancellation
//	resource      resources, templates, contents, resources/* messages
//	content       content-block union (text/image/audio/link/embedded)
//	prompt        prompts, arguments, messages, prompts/* messages
//	tool          tools, annotations, tools/* messages
//	logging       log level and message notifications
//	sampling      LLM sampling request/result and model preferences
//	completion    argument autocompletion
//	roots         filesystem roots
//	elicitation   user-input elicitation and its restricted schemas
//	messages      top-level client/server message unions (documented aliases)
//
// TypeScript union types are represented in Go as marker interfaces plus a
// Decode* helper that discriminates the concrete type from the JSON payload
// (e.g. content.DecodeBlock, resource.DecodeContents). Containers holding a
// union implement json.Unmarshaler so they round-trip transparently.
package protocol
