// Package messages documents the top-level client/server message unions from
// schema.ts (ClientRequest, ClientNotification, ClientResult, ServerRequest,
// ServerNotification, ServerResult).
//
// Go cannot express a closed union over types that live in other packages
// (a marker method must be declared in the type's own package), so these are
// modelled as `any` aliases whose membership is documented here. The concrete
// members live in their respective protocol/* packages.
//
// To decode an incoming frame into the right concrete type, use the method
// dispatchers in decode.go: DecodeClientRequest, DecodeServerRequest,
// DecodeClientNotification and DecodeServerNotification.
//
// Scope: the dispatchers cover the 2025-06-18 method set. Draft-only methods
// (server/discover, subscriptions/listen, tasks/*, elicitation url mode) are
// modelled in their own packages — route them via those packages' Method
// constants (e.g. discover.Method, subscriptions.MethodListen, tasks.MethodGet)
// rather than through these dispatchers.
package messages

// ClientRequest is any request a client may send to a server. Members:
//   - ping.PingRequest
//   - initialize.InitializeRequest
//   - completion.CompleteRequest
//   - logging.SetLevelRequest
//   - prompt.GetRequest
//   - prompt.ListRequest
//   - resource.ListRequest
//   - resource.ListTemplatesRequest
//   - resource.ReadRequest
//   - resource.SubscribeRequest
//   - resource.UnsubscribeRequest
//   - tool.CallRequest
//   - tool.ListRequest
type ClientRequest = any

// ClientNotification is any notification a client may send. Members:
//   - cancellation.CancelledNotification
//   - progress.ProgressNotification
//   - initialize.InitializedNotification
//   - roots.ListChangedNotification
type ClientNotification = any

// ClientResult is any result a client may return. Members:
//   - base.EmptyResult
//   - sampling.CreateMessageResult
//   - roots.ListResult
//   - elicitation.ElicitResult
type ClientResult = any

// ServerRequest is any request a server may send to a client. Members:
//   - ping.PingRequest
//   - sampling.CreateMessageRequest
//   - roots.ListRequest
//   - elicitation.ElicitRequest
type ServerRequest = any

// ServerNotification is any notification a server may send. Members:
//   - cancellation.CancelledNotification
//   - progress.ProgressNotification
//   - logging.MessageNotification
//   - resource.UpdatedNotification
//   - resource.ListChangedNotification
//   - tool.ListChangedNotification
//   - prompt.ListChangedNotification
type ServerNotification = any

// ServerResult is any result a server may return. Members:
//   - base.EmptyResult
//   - initialize.InitializeResult
//   - completion.CompleteResult
//   - prompt.GetResult
//   - prompt.ListResult
//   - resource.ListTemplatesResult
//   - resource.ListResult
//   - resource.ReadResult
//   - tool.CallResult
//   - tool.ListResult
type ServerResult = any
