package messages

import (
	"encoding/json"
	"fmt"

	"meshmcp/protocol/cancellation"
	"meshmcp/protocol/completion"
	"meshmcp/protocol/elicitation"
	"meshmcp/protocol/initialize"
	"meshmcp/protocol/logging"
	"meshmcp/protocol/ping"
	"meshmcp/protocol/progress"
	"meshmcp/protocol/prompt"
	"meshmcp/protocol/resource"
	"meshmcp/protocol/roots"
	"meshmcp/protocol/sampling"
	"meshmcp/protocol/tool"
)

// methodOf reads the "method" discriminator from a raw request or notification
// frame.
func methodOf(raw json.RawMessage) (string, error) {
	var probe struct {
		Method string `json:"method"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return "", err
	}
	if probe.Method == "" {
		return "", fmt.Errorf("messages: frame has no method")
	}
	return probe.Method, nil
}

// decodeInto unmarshals raw into v and returns v as the union type on success.
func decodeInto[T any](raw json.RawMessage, v *T) (any, error) {
	if err := json.Unmarshal(raw, v); err != nil {
		return nil, err
	}
	return v, nil
}

// DecodeClientRequest decodes a raw request frame sent by a client into its
// concrete ClientRequest type, selected by the "method" field.
func DecodeClientRequest(raw json.RawMessage) (ClientRequest, error) {
	method, err := methodOf(raw)
	if err != nil {
		return nil, err
	}
	switch method {
	case ping.Method:
		return decodeInto(raw, &ping.PingRequest{})
	case initialize.MethodInitialize:
		return decodeInto(raw, &initialize.InitializeRequest{})
	case completion.Method:
		return decodeInto(raw, &completion.CompleteRequest{})
	case logging.MethodSetLevel:
		return decodeInto(raw, &logging.SetLevelRequest{})
	case prompt.MethodGet:
		return decodeInto(raw, &prompt.GetRequest{})
	case prompt.MethodList:
		return decodeInto(raw, &prompt.ListRequest{})
	case resource.MethodList:
		return decodeInto(raw, &resource.ListRequest{})
	case resource.MethodTemplatesList:
		return decodeInto(raw, &resource.ListTemplatesRequest{})
	case resource.MethodRead:
		return decodeInto(raw, &resource.ReadRequest{})
	case resource.MethodSubscribe:
		return decodeInto(raw, &resource.SubscribeRequest{})
	case resource.MethodUnsubscribe:
		return decodeInto(raw, &resource.UnsubscribeRequest{})
	case tool.MethodCall:
		return decodeInto(raw, &tool.CallRequest{})
	case tool.MethodList:
		return decodeInto(raw, &tool.ListRequest{})
	default:
		return nil, fmt.Errorf("messages: unknown client request method %q", method)
	}
}

// DecodeServerRequest decodes a raw request frame sent by a server into its
// concrete ServerRequest type, selected by the "method" field.
func DecodeServerRequest(raw json.RawMessage) (ServerRequest, error) {
	method, err := methodOf(raw)
	if err != nil {
		return nil, err
	}
	switch method {
	case ping.Method:
		return decodeInto(raw, &ping.PingRequest{})
	case sampling.Method:
		return decodeInto(raw, &sampling.CreateMessageRequest{})
	case roots.MethodList:
		return decodeInto(raw, &roots.ListRequest{})
	case elicitation.Method:
		return decodeInto(raw, &elicitation.ElicitRequest{})
	default:
		return nil, fmt.Errorf("messages: unknown server request method %q", method)
	}
}

// DecodeClientNotification decodes a raw notification frame sent by a client
// into its concrete ClientNotification type, selected by the "method" field.
func DecodeClientNotification(raw json.RawMessage) (ClientNotification, error) {
	method, err := methodOf(raw)
	if err != nil {
		return nil, err
	}
	switch method {
	case cancellation.Method:
		return decodeInto(raw, &cancellation.CancelledNotification{})
	case progress.Method:
		return decodeInto(raw, &progress.ProgressNotification{})
	case initialize.MethodInitialized:
		return decodeInto(raw, &initialize.InitializedNotification{})
	case roots.MethodListChanged:
		return decodeInto(raw, &roots.ListChangedNotification{})
	default:
		return nil, fmt.Errorf("messages: unknown client notification method %q", method)
	}
}

// DecodeServerNotification decodes a raw notification frame sent by a server
// into its concrete ServerNotification type, selected by the "method" field.
func DecodeServerNotification(raw json.RawMessage) (ServerNotification, error) {
	method, err := methodOf(raw)
	if err != nil {
		return nil, err
	}
	switch method {
	case cancellation.Method:
		return decodeInto(raw, &cancellation.CancelledNotification{})
	case progress.Method:
		return decodeInto(raw, &progress.ProgressNotification{})
	case logging.MethodMessage:
		return decodeInto(raw, &logging.MessageNotification{})
	case resource.MethodUpdated:
		return decodeInto(raw, &resource.UpdatedNotification{})
	case resource.MethodListChanged:
		return decodeInto(raw, &resource.ListChangedNotification{})
	case tool.MethodListChanged:
		return decodeInto(raw, &tool.ListChangedNotification{})
	case prompt.MethodListChanged:
		return decodeInto(raw, &prompt.ListChangedNotification{})
	default:
		return nil, fmt.Errorf("messages: unknown server notification method %q", method)
	}
}
