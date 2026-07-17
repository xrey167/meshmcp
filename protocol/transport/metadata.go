package transport

// ClientInfo is the client Implementation descriptor carried in request
// metadata under MetaKeyClientInfo.
type ClientInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// RequestMeta is the typed view of the well-known request `_meta` fields a
// request carries in the draft revision. It is a decode/encode helper for a
// request params' `_meta` object; unknown keys are ignored.
type RequestMeta struct {
	// ProgressToken, if set, requests out-of-band progress notifications for the
	// request. It is a bare `progressToken` key (string or number).
	ProgressToken any `json:"progressToken,omitempty"`
	// ProtocolVersion is the request's protocol version
	// (io.modelcontextprotocol/protocolVersion).
	ProtocolVersion string `json:"io.modelcontextprotocol/protocolVersion,omitempty"`
	// ClientInfo is the client identity (io.modelcontextprotocol/clientInfo).
	ClientInfo *ClientInfo `json:"io.modelcontextprotocol/clientInfo,omitempty"`
	// ClientCapabilities are the per-request client capabilities
	// (io.modelcontextprotocol/clientCapabilities).
	ClientCapabilities map[string]any `json:"io.modelcontextprotocol/clientCapabilities,omitempty"`
	// LogLevel is the desired log level for this request
	// (io.modelcontextprotocol/logLevel).
	//
	// Deprecated: deprecated as of protocol version 2026-07-28 (SEP-2577);
	// replaces the former logging/setLevel RPC.
	LogLevel string `json:"io.modelcontextprotocol/logLevel,omitempty"`
}

// ResultMeta is the typed view of the well-known result `_meta` fields
// (io.modelcontextprotocol/serverInfo). Unknown keys are ignored.
type ResultMeta struct {
	// ServerInfo identifies the server software producing the response.
	ServerInfo *ClientInfo `json:"io.modelcontextprotocol/serverInfo,omitempty"`
}

// NotificationMeta is the typed view of the well-known notification `_meta`
// fields (io.modelcontextprotocol/subscriptionId). Unknown keys are ignored.
type NotificationMeta struct {
	// SubscriptionID correlates a notification with the subscriptions/listen
	// request that opened its stream (a JSON-RPC id: string or number). Absent
	// on notifications not delivered via a subscription stream.
	SubscriptionID any `json:"io.modelcontextprotocol/subscriptionId,omitempty"`
}
