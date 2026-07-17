package transport

// ClientInfo is the client Implementation descriptor carried in request
// metadata under MetaKeyClientInfo.
type ClientInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// RequestMeta is the typed view of the well-known request `_meta` fields every
// request carries in the draft revision (the io.modelcontextprotocol/* keys).
// It is a decode/encode helper for a request params' `_meta` object; unknown
// keys are ignored.
type RequestMeta struct {
	// ProtocolVersion is the request's protocol version
	// (io.modelcontextprotocol/protocolVersion).
	ProtocolVersion string `json:"io.modelcontextprotocol/protocolVersion,omitempty"`
	// ClientInfo is the client identity (io.modelcontextprotocol/clientInfo).
	ClientInfo *ClientInfo `json:"io.modelcontextprotocol/clientInfo,omitempty"`
	// ClientCapabilities are the per-request client capabilities
	// (io.modelcontextprotocol/clientCapabilities).
	ClientCapabilities map[string]any `json:"io.modelcontextprotocol/clientCapabilities,omitempty"`
}
