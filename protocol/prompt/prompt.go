// Package prompt holds the prompt domain: prompt and argument descriptors,
// prompt messages, and the prompts/* request, result and notification types.
package prompt

import (
	"encoding/json"

	"github.com/xrey167/meshmcp/protocol/base"
	"github.com/xrey167/meshmcp/protocol/content"
)

// Method names in the prompt domain.
const (
	MethodList        = "prompts/list"
	MethodGet         = "prompts/get"
	MethodListChanged = "notifications/prompts/list_changed"
)

// Prompt is a prompt or prompt template that the server offers.
type Prompt struct {
	base.BaseMetadata
	// Description of what this prompt provides.
	Description string `json:"description,omitempty"`
	// Arguments used for templating the prompt.
	Arguments []Argument `json:"arguments,omitempty"`
	// Meta is the open `_meta` object.
	Meta base.Meta `json:"_meta,omitempty"`
}

// Argument describes an argument that a prompt can accept.
type Argument struct {
	base.BaseMetadata
	// Description is a human-readable description of the argument.
	Description string `json:"description,omitempty"`
	// Required reports whether this argument must be provided.
	Required bool `json:"required,omitempty"`
}

// Message is a message returned as part of a prompt. Like a sampling message,
// but it may also embed resources from the MCP server.
type Message struct {
	Role    base.Role     `json:"role"`
	Content content.Block `json:"content"`
}

// UnmarshalJSON decodes the polymorphic content block.
func (m *Message) UnmarshalJSON(data []byte) error {
	var raw struct {
		Role    base.Role       `json:"role"`
		Content json.RawMessage `json:"content"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	m.Role = raw.Role
	if raw.Content != nil {
		b, err := content.DecodeBlock(raw.Content)
		if err != nil {
			return err
		}
		m.Content = b
	}
	return nil
}

// ListRequest is sent from the client to request a list of prompts.
type ListRequest struct {
	Method string                `json:"method"` // MethodList
	Params *base.PaginatedParams `json:"params,omitempty"`
}

// ListResult is the server's response to a prompts/list request.
type ListResult struct {
	base.PaginatedResult
	Prompts []Prompt `json:"prompts"`
}

// GetRequest is used by the client to get a prompt provided by the server.
type GetRequest struct {
	Method string           `json:"method"` // MethodGet
	Params GetRequestParams `json:"params"`
}

// GetRequestParams are the params of a GetRequest.
type GetRequestParams struct {
	// Name of the prompt or prompt template.
	Name string `json:"name"`
	// Arguments to use for templating the prompt.
	Arguments map[string]string `json:"arguments,omitempty"`
}

// GetResult is the server's response to a prompts/get request.
type GetResult struct {
	base.Result
	// Description is an optional description for the prompt.
	Description string    `json:"description,omitempty"`
	Messages    []Message `json:"messages"`
}

// ListChangedNotification informs the client that the list of prompts changed.
type ListChangedNotification struct {
	Method string `json:"method"` // MethodListChanged
}
