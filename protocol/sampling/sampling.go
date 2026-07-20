// Package sampling holds the sampling domain: the server's request to sample an
// LLM via the client, the result, and the model-preference descriptors
// (schema @category `sampling/createMessage`).
package sampling

import (
	"encoding/json"

	"github.com/xrey167/meshmcp/protocol/base"
	"github.com/xrey167/meshmcp/protocol/content"
)

// Method is the JSON-RPC method name for a sampling request.
const Method = "sampling/createMessage"

// IncludeContext selects which servers' context to attach to a sampling prompt.
type IncludeContext string

const (
	IncludeNone       IncludeContext = "none"
	IncludeThisServer IncludeContext = "thisServer"
	IncludeAllServers IncludeContext = "allServers"
)

// Message describes a message issued to or received from an LLM API. Its
// content is restricted to text, image or audio blocks.
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

// ModelHint is a hint to use for model selection.
type ModelHint struct {
	// Name is a hint for a model name, treated as a substring match.
	Name string `json:"name,omitempty"`
}

// ModelPreferences expresses the server's advisory priorities for model
// selection during sampling. The client MAY ignore them.
type ModelPreferences struct {
	// Hints are evaluated in order; the first match is taken.
	Hints []ModelHint `json:"hints,omitempty"`
	// CostPriority weights cost, from 0 (unimportant) to 1 (most important).
	CostPriority *float64 `json:"costPriority,omitempty"`
	// SpeedPriority weights latency, from 0 to 1.
	SpeedPriority *float64 `json:"speedPriority,omitempty"`
	// IntelligencePriority weights capability, from 0 to 1.
	IntelligencePriority *float64 `json:"intelligencePriority,omitempty"`
}

// CreateMessageRequest asks the client to sample an LLM. The client has full
// discretion over which model to select.
type CreateMessageRequest struct {
	Method string                     `json:"method"` // Method
	Params CreateMessageRequestParams `json:"params"`
}

// CreateMessageRequestParams are the params of a CreateMessageRequest.
type CreateMessageRequestParams struct {
	Messages []Message `json:"messages"`
	// ModelPreferences are the server's advisory model-selection preferences.
	ModelPreferences *ModelPreferences `json:"modelPreferences,omitempty"`
	// SystemPrompt is an optional system prompt the client MAY modify or omit.
	SystemPrompt string `json:"systemPrompt,omitempty"`
	// IncludeContext requests context from one or more MCP servers.
	IncludeContext IncludeContext `json:"includeContext,omitempty"`
	// Temperature for sampling.
	Temperature *float64 `json:"temperature,omitempty"`
	// MaxTokens is the requested maximum number of tokens to sample.
	MaxTokens int `json:"maxTokens"`
	// StopSequences halt sampling when matched.
	StopSequences []string `json:"stopSequences,omitempty"`
	// Metadata is provider-specific pass-through metadata.
	Metadata map[string]any `json:"metadata,omitempty"`
}

// CreateMessageResult is the client's response to a sampling/createMessage
// request. It is a sampled Message plus the model and stop reason.
type CreateMessageResult struct {
	base.Result
	Message
	// Model is the name of the model that generated the message.
	Model string `json:"model"`
	// StopReason is why sampling stopped, if known ("endTurn", "stopSequence",
	// "maxTokens", or a provider-specific string).
	StopReason string `json:"stopReason,omitempty"`
}

// UnmarshalJSON decodes the result, including the embedded polymorphic content.
func (r *CreateMessageResult) UnmarshalJSON(data []byte) error {
	var raw struct {
		Meta       base.Meta       `json:"_meta"`
		Role       base.Role       `json:"role"`
		Content    json.RawMessage `json:"content"`
		Model      string          `json:"model"`
		StopReason string          `json:"stopReason"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	r.Meta = raw.Meta
	r.Role = raw.Role
	r.Model = raw.Model
	r.StopReason = raw.StopReason
	if raw.Content != nil {
		b, err := content.DecodeBlock(raw.Content)
		if err != nil {
			return err
		}
		r.Content = b
	}
	return nil
}
