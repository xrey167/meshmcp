// Package samplingtools models the draft sampling tool-use extension: sampling
// messages whose content is an array of blocks that may include tool_use and
// tool_result, plus the request's tools / toolChoice and the tool-use stop
// reason.
//
// Reflects the DRAFT revision (SEP-2577). The 2025-06-18 sampling model in
// protocol/sampling only supports a single text/image/audio content block per
// message and has no tool-use notion; this package handles the wider draft
// shape. Text/image/audio blocks reuse the protocol/content types.
package samplingtools

import (
	"encoding/json"
	"fmt"

	"github.com/xrey167/meshmcp/protocol/base"
	"github.com/xrey167/meshmcp/protocol/content"
	"github.com/xrey167/meshmcp/protocol/sampling"
	"github.com/xrey167/meshmcp/protocol/tool"
)

// Method is the JSON-RPC method name for a sampling request.
const Method = "sampling/createMessage"

// Sampling stop reasons. The field is an open string; these are the standard
// values.
const (
	StopEndTurn      = "endTurn"
	StopStopSequence = "stopSequence"
	StopMaxTokens    = "maxTokens"
	StopToolUse      = "toolUse"
)

// Content-block discriminator values added by the tool-use extension.
const (
	TypeToolUse    = "tool_use"
	TypeToolResult = "tool_result"
)

// ToolChoiceMode controls the model's tool-use behavior.
type ToolChoiceMode string

const (
	ToolChoiceAuto     ToolChoiceMode = "auto"
	ToolChoiceRequired ToolChoiceMode = "required"
	ToolChoiceNone     ToolChoiceMode = "none"
)

// ToolChoice controls tool selection behavior for a sampling request.
type ToolChoice struct {
	Mode ToolChoiceMode `json:"mode,omitempty"`
}

// ToolUseContent is a request from the assistant to call a tool.
type ToolUseContent struct {
	Type string `json:"type"` // "tool_use"
	// ID uniquely identifies this tool use, matched by a ToolResultContent.
	ID string `json:"id"`
	// Name of the tool to call.
	Name string `json:"name"`
	// Input are the arguments to pass, conforming to the tool's input schema.
	Input map[string]any `json:"input"`
	// Meta is the open `_meta` object.
	Meta base.Meta `json:"_meta,omitempty"`
}

// ToolResultContent is the result of a tool use, provided back to the assistant.
type ToolResultContent struct {
	Type string `json:"type"` // "tool_result"
	// ToolUseID matches the ID of a previous ToolUseContent.
	ToolUseID string `json:"toolUseId"`
	// Content is the unstructured result (same shape as a tool call's content).
	Content []content.Block `json:"content"`
	// StructuredContent is an optional structured result (any JSON).
	StructuredContent json.RawMessage `json:"structuredContent,omitempty"`
	// IsError reports whether the tool use resulted in an error.
	IsError bool `json:"isError,omitempty"`
	// Meta is the open `_meta` object.
	Meta base.Meta `json:"_meta,omitempty"`
}

// UnmarshalJSON decodes the polymorphic content block slice.
func (r *ToolResultContent) UnmarshalJSON(data []byte) error {
	var raw struct {
		Type              string            `json:"type"`
		ToolUseID         string            `json:"toolUseId"`
		Content           []json.RawMessage `json:"content"`
		StructuredContent json.RawMessage   `json:"structuredContent"`
		IsError           bool              `json:"isError"`
		Meta              base.Meta         `json:"_meta"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	r.Type = raw.Type
	r.ToolUseID = raw.ToolUseID
	r.StructuredContent = raw.StructuredContent
	r.IsError = raw.IsError
	r.Meta = raw.Meta
	r.Content = make([]content.Block, 0, len(raw.Content))
	for _, item := range raw.Content {
		b, err := content.DecodeBlock(item)
		if err != nil {
			return err
		}
		r.Content = append(r.Content, b)
	}
	return nil
}

// DecodeBlock decodes a single sampling content block into its concrete type:
// *content.TextContent / *content.ImageContent / *content.AudioContent for the
// shared content types, or *ToolUseContent / *ToolResultContent for the
// tool-use additions.
func DecodeBlock(raw json.RawMessage) (any, error) {
	var probe struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return nil, err
	}
	switch probe.Type {
	case TypeToolUse:
		b := &ToolUseContent{}
		return b, json.Unmarshal(raw, b)
	case TypeToolResult:
		b := &ToolResultContent{}
		return b, json.Unmarshal(raw, b)
	case content.TypeText, content.TypeImage, content.TypeAudio,
		content.TypeResourceLink, content.TypeResource:
		return content.DecodeBlock(raw)
	default:
		return nil, fmt.Errorf("samplingtools: unknown content block type %q", probe.Type)
	}
}

// decodeContent decodes a message's content, which may be a single block or an
// array of blocks, into a slice.
func decodeContent(raw json.RawMessage) ([]any, error) {
	trimmed := trimSpace(raw)
	if len(trimmed) > 0 && trimmed[0] == '[' {
		var items []json.RawMessage
		if err := json.Unmarshal(raw, &items); err != nil {
			return nil, err
		}
		blocks := make([]any, 0, len(items))
		for _, item := range items {
			b, err := DecodeBlock(item)
			if err != nil {
				return nil, err
			}
			blocks = append(blocks, b)
		}
		return blocks, nil
	}
	b, err := DecodeBlock(raw)
	if err != nil {
		return nil, err
	}
	return []any{b}, nil
}

func trimSpace(b []byte) []byte {
	i := 0
	for i < len(b) && (b[i] == ' ' || b[i] == '\t' || b[i] == '\n' || b[i] == '\r') {
		i++
	}
	return b[i:]
}

// Message is a sampling message. Its content is normalized to a slice of
// concrete blocks regardless of whether the wire value was a single block or an
// array.
type Message struct {
	Role    base.Role `json:"role"`
	Content []any     `json:"content"`
	Meta    base.Meta `json:"_meta,omitempty"`
}

// UnmarshalJSON decodes the role, the single-or-array polymorphic content, and _meta.
func (m *Message) UnmarshalJSON(data []byte) error {
	var raw struct {
		Role    base.Role       `json:"role"`
		Content json.RawMessage `json:"content"`
		Meta    base.Meta       `json:"_meta"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	m.Role = raw.Role
	m.Meta = raw.Meta
	if raw.Content != nil {
		blocks, err := decodeContent(raw.Content)
		if err != nil {
			return err
		}
		m.Content = blocks
	}
	return nil
}

// CreateMessageRequestParams are the params of a draft sampling/createMessage
// request, extended with tools and toolChoice.
type CreateMessageRequestParams struct {
	Messages []Message `json:"messages"`
	// ModelPreferences are the server's advisory model-selection preferences.
	ModelPreferences *sampling.ModelPreferences `json:"modelPreferences,omitempty"`
	// SystemPrompt is an optional system prompt.
	SystemPrompt string `json:"systemPrompt,omitempty"`
	// IncludeContext requests context from one or more MCP servers.
	IncludeContext string `json:"includeContext,omitempty"`
	// Temperature for sampling.
	Temperature *float64 `json:"temperature,omitempty"`
	// MaxTokens is the requested maximum number of tokens to sample.
	MaxTokens int `json:"maxTokens"`
	// StopSequences halt sampling when matched.
	StopSequences []string `json:"stopSequences,omitempty"`
	// Metadata is provider-specific pass-through metadata.
	Metadata map[string]any `json:"metadata,omitempty"`
	// Tools are the tools the model may call during sampling.
	Tools []tool.Tool `json:"tools,omitempty"`
	// ToolChoice controls the model's tool-use behavior.
	ToolChoice *ToolChoice `json:"toolChoice,omitempty"`
}

// CreateMessageRequest asks the client to sample an LLM, with optional tool use.
type CreateMessageRequest struct {
	Method string                     `json:"method"` // Method
	Params CreateMessageRequestParams `json:"params"`
}

// CreateMessageResult is the client's response: a sampled message plus the
// model and stop reason. When StopReason is "toolUse", the content carries one
// or more ToolUseContent blocks.
type CreateMessageResult struct {
	Message
	// Model is the name of the model that generated the message.
	Model string `json:"model"`
	// StopReason is why sampling stopped (endTurn, stopSequence, maxTokens,
	// toolUse, or a provider-specific value).
	StopReason string `json:"stopReason,omitempty"`
}

// UnmarshalJSON decodes the result including the polymorphic content.
func (r *CreateMessageResult) UnmarshalJSON(data []byte) error {
	if err := r.Message.UnmarshalJSON(data); err != nil {
		return err
	}
	var rest struct {
		Model      string `json:"model"`
		StopReason string `json:"stopReason"`
	}
	if err := json.Unmarshal(data, &rest); err != nil {
		return err
	}
	r.Model = rest.Model
	r.StopReason = rest.StopReason
	return nil
}
