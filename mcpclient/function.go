package mcpclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// ToolContent is a content block of a tool result.
type ToolContent struct {
	Type string `json:"type"`
	Text string `json:"text,omitempty"`
}

// ToolCallResult is a decoded MCP tool result. IsError is the MCP-level
// "the tool ran but reported a failure" flag — distinct from a transport or
// JSON-RPC error (which is returned as a Go error).
type ToolCallResult struct {
	Content    []ToolContent   `json:"content"`
	IsError    bool            `json:"isError,omitempty"`
	Structured json.RawMessage `json:"structuredContent,omitempty"`
	Raw        json.RawMessage `json:"-"`
}

// Text joins the text content blocks.
func (r ToolCallResult) Text() string {
	parts := make([]string, 0, len(r.Content))
	for _, c := range r.Content {
		if c.Type == "text" {
			parts = append(parts, c.Text)
		}
	}
	return strings.Join(parts, "\n")
}

// ToolExecutionError means the MCP round-trip succeeded but the tool itself
// reported isError:true. Callers use errors.As to tell this apart from a
// transport/JSON-RPC failure.
type ToolExecutionError struct {
	Tool   string
	Result ToolCallResult
}

func (e *ToolExecutionError) Error() string {
	return fmt.Sprintf("tool %q reported an error: %s", e.Tool, e.Result.Text())
}

// Function is a provider-neutral view of an MCP tool for model function calling.
type Function struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	Parameters  json.RawMessage `json:"parameters,omitempty"` // the tool's input JSON Schema
}

// ModelFunctionCall is a model-emitted function call. Arguments is a JSON string
// that must decode to exactly one JSON object.
type ModelFunctionCall struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

// ListFunctions returns each tool as a provider-neutral function definition.
func (c *Client) ListFunctions(ctx context.Context) ([]Function, error) {
	tools, err := c.ListTools(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]Function, len(tools))
	for i, t := range tools {
		out[i] = Function{Name: t.Name, Description: t.Description, Parameters: t.InputSchema}
	}
	return out, nil
}

// InvokeTool calls a tool and decodes the result. A transport/JSON-RPC failure
// is returned as a plain error; a tool that reports isError:true is returned as
// a *ToolExecutionError (with the decoded result also returned).
func (c *Client) InvokeTool(ctx context.Context, name string, args any) (ToolCallResult, error) {
	raw, err := c.CallTool(ctx, name, args, false)
	if err != nil {
		return ToolCallResult{}, err
	}
	res := decodeToolResult(raw)
	if res.IsError {
		return res, &ToolExecutionError{Tool: name, Result: res}
	}
	return res, nil
}

// InvokeFunction validates a model function call (arguments must be exactly one
// JSON object) and invokes it.
func (c *Client) InvokeFunction(ctx context.Context, call ModelFunctionCall) (ToolCallResult, error) {
	if err := validateArgumentsObject(call.Arguments); err != nil {
		return ToolCallResult{}, fmt.Errorf("function %q arguments: %w", call.Name, err)
	}
	return c.InvokeTool(ctx, call.Name, json.RawMessage(call.Arguments))
}

// validateArgumentsObject requires exactly one JSON object — rejecting arrays,
// null, scalars, and trailing data before any tool runs.
func validateArgumentsObject(s string) error {
	trimmed := strings.TrimSpace(s)
	if trimmed == "" {
		return fmt.Errorf("arguments are required")
	}
	if trimmed[0] != '{' {
		return fmt.Errorf("arguments must be a single JSON object")
	}
	dec := json.NewDecoder(bytes.NewReader([]byte(trimmed)))
	var obj map[string]json.RawMessage
	if err := dec.Decode(&obj); err != nil {
		return fmt.Errorf("arguments must be a single JSON object: %w", err)
	}
	if dec.More() {
		return fmt.Errorf("unexpected trailing data after the JSON object")
	}
	return nil
}

func decodeToolResult(raw json.RawMessage) ToolCallResult {
	var r ToolCallResult
	_ = json.Unmarshal(raw, &r)
	r.Raw = raw
	return r
}
