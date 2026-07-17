// Package elicitation holds the elicitation domain: the server's request to
// elicit information from the user, the restricted primitive schemas it may
// ask for, and the client's response (schema @category `elicitation/create`).
package elicitation

import (
	"encoding/json"
	"fmt"

	"meshmcp/protocol/base"
)

// Method is the JSON-RPC method name for an elicitation request.
const Method = "elicitation/create"

// PrimitiveSchema is the restricted union of schema definitions allowed in an
// elicitation request: string, number, boolean or enum. No nested objects or
// arrays are permitted.
type PrimitiveSchema interface {
	isPrimitiveSchema()
	// SchemaType returns the JSON "type" discriminator of this schema.
	SchemaType() string
}

// StringSchema constrains a string-valued property.
type StringSchema struct {
	Type        string `json:"type"` // "string"
	Title       string `json:"title,omitempty"`
	Description string `json:"description,omitempty"`
	MinLength   *int   `json:"minLength,omitempty"`
	MaxLength   *int   `json:"maxLength,omitempty"`
	// Format is one of "email", "uri", "date", "date-time".
	Format string `json:"format,omitempty"`
}

// NumberSchema constrains a number- or integer-valued property.
type NumberSchema struct {
	Type        string   `json:"type"` // "number" or "integer"
	Title       string   `json:"title,omitempty"`
	Description string   `json:"description,omitempty"`
	Minimum     *float64 `json:"minimum,omitempty"`
	Maximum     *float64 `json:"maximum,omitempty"`
}

// BooleanSchema constrains a boolean-valued property.
type BooleanSchema struct {
	Type        string `json:"type"` // "boolean"
	Title       string `json:"title,omitempty"`
	Description string `json:"description,omitempty"`
	Default     *bool  `json:"default,omitempty"`
}

// EnumSchema constrains a string property to a fixed set of values.
type EnumSchema struct {
	Type        string   `json:"type"` // "string"
	Title       string   `json:"title,omitempty"`
	Description string   `json:"description,omitempty"`
	Enum        []string `json:"enum"`
	// EnumNames are optional display names for the enum values.
	EnumNames []string `json:"enumNames,omitempty"`
}

func (*StringSchema) isPrimitiveSchema()  {}
func (*NumberSchema) isPrimitiveSchema()  {}
func (*BooleanSchema) isPrimitiveSchema() {}
func (*EnumSchema) isPrimitiveSchema()    {}

func (*StringSchema) SchemaType() string  { return "string" }
func (*NumberSchema) SchemaType() string  { return "number" }
func (*BooleanSchema) SchemaType() string { return "boolean" }
func (*EnumSchema) SchemaType() string    { return "string" }

// DecodePrimitiveSchema discriminates a raw primitive schema. A "string" type
// carrying an "enum" field decodes to an EnumSchema, otherwise a StringSchema.
func DecodePrimitiveSchema(raw json.RawMessage) (PrimitiveSchema, error) {
	var probe struct {
		Type string          `json:"type"`
		Enum json.RawMessage `json:"enum"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return nil, err
	}
	var schema PrimitiveSchema
	switch probe.Type {
	case "boolean":
		schema = &BooleanSchema{}
	case "number", "integer":
		schema = &NumberSchema{}
	case "string":
		if probe.Enum != nil {
			schema = &EnumSchema{}
		} else {
			schema = &StringSchema{}
		}
	default:
		return nil, fmt.Errorf("elicitation: unknown primitive schema type %q", probe.Type)
	}
	if err := json.Unmarshal(raw, schema); err != nil {
		return nil, err
	}
	return schema, nil
}

// RequestedSchema is the restricted JSON Schema object the server asks the user
// to fill in. Only top-level primitive properties are allowed.
type RequestedSchema struct {
	Type       string                     `json:"type"` // always "object"
	Properties map[string]PrimitiveSchema `json:"properties"`
	Required   []string                   `json:"required,omitempty"`
}

// UnmarshalJSON decodes the polymorphic property schemas.
func (s *RequestedSchema) UnmarshalJSON(data []byte) error {
	var raw struct {
		Type       string                     `json:"type"`
		Properties map[string]json.RawMessage `json:"properties"`
		Required   []string                   `json:"required"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	s.Type = raw.Type
	s.Required = raw.Required
	s.Properties = make(map[string]PrimitiveSchema, len(raw.Properties))
	for key, item := range raw.Properties {
		schema, err := DecodePrimitiveSchema(item)
		if err != nil {
			return err
		}
		s.Properties[key] = schema
	}
	return nil
}

// ElicitRequest asks the client to elicit additional information from the user.
type ElicitRequest struct {
	Method string              `json:"method"` // Method
	Params ElicitRequestParams `json:"params"`
}

// ElicitRequestParams are the params of an ElicitRequest.
type ElicitRequestParams struct {
	// Message to present to the user.
	Message string `json:"message"`
	// RequestedSchema is the restricted schema of the requested form.
	RequestedSchema RequestedSchema `json:"requestedSchema"`
}

// Action is the user's action in response to an elicitation.
type Action string

const (
	ActionAccept  Action = "accept"
	ActionDecline Action = "decline"
	ActionCancel  Action = "cancel"
)

// ElicitResult is the client's response to an elicitation request.
type ElicitResult struct {
	base.Result
	// Action is the user action: accept, decline or cancel.
	Action Action `json:"action"`
	// Content is the submitted form data, present only when Action is accept.
	Content map[string]any `json:"content,omitempty"`
}
