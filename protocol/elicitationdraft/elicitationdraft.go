// Package elicitationdraft models the DRAFT redesign of elicitation/create:
// two request modes (form and out-of-band url) and the expanded restricted
// schema set, including single- and multi-select enum variants.
//
// Reflects the DRAFT revision. The 2025-06-18 elicitation model in
// protocol/elicitation only has form-mode requests and string/number/boolean/
// enum schemas; this package handles the wider draft shape and lives in its
// own package to keep the eras separate.
package elicitationdraft

import (
	"encoding/json"
	"fmt"
)

// Method is the JSON-RPC method name for an elicitation request.
const Method = "elicitation/create"

// Elicitation modes.
const (
	ModeForm = "form"
	ModeURL  = "url"
)

// Params is the union of the two elicitation request param shapes, selected by
// the "mode" field: *FormParams (mode "form" or absent) or *URLParams
// (mode "url").
type Params interface {
	isElicitParams()
	// Mode returns the elicitation mode ("form" or "url").
	Mode() string
}

// FormParams elicit non-sensitive information via a form in the client.
type FormParams struct {
	// ModeField is "form" (or omitted, which implies form).
	ModeField string `json:"mode,omitempty"`
	// Message describes what information is being requested.
	Message string `json:"message"`
	// RequestedSchema is the restricted object schema of the form.
	RequestedSchema RequestedSchema `json:"requestedSchema"`
}

// URLParams elicit information via a URL the user navigates to (out-of-band,
// e.g. for sensitive data).
type URLParams struct {
	// ModeField is always "url".
	ModeField string `json:"mode"`
	// Message explains why the interaction is needed.
	Message string `json:"message"`
	// URL the user should navigate to.
	URL string `json:"url"`
}

func (*FormParams) isElicitParams() {}
func (*URLParams) isElicitParams()  {}

func (*FormParams) Mode() string { return ModeForm }
func (*URLParams) Mode() string  { return ModeURL }

// DecodeParams discriminates raw elicitation params by the "mode" field. An
// absent mode is treated as "form".
func DecodeParams(raw json.RawMessage) (Params, error) {
	var probe struct {
		Mode string `json:"mode"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return nil, err
	}
	switch probe.Mode {
	case ModeURL:
		p := &URLParams{}
		return p, json.Unmarshal(raw, p)
	case ModeForm, "":
		p := &FormParams{}
		return p, json.Unmarshal(raw, p)
	default:
		return nil, fmt.Errorf("elicitationdraft: unknown elicitation mode %q", probe.Mode)
	}
}

// ElicitRequest asks the client to elicit information from the user.
type ElicitRequest struct {
	Method string `json:"method"` // Method
	Params Params `json:"params"`
}

// UnmarshalJSON decodes the polymorphic params.
func (r *ElicitRequest) UnmarshalJSON(data []byte) error {
	var raw struct {
		Method string          `json:"method"`
		Params json.RawMessage `json:"params"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	r.Method = raw.Method
	if raw.Params != nil {
		p, err := DecodeParams(raw.Params)
		if err != nil {
			return err
		}
		r.Params = p
	}
	return nil
}

// RequestedSchema is the restricted object schema of a form-mode elicitation.
// Only top-level primitive properties are allowed.
type RequestedSchema struct {
	// Schema is the optional "$schema" URI.
	Schema string `json:"$schema,omitempty"`
	// Type is always "object".
	Type string `json:"type"`
	// Properties maps each field name to its primitive schema.
	Properties map[string]PrimitiveSchema `json:"properties"`
	// Required lists the required property names.
	Required []string `json:"required,omitempty"`
}

// UnmarshalJSON decodes the polymorphic property schemas.
func (s *RequestedSchema) UnmarshalJSON(data []byte) error {
	var raw struct {
		Schema     string                     `json:"$schema"`
		Type       string                     `json:"type"`
		Properties map[string]json.RawMessage `json:"properties"`
		Required   []string                   `json:"required"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	s.Schema = raw.Schema
	s.Type = raw.Type
	s.Required = raw.Required
	s.Properties = make(map[string]PrimitiveSchema, len(raw.Properties))
	for key, item := range raw.Properties {
		p, err := DecodePrimitiveSchema(item)
		if err != nil {
			return err
		}
		s.Properties[key] = p
	}
	return nil
}

// PrimitiveSchema is the restricted union of property schemas: string, number,
// boolean, or an enum variant (single/multi select, titled/untitled, legacy).
type PrimitiveSchema interface {
	isPrimitiveSchema()
	// SchemaType returns the JSON "type" ("string", "number", "integer",
	// "boolean" or "array").
	SchemaType() string
}

// StringSchema constrains a free-text string property.
type StringSchema struct {
	Type        string `json:"type"` // "string"
	Title       string `json:"title,omitempty"`
	Description string `json:"description,omitempty"`
	MinLength   *int   `json:"minLength,omitempty"`
	MaxLength   *int   `json:"maxLength,omitempty"`
	// Format is one of "email", "uri", "date", "date-time".
	Format  string `json:"format,omitempty"`
	Default string `json:"default,omitempty"`
}

// NumberSchema constrains a number- or integer-valued property.
type NumberSchema struct {
	Type        string   `json:"type"` // "number" or "integer"
	Title       string   `json:"title,omitempty"`
	Description string   `json:"description,omitempty"`
	Minimum     *float64 `json:"minimum,omitempty"`
	Maximum     *float64 `json:"maximum,omitempty"`
	Default     *float64 `json:"default,omitempty"`
}

// BooleanSchema constrains a boolean property.
type BooleanSchema struct {
	Type        string `json:"type"` // "boolean"
	Title       string `json:"title,omitempty"`
	Description string `json:"description,omitempty"`
	Default     *bool  `json:"default,omitempty"`
}

// EnumOption is a titled enum option ({const, title}) used by the titled
// single- and multi-select enum schemas.
type EnumOption struct {
	Const string `json:"const"`
	Title string `json:"title"`
}

// UntitledSingleSelectEnumSchema is a single-choice enum without display titles.
type UntitledSingleSelectEnumSchema struct {
	Type        string   `json:"type"` // "string"
	Title       string   `json:"title,omitempty"`
	Description string   `json:"description,omitempty"`
	Enum        []string `json:"enum"`
	Default     string   `json:"default,omitempty"`
}

// TitledSingleSelectEnumSchema is a single-choice enum with per-option titles.
type TitledSingleSelectEnumSchema struct {
	Type        string       `json:"type"` // "string"
	Title       string       `json:"title,omitempty"`
	Description string       `json:"description,omitempty"`
	OneOf       []EnumOption `json:"oneOf"`
	Default     string       `json:"default,omitempty"`
}

// EnumItems is the array-item schema of an untitled multi-select enum.
type EnumItems struct {
	Type string   `json:"type"` // "string"
	Enum []string `json:"enum"`
}

// TitledEnumItems is the array-item schema of a titled multi-select enum.
type TitledEnumItems struct {
	AnyOf []EnumOption `json:"anyOf"`
}

// UntitledMultiSelectEnumSchema is a multi-choice enum without display titles.
type UntitledMultiSelectEnumSchema struct {
	Type        string    `json:"type"` // "array"
	Title       string    `json:"title,omitempty"`
	Description string    `json:"description,omitempty"`
	MinItems    *int      `json:"minItems,omitempty"`
	MaxItems    *int      `json:"maxItems,omitempty"`
	Items       EnumItems `json:"items"`
	Default     []string  `json:"default,omitempty"`
}

// TitledMultiSelectEnumSchema is a multi-choice enum with per-option titles.
type TitledMultiSelectEnumSchema struct {
	Type        string          `json:"type"` // "array"
	Title       string          `json:"title,omitempty"`
	Description string          `json:"description,omitempty"`
	MinItems    *int            `json:"minItems,omitempty"`
	MaxItems    *int            `json:"maxItems,omitempty"`
	Items       TitledEnumItems `json:"items"`
	Default     []string        `json:"default,omitempty"`
}

// LegacyTitledEnumSchema is the deprecated enum schema using enumNames.
//
// Deprecated: use TitledSingleSelectEnumSchema instead.
type LegacyTitledEnumSchema struct {
	Type        string   `json:"type"` // "string"
	Title       string   `json:"title,omitempty"`
	Description string   `json:"description,omitempty"`
	Enum        []string `json:"enum"`
	// EnumNames are display names, non-standard per JSON Schema 2020-12.
	EnumNames []string `json:"enumNames,omitempty"`
	Default   string   `json:"default,omitempty"`
}

func (*StringSchema) isPrimitiveSchema()                   {}
func (*NumberSchema) isPrimitiveSchema()                   {}
func (*BooleanSchema) isPrimitiveSchema()                  {}
func (*UntitledSingleSelectEnumSchema) isPrimitiveSchema() {}
func (*TitledSingleSelectEnumSchema) isPrimitiveSchema()   {}
func (*UntitledMultiSelectEnumSchema) isPrimitiveSchema()  {}
func (*TitledMultiSelectEnumSchema) isPrimitiveSchema()    {}
func (*LegacyTitledEnumSchema) isPrimitiveSchema()         {}

func (*StringSchema) SchemaType() string                   { return "string" }
func (*NumberSchema) SchemaType() string                   { return "number" }
func (*BooleanSchema) SchemaType() string                  { return "boolean" }
func (*UntitledSingleSelectEnumSchema) SchemaType() string { return "string" }
func (*TitledSingleSelectEnumSchema) SchemaType() string   { return "string" }
func (*UntitledMultiSelectEnumSchema) SchemaType() string  { return "array" }
func (*TitledMultiSelectEnumSchema) SchemaType() string    { return "array" }
func (*LegacyTitledEnumSchema) SchemaType() string         { return "string" }

// DecodePrimitiveSchema discriminates a restricted property schema.
//
// A "boolean"/"number"/"integer" type maps directly. A "string" type is a
// TitledSingleSelectEnumSchema when it carries "oneOf", a LegacyTitledEnumSchema
// when it carries "enum" plus "enumNames", an UntitledSingleSelectEnumSchema
// when it carries "enum" alone, otherwise a StringSchema. An "array" type is a
// TitledMultiSelectEnumSchema when its items carry "anyOf", otherwise an
// UntitledMultiSelectEnumSchema.
func DecodePrimitiveSchema(raw json.RawMessage) (PrimitiveSchema, error) {
	var probe struct {
		Type  string          `json:"type"`
		Enum  json.RawMessage `json:"enum"`
		OneOf json.RawMessage `json:"oneOf"`
		Names json.RawMessage `json:"enumNames"`
		Items struct {
			AnyOf json.RawMessage `json:"anyOf"`
		} `json:"items"`
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
	case "array":
		if probe.Items.AnyOf != nil {
			schema = &TitledMultiSelectEnumSchema{}
		} else {
			schema = &UntitledMultiSelectEnumSchema{}
		}
	case "string":
		switch {
		case probe.OneOf != nil:
			schema = &TitledSingleSelectEnumSchema{}
		case probe.Enum != nil && probe.Names != nil:
			schema = &LegacyTitledEnumSchema{}
		case probe.Enum != nil:
			schema = &UntitledSingleSelectEnumSchema{}
		default:
			schema = &StringSchema{}
		}
	default:
		return nil, fmt.Errorf("elicitationdraft: unknown primitive schema type %q", probe.Type)
	}
	if err := json.Unmarshal(raw, schema); err != nil {
		return nil, err
	}
	return schema, nil
}

// Action is the user's response action.
type Action string

const (
	ActionAccept  Action = "accept"
	ActionDecline Action = "decline"
	ActionCancel  Action = "cancel"
)

// ElicitResult is the client's response to an elicitation request.
type ElicitResult struct {
	// Action is accept, decline or cancel.
	Action Action `json:"action"`
	// Content is the submitted form data, present only when Action is accept and
	// the mode was form. Values are string, number, boolean, or []string.
	Content map[string]any `json:"content,omitempty"`
}
