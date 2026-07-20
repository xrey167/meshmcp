// Package completion holds the autocomplete domain: the completion/complete
// request and result, and the prompt/resource references it targets
// (schema @category `completion/complete`).
package completion

import (
	"encoding/json"
	"fmt"

	"github.com/xrey167/meshmcp/protocol/base"
)

// Method is the JSON-RPC method name for a completion request.
const Method = "completion/complete"

// Reference discriminator values.
const (
	TypePromptRef   = "ref/prompt"
	TypeResourceRef = "ref/resource"
)

// Reference is the union of a prompt reference or a resource-template
// reference targeted by a completion request.
type Reference interface {
	isReference()
	// RefType returns the discriminator value of this reference.
	RefType() string
}

// PromptReference identifies a prompt.
type PromptReference struct {
	base.BaseMetadata
	Type string `json:"type"` // "ref/prompt"
}

// ResourceTemplateReference references a resource or resource-template
// definition.
type ResourceTemplateReference struct {
	Type string `json:"type"` // "ref/resource"
	// URI or URI template of the resource.
	URI string `json:"uri"`
}

func (*PromptReference) isReference()           {}
func (*ResourceTemplateReference) isReference() {}

func (*PromptReference) RefType() string           { return TypePromptRef }
func (*ResourceTemplateReference) RefType() string { return TypeResourceRef }

// DecodeReference discriminates a raw reference by its JSON "type" field.
func DecodeReference(raw json.RawMessage) (Reference, error) {
	var probe struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return nil, err
	}
	var ref Reference
	switch probe.Type {
	case TypePromptRef:
		ref = &PromptReference{}
	case TypeResourceRef:
		ref = &ResourceTemplateReference{}
	default:
		return nil, fmt.Errorf("completion: unknown reference type %q", probe.Type)
	}
	if err := json.Unmarshal(raw, ref); err != nil {
		return nil, err
	}
	return ref, nil
}

// Argument is the argument being completed.
type Argument struct {
	// Name of the argument.
	Name string `json:"name"`
	// Value of the argument to use for completion matching.
	Value string `json:"value"`
}

// Context is additional, optional context for completions.
type Context struct {
	// Arguments are previously-resolved variables in a URI template or prompt.
	Arguments map[string]string `json:"arguments,omitempty"`
}

// CompleteRequest asks the server for completion options.
type CompleteRequest struct {
	Method string                `json:"method"` // Method
	Params CompleteRequestParams `json:"params"`
}

// CompleteRequestParams are the params of a CompleteRequest.
type CompleteRequestParams struct {
	// Ref is the prompt or resource-template being completed.
	Ref Reference `json:"ref"`
	// Argument is the argument's information.
	Argument Argument `json:"argument"`
	// Context is optional additional completion context.
	Context *Context `json:"context,omitempty"`
}

// UnmarshalJSON decodes the polymorphic ref field.
func (p *CompleteRequestParams) UnmarshalJSON(data []byte) error {
	var raw struct {
		Ref      json.RawMessage `json:"ref"`
		Argument Argument        `json:"argument"`
		Context  *Context        `json:"context"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	p.Argument = raw.Argument
	p.Context = raw.Context
	if raw.Ref != nil {
		ref, err := DecodeReference(raw.Ref)
		if err != nil {
			return err
		}
		p.Ref = ref
	}
	return nil
}

// CompleteResult is the server's response to a completion/complete request.
type CompleteResult struct {
	base.Result
	Completion Completion `json:"completion"`
}

// Completion holds the completion values returned to the client.
type Completion struct {
	// Values is an array of completion values (max 100 items).
	Values []string `json:"values"`
	// Total is the number of completion options available, which may exceed the
	// number of values sent.
	Total *int `json:"total,omitempty"`
	// HasMore indicates whether additional options exist beyond those provided.
	HasMore bool `json:"hasMore,omitempty"`
}
