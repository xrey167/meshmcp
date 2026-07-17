// Package resource holds the resource domain: resource and resource-template
// descriptors, their contents (text/blob), and the resources/* request,
// result and notification types.
package resource

import (
	"encoding/json"
	"errors"

	"meshmcp/protocol/base"
)

// Method names in the resource domain.
const (
	MethodList          = "resources/list"
	MethodTemplatesList = "resources/templates/list"
	MethodRead          = "resources/read"
	MethodSubscribe     = "resources/subscribe"
	MethodUnsubscribe   = "resources/unsubscribe"
	MethodListChanged   = "notifications/resources/list_changed"
	MethodUpdated       = "notifications/resources/updated"
)

// Resource is a known resource that the server is capable of reading.
type Resource struct {
	base.BaseMetadata
	// URI of this resource.
	URI string `json:"uri"`
	// Description of what this resource represents.
	Description string `json:"description,omitempty"`
	// MimeType of this resource, if known.
	MimeType string `json:"mimeType,omitempty"`
	// Annotations are optional hints for the client.
	Annotations *base.Annotations `json:"annotations,omitempty"`
	// Size is the raw content size in bytes, before encoding, if known.
	Size *int64 `json:"size,omitempty"`
	// Meta is the open `_meta` object.
	Meta base.Meta `json:"_meta,omitempty"`
}

// ResourceTemplate is a template description for resources available on the
// server, using an RFC 6570 URI template.
type ResourceTemplate struct {
	base.BaseMetadata
	// URITemplate is an RFC 6570 template used to construct resource URIs.
	URITemplate string `json:"uriTemplate"`
	// Description of what this template is for.
	Description string `json:"description,omitempty"`
	// MimeType shared by all resources matching this template, if uniform.
	MimeType string `json:"mimeType,omitempty"`
	// Annotations are optional hints for the client.
	Annotations *base.Annotations `json:"annotations,omitempty"`
	// Meta is the open `_meta` object.
	Meta base.Meta `json:"_meta,omitempty"`
}

// Contents is the contents of a specific resource or sub-resource. It is the
// base shared by TextResourceContents and BlobResourceContents.
type Contents struct {
	// URI of this resource.
	URI string `json:"uri"`
	// MimeType of this resource, if known.
	MimeType string `json:"mimeType,omitempty"`
	// Meta is the open `_meta` object.
	Meta base.Meta `json:"_meta,omitempty"`
}

// ContentsUnion is the discriminated union of TextResourceContents and
// BlobResourceContents. Use DecodeContents to decode a raw value.
type ContentsUnion interface {
	isResourceContents()
}

// TextResourceContents is resource contents representable as text.
type TextResourceContents struct {
	Contents
	// Text is the text of the item (set only for text-representable data).
	Text string `json:"text"`
}

// BlobResourceContents is resource contents holding binary data.
type BlobResourceContents struct {
	Contents
	// Blob is the base64-encoded binary data of the item.
	Blob string `json:"blob"`
}

func (*TextResourceContents) isResourceContents() {}
func (*BlobResourceContents) isResourceContents() {}

// DecodeContents discriminates raw resource contents into a text or blob
// variant based on which of the "text"/"blob" fields is present.
func DecodeContents(raw json.RawMessage) (ContentsUnion, error) {
	var probe struct {
		Text *string `json:"text"`
		Blob *string `json:"blob"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return nil, err
	}
	switch {
	case probe.Blob != nil:
		v := &BlobResourceContents{}
		return v, json.Unmarshal(raw, v)
	case probe.Text != nil:
		v := &TextResourceContents{}
		return v, json.Unmarshal(raw, v)
	default:
		return nil, errors.New("resource: contents is neither text nor blob")
	}
}

// ListRequest is sent from the client to request a list of resources.
type ListRequest struct {
	Method string                `json:"method"` // MethodList
	Params *base.PaginatedParams `json:"params,omitempty"`
}

// ListResult is the server's response to a resources/list request.
type ListResult struct {
	base.PaginatedResult
	Resources []Resource `json:"resources"`
}

// ListTemplatesRequest is sent from the client to request resource templates.
type ListTemplatesRequest struct {
	Method string                `json:"method"` // MethodTemplatesList
	Params *base.PaginatedParams `json:"params,omitempty"`
}

// ListTemplatesResult is the server's response to a resources/templates/list request.
type ListTemplatesResult struct {
	base.PaginatedResult
	ResourceTemplates []ResourceTemplate `json:"resourceTemplates"`
}

// ReadRequest is sent from the client to read a specific resource URI.
type ReadRequest struct {
	Method string            `json:"method"` // MethodRead
	Params ReadRequestParams `json:"params"`
}

// ReadRequestParams are the params of a ReadRequest.
type ReadRequestParams struct {
	// URI of the resource to read.
	URI string `json:"uri"`
}

// ReadResult is the server's response to a resources/read request. Its
// contents are text and/or blob variants.
type ReadResult struct {
	base.Result
	Contents []ContentsUnion `json:"contents"`
}

// UnmarshalJSON decodes the polymorphic contents slice.
func (r *ReadResult) UnmarshalJSON(data []byte) error {
	var raw struct {
		Meta     base.Meta         `json:"_meta"`
		Contents []json.RawMessage `json:"contents"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	r.Meta = raw.Meta
	r.Contents = make([]ContentsUnion, 0, len(raw.Contents))
	for _, item := range raw.Contents {
		c, err := DecodeContents(item)
		if err != nil {
			return err
		}
		r.Contents = append(r.Contents, c)
	}
	return nil
}

// SubscribeRequest asks the server for resources/updated notifications for a
// particular resource.
type SubscribeRequest struct {
	Method string                 `json:"method"` // MethodSubscribe
	Params SubscribeRequestParams `json:"params"`
}

// SubscribeRequestParams are the params of a SubscribeRequest.
type SubscribeRequestParams struct {
	// URI of the resource to subscribe to.
	URI string `json:"uri"`
}

// UnsubscribeRequest cancels a previous resources/subscribe request.
type UnsubscribeRequest struct {
	Method string                   `json:"method"` // MethodUnsubscribe
	Params UnsubscribeRequestParams `json:"params"`
}

// UnsubscribeRequestParams are the params of an UnsubscribeRequest.
type UnsubscribeRequestParams struct {
	// URI of the resource to unsubscribe from.
	URI string `json:"uri"`
}

// ListChangedNotification informs the client that the list of resources
// changed.
type ListChangedNotification struct {
	Method string `json:"method"` // MethodListChanged
}

// UpdatedNotification informs the client that a subscribed resource changed and
// may need to be read again.
type UpdatedNotification struct {
	Method string                    `json:"method"` // MethodUpdated
	Params UpdatedNotificationParams `json:"params"`
}

// UpdatedNotificationParams are the params of an UpdatedNotification.
type UpdatedNotificationParams struct {
	// URI of the resource that was updated.
	URI string `json:"uri"`
}
