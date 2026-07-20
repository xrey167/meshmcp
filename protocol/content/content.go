// Package content holds the content-block union embedded in prompts, tool
// results and sampling messages: text, image, audio, resource links and
// embedded resources (schema @category Content).
package content

import (
	"encoding/json"
	"fmt"

	"github.com/xrey167/meshmcp/protocol/base"
	"github.com/xrey167/meshmcp/protocol/resource"
)

// Block is the discriminated union of content types carried in messages and
// tool results: *TextContent, *ImageContent, *AudioContent, *ResourceLink,
// *EmbeddedResource. The concrete type is selected by the JSON "type" field.
type Block interface {
	isContentBlock()
	// BlockType returns the discriminator value of this content block.
	BlockType() string
}

// TextContent is text provided to or from an LLM.
type TextContent struct {
	Type string `json:"type"` // "text"
	// Text is the text content of the message.
	Text string `json:"text"`
	// Annotations are optional hints for the client.
	Annotations *base.Annotations `json:"annotations,omitempty"`
	// Meta is the open `_meta` object.
	Meta base.Meta `json:"_meta,omitempty"`
}

// ImageContent is an image provided to or from an LLM.
type ImageContent struct {
	Type string `json:"type"` // "image"
	// Data is the base64-encoded image data.
	Data string `json:"data"`
	// MimeType of the image.
	MimeType string `json:"mimeType"`
	// Annotations are optional hints for the client.
	Annotations *base.Annotations `json:"annotations,omitempty"`
	// Meta is the open `_meta` object.
	Meta base.Meta `json:"_meta,omitempty"`
}

// AudioContent is audio provided to or from an LLM.
type AudioContent struct {
	Type string `json:"type"` // "audio"
	// Data is the base64-encoded audio data.
	Data string `json:"data"`
	// MimeType of the audio.
	MimeType string `json:"mimeType"`
	// Annotations are optional hints for the client.
	Annotations *base.Annotations `json:"annotations,omitempty"`
	// Meta is the open `_meta` object.
	Meta base.Meta `json:"_meta,omitempty"`
}

// ResourceLink is a resource the server can read, referenced from a prompt or
// tool-call result. Such links are not guaranteed to appear in resources/list.
type ResourceLink struct {
	resource.Resource
	Type string `json:"type"` // "resource_link"
}

// EmbeddedResource is the contents of a resource embedded directly into a
// prompt or tool-call result.
type EmbeddedResource struct {
	Type string `json:"type"` // "resource"
	// Resource is the embedded text or blob contents.
	Resource resource.ContentsUnion `json:"resource"`
	// Annotations are optional hints for the client.
	Annotations *base.Annotations `json:"annotations,omitempty"`
	// Meta is the open `_meta` object.
	Meta base.Meta `json:"_meta,omitempty"`
}

// Content-block discriminator values.
const (
	TypeText         = "text"
	TypeImage        = "image"
	TypeAudio        = "audio"
	TypeResourceLink = "resource_link"
	TypeResource     = "resource"
)

func (*TextContent) isContentBlock()      {}
func (*ImageContent) isContentBlock()     {}
func (*AudioContent) isContentBlock()     {}
func (*ResourceLink) isContentBlock()     {}
func (*EmbeddedResource) isContentBlock() {}

func (*TextContent) BlockType() string      { return TypeText }
func (*ImageContent) BlockType() string     { return TypeImage }
func (*AudioContent) BlockType() string     { return TypeAudio }
func (*ResourceLink) BlockType() string     { return TypeResourceLink }
func (*EmbeddedResource) BlockType() string { return TypeResource }

// UnmarshalJSON decodes the polymorphic embedded resource contents.
func (e *EmbeddedResource) UnmarshalJSON(data []byte) error {
	var raw struct {
		Type        string            `json:"type"`
		Resource    json.RawMessage   `json:"resource"`
		Annotations *base.Annotations `json:"annotations"`
		Meta        base.Meta         `json:"_meta"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	e.Type = raw.Type
	e.Annotations = raw.Annotations
	e.Meta = raw.Meta
	if raw.Resource != nil {
		rc, err := resource.DecodeContents(raw.Resource)
		if err != nil {
			return err
		}
		e.Resource = rc
	}
	return nil
}

// DecodeBlock discriminates a raw content block into its concrete type based
// on the JSON "type" field.
func DecodeBlock(raw json.RawMessage) (Block, error) {
	var probe struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return nil, err
	}
	var b Block
	switch probe.Type {
	case TypeText:
		b = &TextContent{}
	case TypeImage:
		b = &ImageContent{}
	case TypeAudio:
		b = &AudioContent{}
	case TypeResourceLink:
		b = &ResourceLink{}
	case TypeResource:
		b = &EmbeddedResource{}
	default:
		return nil, fmt.Errorf("content: unknown content block type %q", probe.Type)
	}
	if err := json.Unmarshal(raw, b); err != nil {
		return nil, err
	}
	return b, nil
}

// DecodeBlocks decodes a JSON array of content blocks.
func DecodeBlocks(data []byte) ([]Block, error) {
	var items []json.RawMessage
	if err := json.Unmarshal(data, &items); err != nil {
		return nil, err
	}
	blocks := make([]Block, 0, len(items))
	for _, item := range items {
		b, err := DecodeBlock(item)
		if err != nil {
			return nil, err
		}
		blocks = append(blocks, b)
	}
	return blocks, nil
}
