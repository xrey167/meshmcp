// Package roots holds the roots domain: the server's request for root URIs,
// the client's response, and the roots list-changed notification
// (schema @category `roots/list`).
package roots

import "github.com/xrey167/meshmcp/protocol/base"

// Method names in the roots domain.
const (
	MethodList        = "roots/list"
	MethodListChanged = "notifications/roots/list_changed"
)

// Root represents a root directory or file that the server can operate on.
type Root struct {
	// URI identifying the root. This must currently start with file://.
	URI string `json:"uri"`
	// Name is an optional human-readable identifier for the root.
	Name string `json:"name,omitempty"`
	// Meta is the open `_meta` object.
	Meta base.Meta `json:"_meta,omitempty"`
}

// ListRequest is sent from the server to request a list of root URIs from the
// client.
type ListRequest struct {
	Method string `json:"method"` // MethodList
}

// ListResult is the client's response to a roots/list request.
type ListResult struct {
	base.Result
	Roots []Root `json:"roots"`
}

// ListChangedNotification informs the server that the list of roots changed.
type ListChangedNotification struct {
	Method string `json:"method"` // MethodListChanged
}
