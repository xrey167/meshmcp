// Package cancellation holds the cancelled notification, sent by either side to
// abandon a previously-issued request (schema @category `notifications/cancelled`).
package cancellation

import "github.com/xrey167/meshmcp/protocol/base"

// Method is the JSON-RPC method name for a cancelled notification.
const Method = "notifications/cancelled"

// CancelledNotification indicates that a previously-issued request is being
// cancelled. A client MUST NOT attempt to cancel its initialize request.
type CancelledNotification struct {
	Method string                      `json:"method"` // Method
	Params CancelledNotificationParams `json:"params"`
}

// CancelledNotificationParams are the params of a CancelledNotification.
type CancelledNotificationParams struct {
	// RequestId is the ID of the request to cancel. It MUST correspond to a
	// request previously issued in the same direction.
	RequestId base.RequestId `json:"requestId"`
	// Reason optionally describes why the request was cancelled.
	Reason string `json:"reason,omitempty"`
}
