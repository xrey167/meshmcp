// Package progress holds the out-of-band progress notification for long-running
// requests (schema @category `notifications/progress`).
package progress

import "github.com/xrey167/meshmcp/protocol/base"

// Method is the JSON-RPC method name for a progress notification.
const Method = "notifications/progress"

// ProgressNotification informs the receiver of a progress update for a
// long-running request.
type ProgressNotification struct {
	Method string                     `json:"method"` // Method
	Params ProgressNotificationParams `json:"params"`
}

// ProgressNotificationParams are the params of a ProgressNotification.
type ProgressNotificationParams struct {
	// ProgressToken associates this notification with the originating request.
	ProgressToken base.ProgressToken `json:"progressToken"`
	// Progress increases every time progress is made, even if Total is unknown.
	Progress float64 `json:"progress"`
	// Total is the number of items to process, if known.
	Total *float64 `json:"total,omitempty"`
	// Message optionally describes the current progress.
	Message string `json:"message,omitempty"`
}
