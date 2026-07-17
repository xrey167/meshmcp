// Package logging holds the logging domain: the setLevel request and the log
// message notification (schema @category `logging/setLevel`, `notifications/message`).
package logging

// Method names in the logging domain.
const (
	MethodSetLevel = "logging/setLevel"
	MethodMessage  = "notifications/message"
)

// Level is the severity of a log message, mapping to RFC-5424 syslog severities.
type Level string

const (
	LevelDebug     Level = "debug"
	LevelInfo      Level = "info"
	LevelNotice    Level = "notice"
	LevelWarning   Level = "warning"
	LevelError     Level = "error"
	LevelCritical  Level = "critical"
	LevelAlert     Level = "alert"
	LevelEmergency Level = "emergency"
)

// SetLevelRequest is a request from the client to enable or adjust logging.
type SetLevelRequest struct {
	Method string                `json:"method"` // MethodSetLevel
	Params SetLevelRequestParams `json:"params"`
}

// SetLevelRequestParams are the params of a SetLevelRequest.
type SetLevelRequestParams struct {
	// Level is the minimum severity the client wants to receive.
	Level Level `json:"level"`
}

// MessageNotification is a log message passed from server to client.
type MessageNotification struct {
	Method string                    `json:"method"` // MethodMessage
	Params MessageNotificationParams `json:"params"`
}

// MessageNotificationParams are the params of a MessageNotification.
type MessageNotificationParams struct {
	// Level is the severity of this log message.
	Level Level `json:"level"`
	// Logger optionally names the logger issuing this message.
	Logger string `json:"logger,omitempty"`
	// Data is the payload to be logged (any JSON-serializable value).
	Data any `json:"data"`
}
