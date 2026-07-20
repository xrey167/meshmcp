// Package tasks models the MCP Tasks extension (io.modelcontextprotocol/tasks,
// SEP-2663): asynchronous request processing where a server returns a task
// handle and the client polls or subscribes for status.
//
// Source of truth: modelcontextprotocol/ext-tasks (schema/draft/schema.ts).
// This is an EXPERIMENTAL extension, declared via a server's capability
// extensions map under ExtensionID.
package tasks

import "github.com/xrey167/meshmcp/protocol/base"

// ExtensionID is the capability identifier for the tasks extension.
const ExtensionID = "io.modelcontextprotocol/tasks"

// Method names in the tasks extension.
const (
	MethodGet          = "tasks/get"
	MethodUpdate       = "tasks/update"
	MethodCancel       = "tasks/cancel"
	MethodNotification = "notifications/tasks"
)

// Result-type discriminator values used by task results.
const (
	// ResultTypeTask marks a CreateTaskResult (async processing began).
	ResultTypeTask = "task"
	// ResultTypeComplete marks the ack/detail results (tasks/get, update, cancel).
	ResultTypeComplete = "complete"
)

// TaskStatus is the lifecycle status of a task.
type TaskStatus string

const (
	StatusWorking       TaskStatus = "working"
	StatusInputRequired TaskStatus = "input_required"
	StatusCompleted     TaskStatus = "completed"
	StatusFailed        TaskStatus = "failed"
	StatusCancelled     TaskStatus = "cancelled"
)

// Task is the data associated with a task.
type Task struct {
	// TaskID is the task identifier.
	TaskID string `json:"taskId"`
	// Status is the current task status.
	Status TaskStatus `json:"status"`
	// StatusMessage is an optional human-readable description of the state.
	StatusMessage string `json:"statusMessage,omitempty"`
	// CreatedAt is the ISO 8601 creation timestamp.
	CreatedAt string `json:"createdAt"`
	// LastUpdatedAt is the ISO 8601 last-update timestamp.
	LastUpdatedAt string `json:"lastUpdatedAt"`
	// TTLMs is the time-to-live from creation in integer milliseconds; nil (JSON
	// null) means unlimited. It MAY change over the task's lifetime.
	TTLMs *int64 `json:"ttlMs"`
	// PollIntervalMs is the suggested polling interval in integer milliseconds.
	PollIntervalMs *int64 `json:"pollIntervalMs,omitempty"`
}

// InputRequests are outstanding server-to-client requests to fulfill during
// task execution. Keys are arbitrary, unique per task; values are one of a
// CreateMessageRequest, ListRootsRequest or ElicitRequest.
type InputRequests = map[string]any

// InputResponses are client responses to outstanding InputRequests, keyed by
// the corresponding request key; values are one of a CreateMessageResult,
// ListRootsResult or ElicitResult.
type InputResponses = map[string]any

// DetailedTask is the full task state used by tasks/get responses and
// notifications/tasks. It carries the base Task fields plus the status-specific
// field: InputRequests (input_required), Result (completed) or Error (failed).
// Working and cancelled tasks carry none of the three.
type DetailedTask struct {
	Task
	// InputRequests is present when Status is input_required.
	InputRequests InputRequests `json:"inputRequests,omitempty"`
	// Result is the final result when Status is completed; its shape matches the
	// original request's result type.
	Result map[string]any `json:"result,omitempty"`
	// Error is the JSON-RPC error when Status is failed.
	Error map[string]any `json:"error,omitempty"`
}

// CreateTaskResult is returned in lieu of a standard result when a server
// processes a request asynchronously. ResultType MUST be ResultTypeTask.
type CreateTaskResult struct {
	Task
	Meta       base.Meta `json:"_meta,omitempty"`
	ResultType string    `json:"resultType"`
}

// GetTaskParams are the params of a GetTaskRequest.
type GetTaskParams struct {
	// TaskID to query.
	TaskID string `json:"taskId"`
}

// GetTaskRequest retrieves the state of a task.
type GetTaskRequest struct {
	Method string        `json:"method"` // MethodGet
	Params GetTaskParams `json:"params"`
}

// GetTaskResult carries the DetailedTask for the task's current status.
// ResultType MUST be ResultTypeComplete.
type GetTaskResult struct {
	DetailedTask
	Meta       base.Meta `json:"_meta,omitempty"`
	ResultType string    `json:"resultType"`
}

// UpdateTaskParams are the params of an UpdateTaskRequest.
type UpdateTaskParams struct {
	// TaskID to update.
	TaskID string `json:"taskId"`
	// InputResponses answer outstanding inputRequests; each key MUST match a
	// currently-outstanding inputRequest key.
	InputResponses InputResponses `json:"inputResponses"`
}

// UpdateTaskRequest provides input responses to a task in the input_required
// state.
type UpdateTaskRequest struct {
	Method string           `json:"method"` // MethodUpdate
	Params UpdateTaskParams `json:"params"`
}

// CancelTaskParams are the params of a CancelTaskRequest.
type CancelTaskParams struct {
	// TaskID to cancel.
	TaskID string `json:"taskId"`
}

// CancelTaskRequest cancels a task. Cancellation is cooperative and eventually
// consistent.
type CancelTaskRequest struct {
	Method string           `json:"method"` // MethodCancel
	Params CancelTaskParams `json:"params"`
}

// Ack is the empty acknowledgement returned by tasks/update and tasks/cancel.
// ResultType MUST be ResultTypeComplete.
type Ack struct {
	Meta       base.Meta `json:"_meta,omitempty"`
	ResultType string    `json:"resultType"`
}

// UpdateTaskResult is the response to a tasks/update request.
type UpdateTaskResult = Ack

// CancelTaskResult is the response to a tasks/cancel request.
type CancelTaskResult = Ack

// StatusNotificationParams are the params of a TaskStatusNotification: a
// complete DetailedTask for the current status.
type StatusNotificationParams struct {
	DetailedTask
	// Meta is the open `_meta` object (carries the subscriptionId on the stream).
	Meta base.Meta `json:"_meta,omitempty"`
}

// StatusNotification informs the client that a task's status changed. Clients
// subscribe via subscriptions/listen; servers are not required to send these.
type StatusNotification struct {
	Method string                   `json:"method"` // MethodNotification
	Params StatusNotificationParams `json:"params"`
}

// SubscriptionNotifications are the task-specific fields a client adds to a
// subscriptions/listen request to receive notifications/tasks for given IDs.
type SubscriptionNotifications struct {
	// TaskIDs to subscribe to.
	TaskIDs []string `json:"taskIds,omitempty"`
}

// SubscriptionAcknowledgedNotifications are the task-specific fields the server
// echoes on the subscription acknowledgement.
type SubscriptionAcknowledgedNotifications struct {
	// TaskIDs the server agreed to send status notifications for.
	TaskIDs []string `json:"taskIds,omitempty"`
}

// ExtensionCapability is the tasks extension capability declaration. An empty
// object indicates support; no settings are defined.
type ExtensionCapability struct{}
