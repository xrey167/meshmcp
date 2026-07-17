package tasks_test

import (
	"encoding/json"
	"testing"

	"meshmcp/protocol/tasks"
)

func TestCreateTaskResult(t *testing.T) {
	raw := `{
		"resultType": "task",
		"taskId": "t-1",
		"status": "working",
		"createdAt": "2026-07-28T10:00:00Z",
		"lastUpdatedAt": "2026-07-28T10:00:00Z",
		"ttlMs": 60000,
		"pollIntervalMs": 1000
	}`
	var r tasks.CreateTaskResult
	if err := json.Unmarshal([]byte(raw), &r); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if r.ResultType != tasks.ResultTypeTask || r.TaskID != "t-1" || r.Status != tasks.StatusWorking {
		t.Fatalf("mismatch: %+v", r)
	}
	if r.TTLMs == nil || *r.TTLMs != 60000 {
		t.Fatalf("ttlMs = %v", r.TTLMs)
	}
}

func TestTTLNullIsUnlimited(t *testing.T) {
	var r tasks.CreateTaskResult
	if err := json.Unmarshal([]byte(`{"resultType":"task","taskId":"t","status":"working","createdAt":"x","lastUpdatedAt":"x","ttlMs":null}`), &r); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if r.TTLMs != nil {
		t.Fatalf("ttlMs null should decode to nil (unlimited), got %v", *r.TTLMs)
	}
	// And it must marshal back to explicit null.
	out, _ := json.Marshal(r)
	var probe map[string]any
	_ = json.Unmarshal(out, &probe)
	if v, ok := probe["ttlMs"]; !ok || v != nil {
		t.Fatalf("ttlMs should marshal to null, got %v (present=%v)", v, ok)
	}
}

func TestGetTaskResultVariants(t *testing.T) {
	// completed → result present
	completed := `{
		"resultType": "complete",
		"taskId": "t-2", "status": "completed",
		"createdAt": "x", "lastUpdatedAt": "y", "ttlMs": null,
		"result": {"content": [{"type": "text", "text": "done"}]}
	}`
	var c tasks.GetTaskResult
	if err := json.Unmarshal([]byte(completed), &c); err != nil {
		t.Fatalf("completed: %v", err)
	}
	if c.Status != tasks.StatusCompleted || c.Result == nil {
		t.Fatalf("completed task missing result: %+v", c)
	}

	// input_required → inputRequests present
	inputReq := `{
		"resultType": "complete",
		"taskId": "t-3", "status": "input_required",
		"createdAt": "x", "lastUpdatedAt": "y", "ttlMs": 5000,
		"inputRequests": {"k1": {"method": "elicitation/create", "params": {"message": "?"}}}
	}`
	var ir tasks.GetTaskResult
	if err := json.Unmarshal([]byte(inputReq), &ir); err != nil {
		t.Fatalf("input_required: %v", err)
	}
	if ir.Status != tasks.StatusInputRequired || len(ir.InputRequests) != 1 {
		t.Fatalf("input_required task missing inputRequests: %+v", ir)
	}

	// failed → error present
	failed := `{"resultType":"complete","taskId":"t-4","status":"failed","createdAt":"x","lastUpdatedAt":"y","ttlMs":null,"error":{"code":-32603,"message":"boom"}}`
	var f tasks.GetTaskResult
	if err := json.Unmarshal([]byte(failed), &f); err != nil {
		t.Fatalf("failed: %v", err)
	}
	if f.Status != tasks.StatusFailed || f.Error["message"] != "boom" {
		t.Fatalf("failed task missing error: %+v", f)
	}
}

func TestTaskStatusNotification(t *testing.T) {
	frame := `{
		"method": "notifications/tasks",
		"params": {
			"_meta": {"io.modelcontextprotocol/subscriptionId": 1},
			"taskId": "t-5", "status": "working",
			"createdAt": "x", "lastUpdatedAt": "y", "ttlMs": null
		}
	}`
	var n tasks.StatusNotification
	if err := json.Unmarshal([]byte(frame), &n); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if n.Method != tasks.MethodNotification || n.Params.TaskID != "t-5" {
		t.Fatalf("notification mismatch: %+v", n)
	}
	if n.Params.Meta["io.modelcontextprotocol/subscriptionId"] == nil {
		t.Fatalf("subscriptionId meta lost: %+v", n.Params.Meta)
	}
}

func TestTaskOperationRequests(t *testing.T) {
	var g tasks.GetTaskRequest
	if err := json.Unmarshal([]byte(`{"method":"tasks/get","params":{"taskId":"t-1"}}`), &g); err != nil {
		t.Fatalf("get: %v", err)
	}
	if g.Params.TaskID != "t-1" {
		t.Fatalf("get taskId = %q", g.Params.TaskID)
	}

	var u tasks.UpdateTaskRequest
	if err := json.Unmarshal([]byte(`{"method":"tasks/update","params":{"taskId":"t-1","inputResponses":{"k1":{"action":"accept"}}}}`), &u); err != nil {
		t.Fatalf("update: %v", err)
	}
	if len(u.Params.InputResponses) != 1 {
		t.Fatalf("update inputResponses = %v", u.Params.InputResponses)
	}
}
