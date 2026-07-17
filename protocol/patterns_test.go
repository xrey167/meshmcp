package protocol_test

import (
	"encoding/json"
	"testing"

	"meshmcp/protocol/mrtr"
	"meshmcp/protocol/subscriptions"
)

// TestInputRequiredResult checks the MRTR InputRequiredResult decodes its
// discriminator, request map and opaque state.
func TestInputRequiredResult(t *testing.T) {
	raw := `{
		"resultType": "input_required",
		"inputRequests": {
			"github_login": {"method": "elicitation/create", "params": {"message": "user?"}}
		},
		"requestState": "AEAD-blob"
	}`
	var res mrtr.InputRequiredResult
	if err := json.Unmarshal([]byte(raw), &res); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if res.ResultType != mrtr.ResultTypeInputRequired {
		t.Fatalf("resultType = %q", res.ResultType)
	}
	if _, ok := res.InputRequests["github_login"]; !ok {
		t.Fatalf("missing input request: %+v", res.InputRequests)
	}
	if res.RequestState != "AEAD-blob" {
		t.Fatalf("requestState = %q", res.RequestState)
	}
}

// TestSubscriptionsListen checks the listen request filter and the
// acknowledgment's subscription-ID metadata round-trip.
func TestSubscriptionsListen(t *testing.T) {
	req := subscriptions.ListenRequest{
		Method: subscriptions.MethodListen,
		Params: subscriptions.ListenRequestParams{
			Notifications: subscriptions.Filter{
				ToolsListChanged:      true,
				ResourceSubscriptions: []string{"file:///project/config.json"},
			},
		},
	}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out subscriptions.ListenRequest
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !out.Params.Notifications.ToolsListChanged ||
		len(out.Params.Notifications.ResourceSubscriptions) != 1 {
		t.Fatalf("filter lost in round-trip: %+v", out.Params.Notifications)
	}

	ack := `{
		"method": "notifications/subscriptions/acknowledged",
		"params": {"_meta": {"io.modelcontextprotocol/subscriptionId": 1},
			"notifications": {"toolsListChanged": true}}
	}`
	var an subscriptions.AcknowledgedNotification
	if err := json.Unmarshal([]byte(ack), &an); err != nil {
		t.Fatalf("ack unmarshal: %v", err)
	}
	if _, ok := an.Params.Meta[subscriptions.MetaKeySubscriptionID]; !ok {
		t.Fatalf("subscriptionId not in _meta: %+v", an.Params.Meta)
	}
}
