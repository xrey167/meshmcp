package air

import (
	"encoding/json"
	"strings"
	"testing"
)

func deliveredSteerMember(key string) FanoutMember {
	return FanoutMember{
		Recipient: FanoutRecipient{Name: "Analyst", FQDN: "analyst.mesh", PublicKey: key},
		Status:    FanoutDelivered,
		Steer:     &FanoutSteer{Backend: "fs", Session: "9f2a", By: "operator.mesh"},
		Time:      "2026-07-23T10:00:00Z",
	}
}

func deliveredRingMember(key string) FanoutMember {
	return FanoutMember{
		Recipient: FanoutRecipient{
			Name: "Analyst", FQDN: "analyst.mesh", PublicKey: key,
			Service: ServiceRing, Address: "100.64.0.8:9120",
		},
		Status: FanoutDelivered,
	}
}

func TestFanoutResultValid(t *testing.T) {
	res, err := NewFanoutResult("oncall", FanoutActionSteer, []FanoutMember{
		deliveredSteerMember("KEY-A"),
		{Recipient: FanoutRecipient{PublicKey: "KEY-B"}, Status: FanoutSkipped, Reason: "no identity-bound live session"},
		{Recipient: FanoutRecipient{PublicKey: "KEY-C"}, Status: FanoutDenied, Reason: "not permitted for this backend"},
		{Recipient: FanoutRecipient{PublicKey: "KEY-D"}, Status: FanoutFailed, Reason: "dial: connection refused"},
	}, []string{"pubkey:KEY-GONE", "ghost.*"})
	if err != nil {
		t.Fatalf("valid fanout rejected: %v", err)
	}
	if res.Schema != FanoutResultSchemaV1 || len(res.Members) != 4 {
		t.Fatalf("unexpected result: %+v", res)
	}
	if len(res.UnmatchedPatterns) != 2 || res.UnmatchedPatterns[0] != "pubkey:KEY-GONE" {
		t.Fatalf("unmatched echo lost: %v", res.UnmatchedPatterns)
	}

	if _, err := NewFanoutResult("team", FanoutActionRing, []FanoutMember{
		deliveredRingMember("KEY-A"),
		{Recipient: FanoutRecipient{PublicKey: "KEY-B", Service: ServiceRing}, Status: FanoutSkipped, Reason: `no "ring" service advertised`},
	}, nil); err != nil {
		t.Fatalf("valid ring fanout rejected: %v", err)
	}
}

func TestFanoutResultValidationTable(t *testing.T) {
	mutate := func(f func(*FanoutResult)) FanoutResult {
		r := FanoutResult{
			Schema: FanoutResultSchemaV1, Group: "oncall", Action: FanoutActionSteer,
			Members: []FanoutMember{deliveredSteerMember("KEY-A")},
		}
		f(&r)
		return r
	}
	tests := []struct {
		name string
		r    FanoutResult
		want string
	}{
		{"wrong schema", mutate(func(r *FanoutResult) { r.Schema = "air.fanout-result/v0" }), "schema"},
		{"empty group", mutate(func(r *FanoutResult) { r.Group = "" }), "group name"},
		{"group with colon", mutate(func(r *FanoutResult) { r.Group = "on:call" }), `":"`},
		{"group with control char", mutate(func(r *FanoutResult) { r.Group = "on\ncall" }), "control"},
		{"group too long", mutate(func(r *FanoutResult) { r.Group = strings.Repeat("g", MaxGroupNameBytes+1) }), "at most"},
		{"unknown action", mutate(func(r *FanoutResult) { r.Action = "broadcast" }), "action"},
		{"zero members", mutate(func(r *FanoutResult) { r.Members = nil }), "between 1 and"},
		{"unknown status", mutate(func(r *FanoutResult) { r.Members[0].Status = "done" }), "unknown member status"},
		{"delivered with reason", mutate(func(r *FanoutResult) { r.Members[0].Reason = "also fine" }), "must not carry a reason"},
		{"delivered steer without detail", mutate(func(r *FanoutResult) { r.Members[0].Steer = nil }), "requires steer detail"},
		{"steer detail without session", mutate(func(r *FanoutResult) { r.Members[0].Steer = &FanoutSteer{Backend: "fs"} }), "backend and session"},
		{"skipped without reason", mutate(func(r *FanoutResult) {
			r.Members[0] = FanoutMember{Recipient: FanoutRecipient{PublicKey: "K"}, Status: FanoutSkipped}
		}), "requires a reason"},
		{"denied without reason", mutate(func(r *FanoutResult) {
			r.Members[0] = FanoutMember{Recipient: FanoutRecipient{PublicKey: "K"}, Status: FanoutDenied, Reason: "   "}
		}), "requires a reason"},
		{"failed without reason", mutate(func(r *FanoutResult) {
			r.Members[0] = FanoutMember{Recipient: FanoutRecipient{PublicKey: "K"}, Status: FanoutFailed}
		}), "requires a reason"},
		{"reason too long", mutate(func(r *FanoutResult) {
			r.Members[0] = FanoutMember{Recipient: FanoutRecipient{PublicKey: "K"}, Status: FanoutFailed, Reason: strings.Repeat("x", MaxFanoutReasonBytes+1)}
		}), "at most"},
		{"multi-line reason", mutate(func(r *FanoutResult) {
			r.Members[0] = FanoutMember{Recipient: FanoutRecipient{PublicKey: "K"}, Status: FanoutFailed, Reason: "line one\nline two"}
		}), "single line"},
		{"non-delivered with steer detail", mutate(func(r *FanoutResult) {
			r.Members[0] = FanoutMember{Recipient: FanoutRecipient{PublicKey: "K"}, Status: FanoutDenied, Reason: "no", Steer: &FanoutSteer{Backend: "fs", Session: "s"}}
		}), "only a delivered member"},
		{"missing public key", mutate(func(r *FanoutResult) { r.Members[0].Recipient.PublicKey = "" }), "public key"},
		{"friendly name without key", mutate(func(r *FanoutResult) {
			r.Members[0].Recipient = FanoutRecipient{Name: "Analyst"}
		}), "public key"},
		{"bad recipient address", mutate(func(r *FanoutResult) {
			r.Members[0].Recipient.Address = "not-a-host-port"
		}), "host:port"},
		{"unknown recipient service", mutate(func(r *FanoutResult) {
			r.Members[0].Recipient.Service = "shell"
		}), "service kind"},
		{"receipt is reserved", mutate(func(r *FanoutResult) {
			r.Members[0].Receipt = &ActionReceipt{}
		}), "reserved"},
		{"bad member time", mutate(func(r *FanoutResult) { r.Members[0].Time = "yesterday" }), "RFC3339"},
		{"ring delivered without address", FanoutResult{
			Schema: FanoutResultSchemaV1, Group: "team", Action: FanoutActionRing,
			Members: []FanoutMember{{Recipient: FanoutRecipient{PublicKey: "K", Service: ServiceRing}, Status: FanoutDelivered}},
		}, "delivered ring member requires"},
		{"ring member with steer detail", FanoutResult{
			Schema: FanoutResultSchemaV1, Group: "team", Action: FanoutActionRing,
			Members: []FanoutMember{{
				Recipient: FanoutRecipient{PublicKey: "K", Address: "100.64.0.8:9120"},
				Status:    FanoutDelivered, Steer: &FanoutSteer{Backend: "fs", Session: "s"},
			}},
		}, "must not carry steer detail"},
		{"blank unmatched pattern", mutate(func(r *FanoutResult) { r.UnmatchedPatterns = []string{"  "} }), "non-empty"},
		{"unmatched pattern over bound", mutate(func(r *FanoutResult) {
			r.UnmatchedPatterns = []string{strings.Repeat("p", MaxGroupPatternBytes+1)}
		}), "at most"},
		{"unmatched pattern with control char", mutate(func(r *FanoutResult) {
			r.UnmatchedPatterns = []string{"gh\x1bost.*"}
		}), "control"},
		{"too many unmatched patterns", mutate(func(r *FanoutResult) {
			for i := 0; i <= MaxFanoutMembers; i++ {
				r.UnmatchedPatterns = append(r.UnmatchedPatterns, "ghost.*")
			}
		}), "unmatched patterns"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.r.Validate()
			if err == nil {
				t.Fatalf("invalid fanout accepted: %+v", tc.r)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

func TestFanoutResultMemberCountBounds(t *testing.T) {
	members := func(n int) []FanoutMember {
		out := make([]FanoutMember, 0, n)
		for i := 0; i < n; i++ {
			out = append(out, FanoutMember{
				Recipient: FanoutRecipient{PublicKey: "KEY-" + strings.Repeat("x", i%7)},
				Status:    FanoutSkipped, Reason: "not present",
			})
		}
		return out
	}
	if _, err := NewFanoutResult("g", FanoutActionSteer, members(1), nil); err != nil {
		t.Fatalf("1 member rejected: %v", err)
	}
	if _, err := NewFanoutResult("g", FanoutActionSteer, members(MaxFanoutMembers), nil); err != nil {
		t.Fatalf("%d members rejected: %v", MaxFanoutMembers, err)
	}
	if _, err := NewFanoutResult("g", FanoutActionSteer, members(MaxFanoutMembers+1), nil); err == nil {
		t.Fatalf("%d members accepted", MaxFanoutMembers+1)
	}
}

// TestFanoutResultJSONRoundTripAndNoAggregate proves the wire form carries the
// per-member truth unchanged and has NO top-level status/count field a
// presentation layer could mistake for an aggregate verdict.
func TestFanoutResultJSONRoundTripAndNoAggregate(t *testing.T) {
	res, err := NewFanoutResult("oncall", FanoutActionSteer, []FanoutMember{
		deliveredSteerMember("KEY-A"),
		{Recipient: FanoutRecipient{PublicKey: "KEY-B"}, Status: FanoutDenied, Reason: "not permitted for this backend"},
	}, []string{"pubkey:KEY-GONE"})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	var back FanoutResult
	if err := json.Unmarshal(encoded, &back); err != nil {
		t.Fatal(err)
	}
	if err := back.Validate(); err != nil {
		t.Fatalf("round-tripped result invalid: %v", err)
	}
	if len(back.Members) != 2 || back.Members[0].Status != FanoutDelivered || back.Members[1].Status != FanoutDenied {
		t.Fatalf("round trip lost member truth: %+v", back.Members)
	}
	if back.Members[0].Steer == nil || back.Members[0].Steer.Backend != "fs" {
		t.Fatalf("round trip lost steer detail: %+v", back.Members[0])
	}
	if len(back.UnmatchedPatterns) != 1 || back.UnmatchedPatterns[0] != "pubkey:KEY-GONE" {
		t.Fatalf("round trip lost the unmatched echo: %v", back.UnmatchedPatterns)
	}

	var top map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &top); err != nil {
		t.Fatal(err)
	}
	for key := range top {
		switch key {
		case "schema", "group", "action", "members", "unmatched_patterns":
			// unmatched_patterns is resolution metadata (what matched nothing),
			// never a status/count over member outcomes.
		default:
			t.Fatalf("unexpected top-level field %q — the envelope must carry no aggregate verdict", key)
		}
	}
}

func TestValidateGroupName(t *testing.T) {
	if err := ValidateGroupName("oncall-team.a_b"); err != nil {
		t.Fatalf("valid name rejected: %v", err)
	}
	for name, bad := range map[string]string{
		"empty":      "",
		"padded":     " oncall ",
		"colon":      "group:x",
		"control":    "on\x1b[31mcall",
		"over-bound": strings.Repeat("g", MaxGroupNameBytes+1),
	} {
		if err := ValidateGroupName(bad); err == nil {
			t.Fatalf("%s group name %q accepted", name, bad)
		}
	}
}
