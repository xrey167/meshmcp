package mcperror_test

import (
	"encoding/json"
	"testing"

	"github.com/xrey167/meshmcp/protocol/mcperror"
)

func TestUnsupportedProtocolVersionError(t *testing.T) {
	resp := mcperror.ErrorResponse{
		JSONRPC: "2.0",
		ID:      1,
		Error: *mcperror.New(
			mcperror.CodeUnsupportedProtocolVersion,
			"unsupported protocol version",
			mcperror.UnsupportedProtocolVersionData{
				Supported: []string{"2025-06-18"},
				Requested: "1999-01-01",
			},
		),
	}
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var probe struct {
		Error struct {
			Code int `json:"code"`
			Data struct {
				Supported []string `json:"supported"`
				Requested string   `json:"requested"`
			} `json:"data"`
		} `json:"error"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if probe.Error.Code != -32022 {
		t.Fatalf("code = %d", probe.Error.Code)
	}
	if probe.Error.Data.Requested != "1999-01-01" || len(probe.Error.Data.Supported) != 1 {
		t.Fatalf("data payload lost: %+v", probe.Error.Data)
	}
}

func TestErrorInterface(t *testing.T) {
	var e error = mcperror.New(mcperror.CodeInvalidParams, "bad params", nil)
	if e.Error() != "bad params" {
		t.Fatalf("Error() = %q", e.Error())
	}
}
