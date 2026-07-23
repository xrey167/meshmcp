package main

import (
	"encoding/json"
	"testing"

	"github.com/xrey167/meshmcp/mcpclient"
)

func TestFilterPeerRows(t *testing.T) {
	rows := []peerRow{
		{IP: "100.1.1.1", FQDN: "a.mesh", PubKey: "keyA", Status: "connected", Connected: true},
		{IP: "100.1.1.2", FQDN: "b.mesh", PubKey: "keyB", Status: "idle", Connected: false},
	}
	if got := filterPeerRows(rows, false); len(got) != 1 || got[0].FQDN != "a.mesh" {
		t.Fatalf("connected-only: %+v", got)
	}
	if got := filterPeerRows(rows, true); len(got) != 2 {
		t.Fatalf("all: %+v", got)
	}
	if got := filterPeerRows(nil, false); got != nil {
		t.Fatalf("empty: %+v", got)
	}
}

func TestPeerRowJSONShape(t *testing.T) {
	b, err := json.Marshal(peerRow{IP: "100.1.1.1", FQDN: "a.mesh", PubKey: "keyA", Status: "connected", Connected: true})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"ip", "fqdn", "pubkey", "status", "connected"} {
		if _, ok := m[k]; !ok {
			t.Fatalf("missing key %q in %s", k, b)
		}
	}
}

func TestMarshalLsOutput(t *testing.T) {
	// Nil slices must serialize as [] so consumers can iterate unconditionally.
	b, err := marshalLsOutput(lsOutput{})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"tools", "resources", "prompts"} {
		v, ok := m[k]
		if !ok {
			t.Fatalf("missing key %q in %s", k, b)
		}
		if string(v) == "null" {
			t.Fatalf("key %q is null, want []", k)
		}
	}

	b, err = marshalLsOutput(lsOutput{Tools: []mcpclient.Tool{{Name: "echo", Description: "say it back"}}})
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		Tools []struct {
			Name string `json:"name"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Tools) != 1 || out.Tools[0].Name != "echo" {
		t.Fatalf("tools round-trip: %s", b)
	}
}
