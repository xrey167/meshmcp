package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// TestAirLaunchGate: the air_launch tool is disabled unless --allow-launch was set.
func TestAirLaunchGate(t *testing.T) {
	off := &meshApp{allowLaunch: false}
	res, _ := off.toolAirLaunch(context.Background(), json.RawMessage(`{"role":"reader","gateway":"1.2.3.4:9101"}`))
	if !res.IsError || !strings.Contains(res.Content[0].Text, "disabled") {
		t.Fatalf("expected disabled error, got %+v", res)
	}

	// Enabled but bad args → validation error (does not spawn).
	on := &meshApp{allowLaunch: true}
	res, _ = on.toolAirLaunch(context.Background(), json.RawMessage(`{"role":"reader"}`))
	if !res.IsError || !strings.Contains(res.Content[0].Text, "required") {
		t.Fatalf("expected role/gateway required error, got %+v", res)
	}
	// Enabled + unknown role → spawnAgent rejects before exec.
	res, _ = on.toolAirLaunch(context.Background(), json.RawMessage(`{"role":"nope","gateway":"1.2.3.4:9101"}`))
	if !res.IsError {
		t.Fatalf("expected unknown-role error, got %+v", res)
	}
}

// TestAirToolsRequireMesh: the mesh-driving air tools fail cleanly when not joined.
func TestAirToolsRequireMesh(t *testing.T) {
	app := &meshApp{}
	// air_peers with no mesh.
	if r, _ := app.toolAirPeers(context.Background(), nil); !r.IsError {
		t.Fatal("air_peers should error without a mesh")
	}
	// air_push validation runs before the mesh check.
	if r, _ := app.toolAirPush(context.Background(), json.RawMessage(`{}`)); !r.IsError {
		t.Fatal("air_push should require target and text")
	}
	if r, _ := app.toolAirFetch(context.Background(), json.RawMessage(`{"target":"x","hash":"short"}`)); !r.IsError {
		t.Fatal("air_fetch should reject a non-sha256 hash")
	}
}

func TestAirSendToolValidation(t *testing.T) {
	app := &meshApp{}
	for _, tc := range []struct {
		name string
		want string
		call func() (string, bool)
	}{
		{
			name: "send requires recipient",
			want: "required",
			call: func() (string, bool) {
				r, _ := app.toolAirSend(context.Background(), json.RawMessage(`{"text":"hello"}`))
				return r.Content[0].Text, r.IsError
			},
		},
		{
			name: "send requires content",
			want: "required",
			call: func() (string, bool) {
				r, _ := app.toolAirSend(context.Background(), json.RawMessage(`{"to":"Analyst"}`))
				return r.Content[0].Text, r.IsError
			},
		},
		{
			name: "push rejects two recipient forms",
			want: "either",
			call: func() (string, bool) {
				r, _ := app.toolAirPush(context.Background(), json.RawMessage(`{"target":"203.0.113.9:9110","to":"Analyst","text":"hello"}`))
				return r.Content[0].Text, r.IsError
			},
		},
		{
			name: "drop rejects two recipient forms",
			want: "either",
			call: func() (string, bool) {
				r, _ := app.toolDropFile(context.Background(), json.RawMessage(`{"target":"203.0.113.9:9110","to":"Analyst","path":"report.txt"}`))
				return r.Content[0].Text, r.IsError
			},
		},
		{
			name: "resolved send is nil-safe without mesh",
			want: "not joined",
			call: func() (string, bool) {
				r, _ := app.toolAirSend(context.Background(), json.RawMessage(`{"to":"Analyst","text":"hello"}`))
				return r.Content[0].Text, r.IsError
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			message, isError := tc.call()
			if !isError || !strings.Contains(message, tc.want) {
				t.Fatalf("validation result = error:%v %q", isError, message)
			}
		})
	}
}

// TestAirCatalogRequiresControl proves air_catalog errors without a --control
// endpoint (no mesh / no control configured), rather than panicking.
func TestAirCatalogRequiresControl(t *testing.T) {
	app := &meshApp{}
	if r, _ := app.toolAirNearby(context.Background(), nil); !r.IsError {
		t.Fatal("air_nearby should error without a control endpoint")
	}
	if r, _ := app.toolAirCatalog(context.Background(), nil); !r.IsError {
		t.Fatal("air_catalog should error without a control endpoint")
	}
}
