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
