package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// S60 — Control-Room multiplayer presence.

func heartbeat(t *testing.T, rs *roomServer, token, id, name string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/presence",
		strings.NewReader(fmt.Sprintf(`{"id":%q,"name":%q}`, id, name)))
	if token != "" {
		req.Header.Set("X-Room-Token", token)
	}
	rs.requireToken(rs.handlePresence)(rec, req)
	return rec
}

func TestRoomPresenceRequiresToken(t *testing.T) {
	rs := &roomServer{token: "sekrit"}
	if rec := heartbeat(t, rs, "", "tab1", "alice"); rec.Code != http.StatusForbidden {
		t.Fatalf("presence without the room token must be forbidden, got %d", rec.Code)
	}
	if rec := heartbeat(t, rs, "wrong", "tab1", "alice"); rec.Code != http.StatusForbidden {
		t.Fatalf("presence with a bad token must be forbidden, got %d", rec.Code)
	}
	if rec := heartbeat(t, rs, "sekrit", "tab1", "alice"); rec.Code != http.StatusOK {
		t.Fatalf("presence with the token should be accepted, got %d: %s", rec.Code, rec.Body)
	}
}

func TestRoomPresenceRosterRidesTheFeed(t *testing.T) {
	rs := &roomServer{token: "sekrit", auditPath: "does-not-exist.jsonl"}
	heartbeat(t, rs, "sekrit", "tab1", "alice")
	heartbeat(t, rs, "sekrit", "tab2", "bob")
	heartbeat(t, rs, "sekrit", "tab1", "alice") // re-heartbeat upserts, not duplicates

	rec := httptest.NewRecorder()
	rs.handleRoom(rec, httptest.NewRequest("GET", "/api/room", nil))
	var feed struct {
		Viewers []struct {
			Name string `json:"name"`
			Idle int    `json:"idle"`
		} `json:"viewers"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &feed); err != nil {
		t.Fatalf("bad feed json: %v\n%s", err, rec.Body)
	}
	if len(feed.Viewers) != 2 {
		t.Fatalf("expected 2 viewers, got %+v", feed.Viewers)
	}
	if feed.Viewers[0].Name != "alice" || feed.Viewers[1].Name != "bob" {
		t.Fatalf("roster wrong (want sorted alice,bob): %+v", feed.Viewers)
	}
}

func TestRoomPresenceExpires(t *testing.T) {
	rs := &roomServer{token: "sekrit"}
	heartbeat(t, rs, "sekrit", "tab1", "alice")
	rs.vmu.Lock()
	rs.viewers["tab1"].lastSeen = time.Now().Add(-presenceTTL - time.Second)
	rs.vmu.Unlock()
	if got := rs.viewerRoster(time.Now()); len(got) != 0 {
		t.Fatalf("stale viewer should have been swept, got %+v", got)
	}
}

func TestRoomPresenceInputHardening(t *testing.T) {
	rs := &roomServer{token: "sekrit"}
	// Missing id → 400.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/presence", strings.NewReader(`{"name":"x"}`))
	req.Header.Set("X-Room-Token", "sekrit")
	rs.requireToken(rs.handlePresence)(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("missing id should be 400, got %d", rec.Code)
	}
	// Over-long name is clipped; empty name defaults.
	heartbeat(t, rs, "sekrit", "tab1", strings.Repeat("n", 100))
	heartbeat(t, rs, "sekrit", "tab2", "  ")
	roster := rs.viewerRoster(time.Now())
	for _, v := range roster {
		if len(v.Name) > 32 || v.Name == "" {
			t.Fatalf("name not sanitized: %+v", roster)
		}
	}
	// Roster is capped: a flood of fresh ids cannot grow it unbounded.
	for i := 0; i < maxViewers+10; i++ {
		heartbeat(t, rs, "sekrit", fmt.Sprintf("flood-%d", i), "f")
	}
	if got := len(rs.viewerRoster(time.Now())); got > maxViewers {
		t.Fatalf("roster exceeded the cap: %d > %d", got, maxViewers)
	}
	// A known id still heartbeats fine at the cap.
	if rec := heartbeat(t, rs, "sekrit", "tab1", "alice"); rec.Code != http.StatusOK {
		t.Fatalf("existing viewer refused at cap: %d", rec.Code)
	}
}
