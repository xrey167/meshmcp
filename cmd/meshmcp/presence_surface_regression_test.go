package main

import (
	"encoding/json"
	"flag"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xrey167/meshmcp/air"
)

const surfacePresenceJSON = `{"version":"air.presence/v1","name":"Surface Agent","kind":"agent","services":[{"kind":"steer","port":9120}]}`

// TestPresenceRouteRejectsTrailingOversizeAndSpoofedInput protects the HTTP
// trust boundary in addition to the air.Registry unit tests. The handler must
// consume exactly one bounded JSON value, derive addresses from RemoteAddr,
// and leave no card behind after any malformed announcement.
func TestPresenceRouteRejectsTrailingOversizeAndSpoofedInput(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		remoteAddr string
	}{
		{
			name:       "second JSON value",
			body:       surfacePresenceJSON + `{}`,
			remoteAddr: "192.0.2.44:5000",
		},
		{
			name:       "trailing non-JSON data",
			body:       surfacePresenceJSON + ` trailing`,
			remoteAddr: "192.0.2.44:5000",
		},
		{
			name:       "oversize unread suffix",
			body:       surfacePresenceJSON + strings.Repeat(" ", (32<<10)+1),
			remoteAddr: "192.0.2.44:5000",
		},
		{
			name: "claimed service address",
			body: `{"version":"air.presence/v1","name":"Surface Agent","kind":"agent",` +
				`"services":[{"kind":"steer","port":9120,"address":"203.0.113.8:9120"}]}`,
			remoteAddr: "192.0.2.44:5000",
		},
		{
			name:       "non-IP remote address",
			body:       surfacePresenceJSON,
			remoteAddr: "attacker.example:5000",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := &fakeAirControl{}
			var audits []airSteerAudit
			h := handlerWithIdentity(c, "verified-key", "surface.mesh", func(rec airSteerAudit) {
				audits = append(audits, rec)
			})
			rr := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/v1/presence", strings.NewReader(tc.body))
			req.RemoteAddr = tc.remoteAddr
			h.ServeHTTP(rr, req)

			if rr.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400: %s", rr.Code, rr.Body)
			}
			if got := c.nearby(time.Now()); len(got) != 0 {
				t.Fatalf("rejected announcement left registry state: %+v", got)
			}
			if len(audits) != 1 || audits[0].Method != "air/presence.announce" || audits[0].OK {
				t.Fatalf("rejected announcement audit = %+v", audits)
			}
		})
	}
}

func TestPresenceRouteAllowsTrailingWhitespaceAndIgnoresForwardedIP(t *testing.T) {
	c := &fakeAirControl{}
	h := handlerWithIdentity(c, "verified-key", "surface.mesh", nil)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/presence", strings.NewReader(surfacePresenceJSON+" \n\t"))
	req.RemoteAddr = "192.0.2.44:5000"
	req.Header.Set("X-Forwarded-For", "203.0.113.66")
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("valid single JSON value with whitespace = %d: %s", rr.Code, rr.Body)
	}
	cards := c.nearby(time.Now())
	if len(cards) != 1 || cards[0].IP != "192.0.2.44" || cards[0].Services[0].Address != "192.0.2.44:9120" {
		t.Fatalf("forwarded IP influenced stamped card: %+v", cards)
	}
}

func TestPresenceRouteAuditsRejectedDeleteAndUnsupportedMethod(t *testing.T) {
	c := &fakeAirControl{}
	var audits []airSteerAudit
	missingKey := handlerWithIdentity(c, "", "name-only.mesh", func(rec airSteerAudit) {
		audits = append(audits, rec)
	})
	rr := httptest.NewRecorder()
	missingKey.ServeHTTP(rr, httptest.NewRequest(http.MethodDelete, "/v1/presence", nil))
	if rr.Code != http.StatusForbidden {
		t.Fatalf("keyless DELETE = %d, want 403", rr.Code)
	}
	if len(audits) != 1 || audits[0].Method != "air/presence.leave" || audits[0].OK {
		t.Fatalf("keyless DELETE audit = %+v", audits)
	}

	audits = nil
	withKey := handlerWithIdentity(c, "verified-key", "surface.mesh", func(rec airSteerAudit) {
		audits = append(audits, rec)
	})
	rr = httptest.NewRecorder()
	withKey.ServeHTTP(rr, httptest.NewRequest(http.MethodPatch, "/v1/presence", nil))
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("PATCH presence = %d, want 405", rr.Code)
	}
	if len(audits) != 1 || audits[0].Method != "air/presence" || audits[0].OK {
		t.Fatalf("unsupported method audit = %+v", audits)
	}
}

// TestNearbyWatchSignatureIgnoresHeartbeatTimestamps exercises the exact
// material signature used by cmdAirNearby's watch loop. SeenAt/ExpiresAt move
// on every heartbeat; availability and Activity changes must still redraw.
func TestNearbyWatchSignatureIgnoresHeartbeatTimestamps(t *testing.T) {
	progress := 20
	card := air.Presence{
		Version: air.PresenceSchema, Name: "Watch Agent", Kind: air.NodeAgent, Status: air.StatusAvailable,
		PublicKey: "watch-key", FQDN: "watch.mesh", IP: "192.0.2.50",
		SeenAt: "2026-07-22T12:00:00.1Z", ExpiresAt: "2026-07-22T12:01:30.1Z",
		Services: []air.Service{{Kind: air.ServiceSteer, Port: 9120, Protocol: "tcp", Address: "192.0.2.50:9120"}},
		Activity: &air.Activity{
			Schema: air.ActivitySchema, ID: "watch-task", Kind: air.ActivityTask,
			Title: "Review", State: air.ActivityRunning, Progress: &progress,
		},
	}
	signature := func(p air.Presence) string {
		return (air.Home{Nearby: []air.Presence{p}}).Signature()
	}
	base := signature(card)

	heartbeat := card
	heartbeat.SeenAt = "2026-07-22T12:00:30.2Z"
	heartbeat.ExpiresAt = "2026-07-22T12:02:00.2Z"
	if got := signature(heartbeat); got != base {
		t.Fatalf("heartbeat-only timestamps changed watch signature: %s != %s", got, base)
	}

	material := heartbeat
	material.Status = air.StatusBusy
	if got := signature(material); got == base {
		t.Fatal("material status change did not change watch signature")
	}
	newProgress := 21
	material = heartbeat
	activity := *heartbeat.Activity
	activity.Progress = &newProgress
	material.Activity = &activity
	if got := signature(material); got == base {
		t.Fatal("Activity progress change did not change watch signature")
	}
}

func TestPresenceCLIRejectsOrphanServiceAndInvalidNegativeProgress(t *testing.T) {
	if err := cmdAirNearby([]string{"--service", "steer", "control.invalid:9999"}); err == nil || !strings.Contains(err.Error(), "only valid with --resolve") {
		t.Fatalf("orphan --service error = %v", err)
	}

	fs := flag.NewFlagSet("presence-negative-progress", flag.ContinueOnError)
	flags := bindPresenceFlags(fs)
	if err := fs.Parse([]string{"--name", "Agent", "--progress", "-2"}); err != nil {
		t.Fatal(err)
	}
	if _, err := flags.announcement(); err == nil || !strings.Contains(err.Error(), "--progress") {
		t.Fatalf("--progress -2 error = %v", err)
	}
}

// repeatedByteReader is an allocation-free infinite source used to exercise
// the Presence-list response bound without first constructing a 64 MiB slice.
type repeatedByteReader byte

func (r repeatedByteReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(r)
	}
	return len(p), nil
}

type oversizedPresenceTransport struct{}

func (oversizedPresenceTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	body := io.LimitReader(repeatedByteReader('x'), int64(maxPresenceListBytes)+1)
	return &http.Response{
		StatusCode: http.StatusOK,
		Status:     "200 OK",
		Header:     make(http.Header),
		Body:       io.NopCloser(body),
		Request:    req,
	}, nil
}

func TestAirServeNearbyOversizeFailsExplicitly(t *testing.T) {
	h := airServeHandler(airServeDeps{
		controlBase: "http://air-control",
		controlHC:   &http.Client{Transport: oversizedPresenceTransport{}},
	})
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/nearby", nil))
	if rr.Code != http.StatusBadGateway {
		t.Fatalf("oversize nearby response = %d, want 502: %s", rr.Code, rr.Body)
	}
	if !strings.Contains(rr.Body.String(), "too large") {
		t.Fatalf("oversize response lacks explicit error: %q", rr.Body.String())
	}
}

func TestAirServeHomePresenceRelayAttestsViewer(t *testing.T) {
	var sawPresence atomic.Bool
	control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/presence":
			sawPresence.Store(true)
			if got := r.Header.Get("X-Air-On-Behalf"); got != "phone.mesh" {
				t.Errorf("presence relay FQDN attestation = %q", got)
			}
			if got := r.Header.Get("X-Air-On-Behalf-Key"); got != "phone-key" {
				t.Errorf("presence relay key attestation = %q", got)
			}
			_, _ = io.WriteString(w, `{"presence":[{"version":"air.presence/v1","name":"Relayed Agent","kind":"agent","status":"available","labels":[],"services":[],"public_key":"agent-key","ip":"192.0.2.60","seen_at":"2026-07-22T12:00:00Z","expires_at":"2026-07-22T12:01:30Z"}]}`)
		case "/v1/sessions":
			_, _ = io.WriteString(w, `{"sessions":[]}`)
		case airCatalogPath:
			_, _ = io.WriteString(w, `{"service":"meshmcp","version":"test","endpoints":[]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer control.Close()

	h := airServeHandler(airServeDeps{
		controlBase: control.URL,
		controlHC:   control.Client(),
		identify: func(*http.Request) (string, string) {
			return "phone-key", "phone.mesh"
		},
	})
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/home", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("home status = %d: %s", rr.Code, rr.Body)
	}
	var home air.Home
	if err := json.Unmarshal(rr.Body.Bytes(), &home); err != nil {
		t.Fatal(err)
	}
	if !sawPresence.Load() || len(home.Nearby) != 1 || home.Nearby[0].Name != "Relayed Agent" {
		t.Fatalf("relayed Presence missing from Home: saw=%v nearby=%+v", sawPresence.Load(), home.Nearby)
	}
}

// TestAirLivePresenceWiring guards the otherwise easy-to-miss final hop from
// /api/home into the embedded page. These are static integration assertions:
// detailed DOM behavior belongs in a browser test, but a build should fail if
// Presence is no longer consumed, fallback peers are discarded, or heartbeat
// timestamps return to the visual diff signature.
func TestAirLivePresenceWiring(t *testing.T) {
	html := string(airLiveHTML)
	section := func(start, end string) string {
		t.Helper()
		startAt := strings.Index(html, start)
		if startAt < 0 {
			t.Fatalf("embedded Air page is missing %q", start)
		}
		endAt := strings.Index(html[startAt:], end)
		if endAt < 0 {
			t.Fatalf("embedded Air page has no %q after %q", end, start)
		}
		return html[startAt : startAt+endAt]
	}

	normalize := section("function normalizeNearby", "function serviceHints")
	if !strings.Contains(normalize, "array(peers).forEach") || !strings.Contains(normalize, "near.push") {
		t.Fatal("Nearby normalization no longer merges unannounced fallback peers with Presence cards")
	}
	render := section("function renderNearby", "function renderRecipients")
	if !strings.Contains(render, "JSON.stringify(nearbyCards.map") {
		t.Fatal("Nearby renderer no longer builds a material-card signature")
	}
	if strings.Contains(render, "seen_at") || strings.Contains(render, "expires_at") {
		t.Fatal("heartbeat timestamps leaked back into the Nearby visual signature")
	}
	if !strings.Contains(html, "renderNearby(d.nearby,d.peers)") {
		t.Fatal("/api/home Presence cards are not wired into the served Nearby renderer")
	}
}

// TestAirLiveUniversalActionsWiring protects the trust-sensitive final hop
// from a verified Presence card to the browser action payload. In particular,
// client-authored names and Activity targets must never select a session to
// steer, and logical delivery must keep using the durable public-key selector.
func TestAirLiveUniversalActionsWiring(t *testing.T) {
	html := string(airLiveHTML)
	section := func(start, end string) string {
		t.Helper()
		startAt := strings.Index(html, start)
		if startAt < 0 {
			t.Fatalf("embedded Air page is missing %q", start)
		}
		endAt := strings.Index(html[startAt:], end)
		if endAt < 0 {
			t.Fatalf("embedded Air page has no %q after %q", end, start)
		}
		return html[startAt : startAt+endAt]
	}

	for _, want := range []string{
		`id="actionDlg"`,
		`id="commandDlg"`,
		`Search agents, sessions, and actions`,
		`Verified destinations · actions remain policy governed`,
		`fetch("api/ring"`,
		`payload.recipient=recipient`,
		`form.append("recipient",recipient)`,
		`title:"Browse reachable services"`,
		`tabindex="-1"`,
		`maxlength="500"`,
	} {
		if !strings.Contains(html, want) {
			t.Errorf("Universal Actions page is missing %q", want)
		}
	}

	selector := section("function selectorForNode", "function sameVerifiedNode")
	if !strings.Contains(selector, `return "pubkey:"+String(key)`) {
		t.Fatal("logical actions no longer prefer the durable full public-key selector")
	}

	for name, body := range map[string]string{
		"sessionForNode":  section("function sessionForNode", "function actionsForNode"),
		"matchingSession": section("function matchingSession", "function updateSummary"),
	} {
		if strings.Contains(body, "n.name") || strings.Contains(body, "activity.target") || strings.Contains(body, `"session:"`) {
			t.Errorf("%s uses client-authored Presence metadata to select a steerable session", name)
		}
		if !strings.Contains(body, "n.fqdn") || !strings.Contains(body, "n.public_key") || !strings.Contains(body, "n.ip") {
			t.Errorf("%s no longer associates sessions through transport-stamped identities", name)
		}
	}
}
