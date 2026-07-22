package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/xrey167/meshmcp/air"
)

func TestPresenceFlagsBuildActivityAndServices(t *testing.T) {
	fs := flag.NewFlagSet("presence", flag.ContinueOnError)
	p := bindPresenceFlags(fs)
	if err := fs.Parse([]string{
		"--name", "Code Agent", "--kind", "agent", "--label", "developer",
		"--service", "steer=9120,task,nudge", "--service", "home=9800/http",
		"--activity-id", "auth-flow", "--activity-title", "Implement auth flow",
		"--progress", "68", "--activity-target", "task:auth-flow", "--revision", "3",
	}); err != nil {
		t.Fatal(err)
	}
	a, err := p.announcement()
	if err != nil {
		t.Fatal(err)
	}
	if a.Version != air.PresenceSchema || a.Name != "Code Agent" || len(a.Services) != 2 {
		t.Fatalf("announcement lost fields: %+v", a)
	}
	if a.Services[0].Kind != air.ServiceHome || a.Services[0].Protocol != "http" || a.Services[1].Kind != air.ServiceSteer {
		t.Fatalf("services not normalized into stable order: %+v", a.Services)
	}
	if a.Activity == nil || a.Activity.Progress == nil || *a.Activity.Progress != 68 || a.Activity.Revision != 3 {
		t.Fatalf("activity not built: %+v", a.Activity)
	}
}

func TestPresenceFlagsRejectIncompleteActivity(t *testing.T) {
	fs := flag.NewFlagSet("presence", flag.ContinueOnError)
	p := bindPresenceFlags(fs)
	if err := fs.Parse([]string{"--name", "Agent", "--activity-title", "Missing id"}); err != nil {
		t.Fatal(err)
	}
	if _, err := p.announcement(); err == nil || !strings.Contains(err.Error(), "activity-id") {
		t.Fatalf("incomplete Activity = %v, want validation error", err)
	}
}

func TestParsePresenceService(t *testing.T) {
	svc, err := parsePresenceService("ring=9130/https,urgent")
	if err != nil {
		t.Fatal(err)
	}
	if svc.Kind != air.ServiceRing || svc.Port != 9130 || svc.Protocol != "https" || len(svc.Capabilities) != 1 {
		t.Fatalf("service = %+v", svc)
	}
	for _, bad := range []string{"ring", "ring=nope", "=9130"} {
		if _, err := parsePresenceService(bad); err == nil {
			t.Errorf("bad service %q was accepted", bad)
		}
	}
}

func TestParseAirControlFlagsAcceptsAdvertisedControlFirstForm(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
	}{
		{name: "control first", args: []string{"192.0.2.1:9600", "--name", "Code Agent", "--label", "code"}},
		{name: "flags first", args: []string{"--name", "Code Agent", "--label", "code", "192.0.2.1:9600"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fs := flag.NewFlagSet("air node", flag.ContinueOnError)
			name := fs.String("name", "", "")
			var labels multiFlag
			fs.Var(&labels, "label", "")
			control, err := parseAirControlFlags(fs, tc.args)
			if err != nil {
				t.Fatal(err)
			}
			if control != "192.0.2.1:9600" || *name != "Code Agent" || len(labels) != 1 || labels[0] != "code" {
				t.Fatalf("control=%q name=%q labels=%v", control, *name, labels)
			}
		})
	}
}

func TestPresenceHTTPHelpers(t *testing.T) {
	var methods []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		methods = append(methods, r.Method)
		switch r.Method {
		case http.MethodGet:
			_, _ = io.WriteString(w, `{"presence":[],"you":"phone.mesh"}`)
		case http.MethodPost:
			var a air.Announcement
			if err := json.NewDecoder(r.Body).Decode(&a); err != nil || a.Name != "Code Agent" {
				t.Errorf("posted announcement = %+v err=%v", a, err)
			}
			_, _ = io.WriteString(w, `{"status":"present","changed":true,"presence":{"version":"air.presence/v1","name":"Code Agent","kind":"agent","status":"available","labels":[],"services":[],"public_key":"K","ip":"192.0.2.1","seen_at":"2026-07-22T12:00:00Z","expires_at":"2026-07-22T12:01:30Z"}}`)
		case http.MethodDelete:
			_, _ = io.WriteString(w, `{"status":"left","removed":true}`)
		}
	}))
	defer srv.Close()

	hc := srv.Client()
	// The helpers intentionally use a stable logical URL. Rewrite it to this
	// httptest server while preserving method/body behavior.
	hc.Transport = rewriteTransport{base: srv.URL, next: hc.Transport}
	out, err := fetchPresence(context.Background(), hc)
	if err != nil || out.You != "phone.mesh" || out.Presence == nil {
		t.Fatalf("fetch = %+v err=%v", out, err)
	}
	posted, err := postPresence(context.Background(), hc, air.Announcement{Version: air.PresenceSchema, Name: "Code Agent", Kind: air.NodeAgent})
	if err != nil || !posted.Changed || posted.Presence.PublicKey != "K" {
		t.Fatalf("post = %+v err=%v", posted, err)
	}
	if err := deletePresence(context.Background(), hc); err != nil {
		t.Fatal(err)
	}
	if strings.Join(methods, ",") != "GET,POST,DELETE" {
		t.Fatalf("methods = %v", methods)
	}
}

type rewriteTransport struct {
	base string
	next http.RoundTripper
}

func (r rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	clone.URL.Scheme = "http"
	clone.URL.Host = strings.TrimPrefix(r.base, "http://")
	return r.next.RoundTrip(clone)
}

func TestRenderNearbySanitizesRemoteValues(t *testing.T) {
	var buf bytes.Buffer
	renderNearby(&buf, presenceResponse{Presence: []air.Presence{{
		Name: "evil\x1b[2J", Kind: air.NodeAgent, Status: air.StatusAvailable,
		PublicKey: "K", FQDN: "evil\x1b[31m.mesh",
		Services: []air.Service{{Kind: air.ServiceSteer}},
		Activity: &air.Activity{State: air.ActivityRunning, Title: "task\x1b[H"},
	}}})
	if bytes.Contains(buf.Bytes(), []byte{0x1b}) {
		t.Fatalf("render leaked terminal escape: %q", buf.String())
	}
}
