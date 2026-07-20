package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWebhookNotifierDelivers(t *testing.T) {
	var got webhookPush
	var gotCT, gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotCT = r.Header.Get("Content-Type")
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &got)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	n := newWebhookNotifier(srv.URL)
	devs := []Device{
		{Identity: "alice.mesh", Token: "tok-a", Platform: "apns"},
		{Identity: "bob.mesh", Token: "tok-b", Platform: "fcm"},
	}
	if err := n.Notify(devs, "approval needed", "billing.mesh wants wire"); err != nil {
		t.Fatalf("Notify: %v", err)
	}

	if gotMethod != http.MethodPost {
		t.Errorf("method = %q, want POST", gotMethod)
	}
	if gotCT != "application/json" {
		t.Errorf("content-type = %q, want application/json", gotCT)
	}
	if got.Title != "approval needed" || got.Body != "billing.mesh wants wire" {
		t.Errorf("title/body did not round-trip: %+v", got)
	}
	if len(got.Devices) != 2 || got.Devices[0].Token != "tok-a" || got.Devices[1].Platform != "fcm" {
		t.Errorf("device list did not round-trip: %+v", got.Devices)
	}
}

func TestWebhookNotifierErrorsOnNon2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	n := newWebhookNotifier(srv.URL)
	if err := n.Notify([]Device{{Identity: "x", Token: "t", Platform: "apns"}}, "t", "b"); err == nil {
		t.Fatal("expected an error on a 503 response, got nil")
	}
}

func TestWebhookNotifierErrorsOnUnreachable(t *testing.T) {
	// A closed server → transport error surfaces.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close()

	n := newWebhookNotifier(url)
	if err := n.Notify([]Device{{Identity: "x", Token: "t", Platform: "apns"}}, "t", "b"); err == nil {
		t.Fatal("expected a transport error to an unreachable endpoint, got nil")
	}
}
