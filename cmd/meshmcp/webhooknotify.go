package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// webhookNotifier delivers push-wake notifications by POSTing them to an
// operator-supplied HTTPS endpoint — a self-hosted relay, an ntfy/Pushover/Slack
// incoming hook, or a small function that fans out to APNs/FCM with the
// operator's own credentials. It is the credentialed vendor delivery's stand-in
// that still ships in-repo: unlike logNotifier it actually leaves the process,
// but it needs no Apple/Google keys of its own.
//
// The endpoint receives, as application/json:
//
//	{"title": "...", "body": "...", "devices": [{"identity","token","platform"}, ...]}
//
// so the relay can route each device token to the right vendor. Delivery is
// synchronous with a short timeout: Notify is already called off the enforcement
// path (only when a co-sign becomes pending), and the approvals caller ignores
// the return, so a slow or failing endpoint cannot stall a decision.
type webhookNotifier struct {
	url    string
	client *http.Client
}

func newWebhookNotifier(url string) webhookNotifier {
	return webhookNotifier{url: url, client: &http.Client{Timeout: 10 * time.Second}}
}

// webhookPush is the JSON body delivered to the webhook endpoint.
type webhookPush struct {
	Title   string   `json:"title"`
	Body    string   `json:"body"`
	Devices []Device `json:"devices"`
}

func (n webhookNotifier) Notify(devices []Device, title, body string) error {
	payload, err := json.Marshal(webhookPush{Title: title, Body: body, Devices: devices})
	if err != nil {
		return err
	}
	resp, err := n.client.Post(n.url, "application/json", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("push webhook %s: status %d", n.url, resp.StatusCode)
	}
	return nil
}
