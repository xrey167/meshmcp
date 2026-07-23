package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xrey167/meshmcp/air"
)

func TestParseAirSendArgs(t *testing.T) {
	got, err := parseAirSendArgs([]string{
		"192.0.2.1:9600", "--to", "Analyst", "--text", "hello",
		"--file", "one.txt", "--file", "two.txt", "--name", "brief.txt",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.control != "192.0.2.1:9600" || got.to != "Analyst" || got.text != "hello" || got.name != "brief.txt" {
		t.Fatalf("parsed options = %+v", got)
	}
	if strings.Join(got.files, ",") != "one.txt,two.txt" {
		t.Fatalf("files = %v", got.files)
	}

	for _, tc := range []struct {
		name string
		args []string
	}{
		{name: "missing control", args: []string{"--to", "Analyst", "--text", "hello"}},
		{name: "missing selector", args: []string{"192.0.2.1:9600", "--text", "hello"}},
		{name: "bad stdin bound", args: []string{"192.0.2.1:9600", "--to", "Analyst", "--max-bytes", "0"}},
		{name: "oversized stdin bound", args: []string{"192.0.2.1:9600", "--to", "Analyst", "--max-bytes", "8388609"}},
		{name: "empty file", args: []string{"192.0.2.1:9600", "--to", "Analyst", "--file", ""}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseAirSendArgs(tc.args); err == nil {
				t.Fatal("expected argument error")
			}
		})
	}
}

func TestAirSendUsageShowsRepeatableFilesAndNames(t *testing.T) {
	var out bytes.Buffer
	writeAirSendUsage(&out)
	text := out.String()
	for _, want := range []string{"--name name", "--file path", "repeatable", "receiver-confirmed", "64 MiB total"} {
		if !strings.Contains(text, want) {
			t.Fatalf("air send help missing %q:\n%s", want, text)
		}
	}
}

func TestResolveAirInbox(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/presence" {
			t.Errorf("request = %s %s", r.Method, r.URL.Path)
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		_, _ = io.WriteString(w, `{"presence":[{"version":"air.presence/v1","name":"Analyst","kind":"agent","status":"available","labels":[],"services":[{"kind":"inbox","port":9110,"protocol":"tcp","capabilities":["drop.complete.v1"],"address":"203.0.113.9:9110"}],"public_key":"K","fqdn":"analyst.mesh","ip":"203.0.113.9","seen_at":"2026-07-22T12:00:00Z","expires_at":"2026-07-22T12:01:30Z"}]}`)
	}))
	defer srv.Close()
	hc := srv.Client()
	hc.Transport = rewriteTransport{base: srv.URL, next: hc.Transport}

	resolved, err := resolveAirInbox(context.Background(), hc, "Analyst")
	if err != nil {
		t.Fatal(err)
	}
	if resolved.Node.PublicKey != "K" || resolved.Service.Kind != air.ServiceInbox || resolved.Service.Address != "203.0.113.9:9110" {
		t.Fatalf("resolved = %+v", resolved)
	}
	if _, err := resolveAirInbox(context.Background(), hc, "Missing"); err == nil {
		t.Fatal("missing selector resolved")
	}
}

func TestResolveAirInboxRejectsSelectorBeforeControlIO(t *testing.T) {
	called := false
	hc := &http.Client{Transport: airRoundTripFunc(func(*http.Request) (*http.Response, error) {
		called = true
		return nil, errors.New("unexpected request")
	})}
	if _, err := resolveAirInbox(context.Background(), hc, "unsafe\u0085selector"); err == nil {
		t.Fatal("invalid selector was accepted")
	}
	if called {
		t.Fatal("invalid selector reached the control endpoint")
	}
}

func TestResolvedAirDeliveryRejectsSelectorBeforeSnapshot(t *testing.T) {
	app := &meshApp{}
	_, err := app.sendResolvedAirDelivery(context.Background(), "unsafe\u0085selector", airDelivery{
		files: []string{filepath.Join(t.TempDir(), "missing")},
	})
	if err == nil || !strings.Contains(err.Error(), "selector") {
		t.Fatalf("early selector validation = %v", err)
	}
}

func TestAppInboxRecipientValidatesLegacyTarget(t *testing.T) {
	app := &meshApp{}
	recipient, err := app.appInboxRecipient(context.Background(), "203.0.113.9:9110", "")
	if err != nil {
		t.Fatal(err)
	}
	if recipient.Address != "203.0.113.9:9110" || recipient.PublicKey != "" {
		t.Fatalf("legacy recipient = %+v", recipient)
	}
	for _, target := range []string{"host:0", "host:70000", "host:nope"} {
		if _, err := app.appInboxRecipient(context.Background(), target, ""); err == nil {
			t.Errorf("invalid target %q was accepted", target)
		}
	}
}

func TestPrepareAirDeliveryUsesBoundedStdinFallback(t *testing.T) {
	opts := airSendOptions{to: "Analyst", maxBytes: 4}
	delivery, err := prepareAirDelivery(opts, strings.NewReader("note"), time.Unix(42, 0))
	if err != nil {
		t.Fatal(err)
	}
	if string(delivery.text) != "note" || delivery.textName != "clip-42.txt" {
		t.Fatalf("delivery = %+v", delivery)
	}
	if _, err := prepareAirDelivery(opts, strings.NewReader(""), time.Unix(42, 0)); err == nil {
		t.Fatal("empty stdin was accepted")
	}
	if _, err := prepareAirDelivery(opts, strings.NewReader("large"), time.Unix(42, 0)); err == nil {
		t.Fatal("oversized stdin was accepted")
	}
	overflow := opts
	overflow.maxBytes = int64(^uint64(0) >> 1)
	if _, err := prepareAirDelivery(overflow, strings.NewReader("note"), time.Unix(42, 0)); err == nil {
		t.Fatal("overflowing stdin bound was accepted")
	}
}

func TestSnapshotAirDeliveryBoundsSelectedFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "large.txt")
	if err := os.WriteFile(path, []byte("large"), 0o600); err != nil {
		t.Fatal(err)
	}
	tight := airDeliveryBounds{perItemBytes: 4, totalBytes: 8, payloads: 2}
	if _, err := snapshotAirDelivery(airDelivery{files: []string{path}}, tight); err == nil {
		t.Fatal("oversized selected file was accepted")
	}
	if _, err := snapshotAirDelivery(airDelivery{}, tight); err == nil {
		t.Fatal("empty delivery was accepted")
	}
	if _, err := snapshotAirDelivery(airDelivery{files: []string{"a", "b", "c"}}, tight); err == nil {
		t.Fatal("selected path count limit was not enforced")
	}
	for _, name := range []string{strings.Repeat("x", air.MaxActionPayloadNameBytes+1), "bad\nname", `..\secret`} {
		if _, err := snapshotAirDelivery(airDelivery{text: []byte("x"), textName: name}, tight); err == nil {
			t.Fatalf("invalid payload name %q was accepted", name)
		}
	}
	missing := filepath.Join(dir, "private-source-name.txt")
	if _, err := snapshotAirDelivery(airDelivery{files: []string{missing}}, tight); err == nil {
		t.Fatal("missing selected path was accepted")
	} else if strings.Contains(err.Error(), missing) {
		t.Fatalf("error leaked source path: %v", err)
	}
	one := filepath.Join(dir, "one.txt")
	two := filepath.Join(dir, "two.txt")
	if err := os.WriteFile(one, []byte("one"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(two, []byte("two"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := snapshotAirDelivery(airDelivery{
		text: []byte("x"), textName: "ONE.TXT", files: []string{one},
	}, tight); err == nil {
		t.Fatal("case-insensitive destination name collision was accepted")
	}
	if _, err := snapshotAirDelivery(airDelivery{files: []string{one, two}}, airDeliveryBounds{
		perItemBytes: 4, totalBytes: 5, payloads: 2,
	}); err == nil {
		t.Fatal("aggregate byte limit was not enforced")
	}
	if _, err := snapshotAirDelivery(airDelivery{files: []string{one, two}}, airDeliveryBounds{
		perItemBytes: 4, totalBytes: 8, payloads: 1,
	}); err == nil {
		t.Fatal("payload count limit was not enforced")
	}
	link := filepath.Join(dir, "link.txt")
	if err := os.Symlink(one, link); err != nil {
		t.Logf("symlink unavailable on this platform: %v", err)
		return
	}
	if _, err := snapshotAirDelivery(airDelivery{files: []string{link}}, tight); err == nil {
		t.Fatal("top-level symbolic link was accepted")
	}
}

func TestWriteAirDeliveryUsesOneImmutableSnapshot(t *testing.T) {
	source := t.TempDir()
	path := filepath.Join(source, "report.txt")
	if err := os.WriteFile(path, []byte("file body"), 0o600); err != nil {
		t.Fatal(err)
	}

	var wire bytes.Buffer
	delivery := airDelivery{
		text:     []byte("short note"),
		textName: "note.txt",
		files:    []string{path},
	}
	snapshot, err := snapshotAirDelivery(delivery, defaultAirDeliveryBounds)
	if err != nil {
		t.Fatal(err)
	}
	defer snapshot.close()
	result, err := buildAirSendResult(snapshot.payloads, air.ActionRecipient{
		Name: "Analyst", PublicKey: "K", Service: air.ServiceInbox, Address: "203.0.113.9:9110",
	}, time.Unix(42, 0))
	if err != nil {
		t.Fatal(err)
	}
	if result.Payloads != 2 || result.Bytes != int64(len("short note")+len("file body")) || len(result.Receipts) != 2 {
		t.Fatalf("result = %+v", result)
	}
	if result.Schema != air.ActionResultSchemaV1 || result.Receipts[0].Schema != air.ActionReceiptSchemaV1 {
		t.Fatalf("result schemas = %q / %q", result.Schema, result.Receipts[0].Schema)
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte("short note")) || bytes.Contains(encoded, []byte(source)) {
		t.Fatalf("receipt leaked payload or source path: %s", encoded)
	}
	// Mutating the selected source after preflight cannot change the bytes or
	// metadata delivered from the private snapshot.
	if err := os.WriteFile(path, []byte("changed after selection"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeAirDelivery(&wire, snapshot.delivery); err != nil {
		t.Fatal(err)
	}

	dest := t.TempDir()
	var received []recvInfo
	if err := recvFiles(&wire, dirPlacer(dest), dropLimits{}, func(info recvInfo) {
		received = append(received, info)
	}); err != nil {
		t.Fatal(err)
	}
	if len(received) != 2 || received[0].Name != "note.txt" || received[1].Name != "report.txt" {
		t.Fatalf("received = %+v", received)
	}
	for name, want := range map[string]string{"note.txt": "short note", "report.txt": "file body"} {
		got, err := os.ReadFile(filepath.Join(dest, name))
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != want {
			t.Fatalf("%s = %q, want %q", name, got, want)
		}
	}
}

func TestSnapshotAirDeliveryFreezesDirectoryMembership(t *testing.T) {
	parent := t.TempDir()
	source := filepath.Join(parent, "briefing")
	if err := os.MkdirAll(filepath.Join(source, "notes"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "notes", "one.txt"), []byte("one"), 0o600); err != nil {
		t.Fatal(err)
	}
	snapshot, err := snapshotAirDelivery(airDelivery{files: []string{source}}, defaultAirDeliveryBounds)
	if err != nil {
		t.Fatal(err)
	}
	defer snapshot.close()
	if err := os.WriteFile(filepath.Join(source, "late.txt"), []byte("late"), 0o600); err != nil {
		t.Fatal(err)
	}

	result, err := buildAirSendResult(snapshot.payloads, air.ActionRecipient{
		Name: "Analyst", PublicKey: "K", Service: air.ServiceInbox, Address: "203.0.113.9:9110",
	}, time.Unix(42, 0))
	if err != nil {
		t.Fatal(err)
	}
	if result.Payloads != 1 || result.Receipts[0].PayloadName != "briefing/notes/one.txt" {
		t.Fatalf("directory result = %+v", result)
	}
	var wire bytes.Buffer
	if err := writeAirDelivery(&wire, snapshot.delivery); err != nil {
		t.Fatal(err)
	}
	var received []recvInfo
	if err := recvFiles(&wire, dirPlacer(t.TempDir()), dropLimits{}, func(info recvInfo) {
		received = append(received, info)
	}); err != nil {
		t.Fatal(err)
	}
	if len(received) != 1 || received[0].Name != "briefing/notes/one.txt" {
		t.Fatalf("directory delivery = %+v", received)
	}
}
