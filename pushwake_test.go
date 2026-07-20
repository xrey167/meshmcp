package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/xrey167/meshmcp/policy"
)

// captureNotifier records the last Notify call for assertions.
type captureNotifier struct {
	devices []Device
	title   string
	body    string
	calls   int
}

func (c *captureNotifier) Notify(d []Device, title, body string) error {
	c.devices, c.title, c.body, c.calls = d, title, body, c.calls+1
	return nil
}

func TestDeviceStoreRoundTrip(t *testing.T) {
	s := &DeviceStore{Dir: t.TempDir()}
	if l, _ := s.List(""); len(l) != 0 {
		t.Fatal("new store not empty")
	}
	if err := s.Register(Device{Identity: "phone.mesh", Token: "tok1", Platform: "apns"}); err != nil {
		t.Fatal(err)
	}
	s.Register(Device{Identity: "phone.mesh", Token: "tok2", Platform: "fcm"}) // second device, same identity
	s.Register(Device{Identity: "other.mesh", Token: "tok3", Platform: "apns"})
	if l, _ := s.List(""); len(l) != 3 {
		t.Fatalf("want 3 devices, got %d", len(l))
	}
	if l, _ := s.List("phone.mesh"); len(l) != 2 {
		t.Fatalf("want 2 for phone.mesh, got %d", len(l))
	}
	// Re-register is idempotent (same identity+token → same file).
	s.Register(Device{Identity: "phone.mesh", Token: "tok1", Platform: "apns"})
	if l, _ := s.List(""); len(l) != 3 {
		t.Fatalf("re-register changed count: %d", len(l))
	}
	if err := s.Register(Device{Identity: "x"}); err == nil {
		t.Fatal("expected error registering device with no token")
	}
}

func TestPushWakeNotifiesOnRequest(t *testing.T) {
	dir := t.TempDir()
	ps := &policy.FilePending{Dir: dir}
	devs := &DeviceStore{Dir: t.TempDir()}
	cap := &captureNotifier{}
	h := approvalsHandler(ps, func(*http.Request) string { return "phone.mesh" }, nil, time.Now, withPushWake(devs, cap))

	// Register a device.
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/v1/devices", strings.NewReader(`{"token":"tok1","platform":"apns"}`)))
	if rr.Code != http.StatusOK {
		t.Fatalf("register status %d: %s", rr.Code, rr.Body)
	}

	// A new approval request should notify the registered device.
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/v1/request", strings.NewReader(`{"peer":"billing.mesh","tool":"transfer_funds"}`)))
	if rr.Code != http.StatusOK {
		t.Fatalf("request status %d: %s", rr.Code, rr.Body)
	}
	if cap.calls != 1 || len(cap.devices) != 1 || cap.devices[0].Token != "tok1" {
		t.Fatalf("notifier not called with device: calls=%d devices=%+v", cap.calls, cap.devices)
	}
	if !strings.Contains(cap.body, "transfer_funds") {
		t.Fatalf("notify body missing tool: %q", cap.body)
	}
}

func TestPushWakeDisabledWithoutDevices(t *testing.T) {
	// No withPushWake → /v1/devices is not registered.
	h := approvalsHandler(&policy.FilePending{Dir: t.TempDir()}, func(*http.Request) string { return "x" }, nil, time.Now)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/v1/devices", strings.NewReader(`{"token":"t"}`)))
	if rr.Code == http.StatusOK {
		t.Fatal("expected /v1/devices to be absent without push-wake")
	}
}
