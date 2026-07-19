package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Push-wake (the seam). A phone registers its push token by its mesh identity;
// when a co-sign request becomes pending, the approver's device(s) are notified
// so the phone buzzes instead of the page polling. The vendor delivery (APNs /
// FCM) is a pluggable Notifier — the registry, the wiring, and a logging
// Notifier ship here; the actual Apple/Google HTTP call is a small
// credentialed implementation that satisfies the same interface.

// Device is one registered push endpoint, owned by a mesh identity.
type Device struct {
	Identity string `json:"identity"` // caller's mesh FQDN (from the WireGuard key)
	Token    string `json:"token"`    // APNs / FCM device token
	Platform string `json:"platform"` // "apns" | "fcm"
}

// DeviceStore persists registered devices as one JSON file each in Dir.
type DeviceStore struct{ Dir string }

func (s *DeviceStore) path(d Device) string {
	sum := sha256.Sum256([]byte(d.Identity + "\x00" + d.Token))
	return filepath.Join(s.Dir, hex.EncodeToString(sum[:])+".json")
}

// Register records (or refreshes) a device. Idempotent per (identity, token).
func (s *DeviceStore) Register(d Device) error {
	if d.Identity == "" || d.Token == "" {
		return fmt.Errorf("device identity and token are required")
	}
	if err := os.MkdirAll(s.Dir, 0o755); err != nil {
		return err
	}
	b, _ := json.Marshal(d)
	tmp := s.path(d) + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path(d))
}

// List returns every registered device (optionally only those owned by identity).
func (s *DeviceStore) List(identity string) ([]Device, error) {
	entries, err := os.ReadDir(s.Dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []Device
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(s.Dir, e.Name()))
		if err != nil {
			continue
		}
		var d Device
		if json.Unmarshal(b, &d) == nil && d.Token != "" {
			if identity == "" || d.Identity == identity {
				out = append(out, d)
			}
		}
	}
	return out, nil
}

// Notifier delivers a push to the given devices. logNotifier ships; an APNs/FCM
// implementation (needs vendor credentials) plugs into the same interface.
type Notifier interface {
	Notify(devices []Device, title, body string) error
}

// logNotifier writes what would be pushed to w — the default, credential-free
// Notifier, so the seam is exercisable end-to-end without APNs/FCM.
type logNotifier struct{ w io.Writer }

func (n logNotifier) Notify(devices []Device, title, body string) error {
	for _, d := range devices {
		fmt.Fprintf(n.w, "push-wake → %s (%s): %s — %s\n", d.Identity, d.Platform, title, body)
	}
	return nil
}
