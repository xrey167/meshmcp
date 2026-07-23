package main

import (
	"os"
	"syscall"
	"testing"
)

// TestShutdownSignalsIncludeTermAndInterrupt locks in the contract that every
// long-running command reacts to both Ctrl-C (SIGINT/os.Interrupt) and the
// SIGTERM that process supervisors (systemd, Docker, Kubernetes) send to stop a
// container — so a stop drains gracefully instead of being killed.
func TestShutdownSignalsIncludeTermAndInterrupt(t *testing.T) {
	want := map[os.Signal]bool{os.Interrupt: false, syscall.SIGTERM: false}
	for _, s := range shutdownSignals {
		if _, ok := want[s]; ok {
			want[s] = true
		}
	}
	for sig, found := range want {
		if !found {
			t.Errorf("shutdownSignals is missing %v", sig)
		}
	}
}
