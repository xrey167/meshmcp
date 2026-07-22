package main

import (
	"context"
	"errors"
	"net"
	"reflect"
	"testing"
	"time"
)

// The workflow schema/parsing/validation/expansion tests live with the code, in
// air/workflow_test.go. These are the mesh-coupled runner tests.

func TestIsConnError(t *testing.T) {
	if isConnError(nil) {
		t.Fatal("nil is not a conn error")
	}
	if !isConnError(&net.OpError{Op: "dial", Err: errors.New("refused")}) {
		t.Fatal("net.OpError should be a conn error")
	}
	if isConnError(&httpStatusError{status: "403 Forbidden"}) {
		t.Fatal("a 4xx is a peer decision, not retryable")
	}
}

func TestRetryConnStopsOnTerminalError(t *testing.T) {
	calls := 0
	err := retryConn(context.Background(), time.Second, func() error {
		calls++
		return &httpStatusError{status: "404 Not Found"}
	})
	if calls != 1 {
		t.Fatalf("terminal error retried %d times, want 1", calls)
	}
	if err == nil {
		t.Fatal("expected the terminal error back")
	}
}

func TestRetryConnRetriesThenSucceeds(t *testing.T) {
	calls := 0
	err := retryConn(context.Background(), 5*time.Second, func() error {
		calls++
		if calls < 3 {
			return &net.OpError{Op: "dial", Err: errors.New("connection refused")}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("expected success after retries, got %v", err)
	}
	if calls != 3 {
		t.Fatalf("calls = %d, want 3", calls)
	}
}

// TestWorkflowLaunchCap proves the per-run launch cap refuses the launch that
// would exceed it, and that a released reservation frees a slot.
func TestWorkflowLaunchCap(t *testing.T) {
	r := &wfRun{vars: map[string]any{}}
	for i := 0; i < maxWorkflowLaunches; i++ {
		if err := r.reserveLaunch(); err != nil {
			t.Fatalf("reservation %d unexpectedly refused: %v", i, err)
		}
		r.recordLaunch(1000 + i)
	}
	if err := r.reserveLaunch(); err == nil {
		t.Fatalf("reservation beyond the cap must be refused")
	}
	r.releaseLaunch()
	if err := r.reserveLaunch(); err != nil {
		t.Fatalf("a slot freed by releaseLaunch must be reusable: %v", err)
	}
}

func TestWorkflowLaunchArgsPassesEverySteerAllow(t *testing.T) {
	launch := &launchStep{
		SteerPort:  9120,
		SteerAllow: []string{"operator.example.net", "pubkey:controller-key"},
		Interval:   "1s",
	}
	want := []string{
		"--steer-port", "9120",
		"--steer-allow", "operator.example.net",
		"--steer-allow", "pubkey:controller-key",
		"--interval", "1s",
	}
	if got := workflowLaunchArgs(launch); !reflect.DeepEqual(got, want) {
		t.Fatalf("workflowLaunchArgs() = %#v, want %#v", got, want)
	}
}
