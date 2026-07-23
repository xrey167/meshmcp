package main

import (
	"io"
	"net"
	"net/http"
	"os"
	"runtime"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// TestServeGracefullyDrainsOnSignal proves the shared shutdown seam: a SIGTERM
// while a request is in flight lets that request finish (drain, not kill),
// returns nil (a signal stop is a clean stop), and runs the onStop hooks —
// the contract every previously signal-less server command now inherits.
func TestServeGracefullyDrainsOnSignal(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("sending SIGTERM to self is not supported on Windows")
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	inHandler := make(chan struct{})
	mux := http.NewServeMux()
	mux.HandleFunc("/slow", func(w http.ResponseWriter, r *http.Request) {
		close(inHandler)
		time.Sleep(300 * time.Millisecond) // still running when the signal lands
		_, _ = io.WriteString(w, "done")
	})

	var stopped atomic.Bool
	served := make(chan error, 1)
	go func() {
		served <- serveGracefully(&http.Server{Handler: mux}, ln, func() { stopped.Store(true) })
	}()

	// Fire a request that will be mid-flight when the signal arrives.
	resc := make(chan string, 1)
	go func() {
		resp, err := http.Get("http://" + ln.Addr().String() + "/slow")
		if err != nil {
			resc <- "error: " + err.Error()
			return
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		resc <- string(b)
	}()

	<-inHandler // the handler is running — now stop the server
	p, _ := os.FindProcess(os.Getpid())
	if err := p.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("signal self: %v", err)
	}

	// The in-flight request must complete (drained, not killed).
	select {
	case body := <-resc:
		if body != "done" {
			t.Fatalf("in-flight request did not drain cleanly: %q", body)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("in-flight request never completed")
	}
	// The server must return nil (clean signal stop) and run onStop.
	select {
	case err := <-served:
		if err != nil {
			t.Fatalf("signal stop returned %v, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serveGracefully never returned after SIGTERM")
	}
	if !stopped.Load() {
		t.Fatal("onStop hook did not run")
	}
}

// TestServeGracefullyReturnsServeError proves a server failure (here: a closed
// listener) surfaces as an error rather than hanging waiting for a signal.
func TestServeGracefullyReturnsServeError(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln.Close() // Serve fails immediately

	var stopped atomic.Bool
	errc := make(chan error, 1)
	go func() {
		errc <- serveGracefully(&http.Server{Handler: http.NewServeMux()}, ln, func() { stopped.Store(true) })
	}()
	select {
	case err := <-errc:
		if err == nil {
			t.Fatal("expected an error from a dead listener")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serveGracefully hung on a dead listener")
	}
	if !stopped.Load() {
		t.Fatal("onStop hook must run on the error path too")
	}
}
