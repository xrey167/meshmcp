package main

import (
	"context"
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// shutdownSignals is the set of OS signals every long-running meshmcp command
// treats as a request to shut down gracefully. os.Interrupt is Ctrl-C (SIGINT);
// syscall.SIGTERM is what systemd, Docker (`docker stop`), Kubernetes, and most
// process supervisors send to ask a process to exit — without it, those stops
// fall through to the OS default disposition and kill the process ungracefully,
// skipping the audit flush / listener drain each command performs on shutdown.
//
// Keeping the set in one place confines the syscall import to this file and lets
// every signal.Notify / signal.NotifyContext site spread it with
// `shutdownSignals...`. SIGTERM is a defined constant on all platforms (it is
// simply never delivered on Windows, where os.Interrupt maps to Ctrl-C), so this
// compiles and is safe cross-platform.
var shutdownSignals = []os.Signal{os.Interrupt, syscall.SIGTERM}

// reloadSignals is the set of OS signals that ask a running gateway to re-read
// its config and hot-swap policy rules in place, without a restart. SIGHUP is
// the long-standing Unix convention for "reload your configuration"; it is a
// defined constant on all platforms (never delivered on Windows), so referencing
// it here compiles cross-platform, mirroring shutdownSignals' SIGTERM handling.
var reloadSignals = []os.Signal{syscall.SIGHUP}

// gracefulDrainTimeout bounds how long a stopping server waits for in-flight
// requests before giving up the drain. Ten seconds comfortably covers a page
// render or an API call while staying inside systemd's default stop window.
const gracefulDrainTimeout = 10 * time.Second

// serveGracefully serves srv — on ln when non-nil, else via ListenAndServe —
// until a shutdown signal (SIGINT/SIGTERM) arrives, then drains in-flight
// requests with Shutdown before returning. This is the shared shutdown seam for
// the single-server commands (dash, room, approvals, control, air serve, air kg
// serve): without it a `systemctl stop`/`docker stop` kills them mid-response
// with no drain and no deferred cleanup (mesh stop, file close, audit flush).
// A signal-initiated stop returns nil; a server failure returns its error.
// onStop hooks run after the drain, before returning — the place to flush an
// audit sink the command holds.
func serveGracefully(srv *http.Server, ln net.Listener, onStop ...func()) error {
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, shutdownSignals...)
	defer signal.Stop(stop)

	errc := make(chan error, 1)
	go func() {
		if ln != nil {
			errc <- srv.Serve(ln)
		} else {
			errc <- srv.ListenAndServe()
		}
	}()

	var err error
	select {
	case sig := <-stop:
		log.Printf("received %v — draining and shutting down", sig)
		ctx, cancel := context.WithTimeout(context.Background(), gracefulDrainTimeout)
		_ = srv.Shutdown(ctx)
		cancel()
		<-errc // Serve/ListenAndServe returns ErrServerClosed after Shutdown
	case err = <-errc:
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
	}
	for _, f := range onStop {
		f()
	}
	return err
}
