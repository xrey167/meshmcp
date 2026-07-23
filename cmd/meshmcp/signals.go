package main

import (
	"os"
	"syscall"
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
