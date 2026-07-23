package main

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
)

// presentError is the single seam between a command's returned error chain and
// the human reading the terminal. The rule (see CONTRIBUTING.md): every
// user-facing error names what failed and a next step. The full wrapped chain
// is always shown — hiding detail helps nobody — but the known failure shapes
// get one added line of guidance, and the timestamped log.Fatal noise is gone.
// It exits 1, preserving the historical exit code.
func presentError(err error) {
	// cmdAirUp already printed the full setup-key guidance; repeating the raw
	// sentinel under it would just be noise.
	if errors.Is(err, errSetupKeyMissing) {
		os.Exit(1)
	}
	fmt.Fprintln(os.Stderr, amber("✗")+" "+err.Error())
	if hint := hintFor(err); hint != "" {
		fmt.Fprintln(os.Stderr, dim("  → "+hint))
	}
	if logLevel.Level() > slog.LevelDebug {
		fmt.Fprintln(os.Stderr, dim("  "+tr("(run with --verbose or MESHMCP_LOG=debug for diagnostic logging)")))
	}
	os.Exit(1)
}

// hintFor maps the common failure shapes to a one-line next step. Matching is
// on the error text because these chains cross package and process boundaries
// where typed errors do not survive; the strings matched are our own.
func hintFor(err error) string {
	msg := err.Error()
	has := func(subs ...string) bool {
		for _, s := range subs {
			if strings.Contains(msg, s) {
				return true
			}
		}
		return false
	}
	switch {
	case has("request declined"):
		return "" // the join flow already printed its own guidance
	case has("no such file", "cannot find the file") && has("config"):
		return "no config found — run `meshmcp air init` to scaffold one, or pass --config <file>"
	case has("connection refused", "no route to host", "i/o timeout", "context deadline exceeded", "dial "):
		return "the target is unreachable — is the gateway up (`meshmcp air up`)? check the address (or `meshmcp profile show`), and confirm both peers are on the same mesh (`meshmcp air whoami`)"
	case has("management", "setup key", "login", "engine"):
		return "the mesh could not come up — check $NB_SETUP_KEY and the management URL, then `meshmcp doctor`; `meshmcp diag --bundle` collects everything support needs"
	case has("was edited", "does not link", "schema version", "not valid JSON") && has("audit", "record"):
		return "the audit ledger failed verification — do NOT delete it; see docs/RUNBOOK.md (suspected tamper) and `meshmcp audit verify`"
	case has("already exists"):
		return "" // the message already names --force where applicable
	case has("newer than this build supports"):
		return "this state was written by a newer meshmcp — upgrade this binary to match the one that wrote it"
	default:
		return ""
	}
}
