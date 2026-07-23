package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
)

// meshmcp's own operational output becomes leveled, structured logging without
// changing what a user sees today: initLogging installs a slog default whose
// handler reproduces the historical stdlib format ("2006/01/02 15:04:05
// meshmcp: message key=val"), and — because slog.SetDefault bridges the stdlib
// log package — every existing log.Printf call site now flows through it at
// Info level. That gives operators level control ($MESHMCP_LOG=warn quiets the
// startup chatter; =debug surfaces diagnostics; a leading --verbose flag is
// sugar for debug) and gives new code slog.Debug/Info/Warn/Error with
// structured attributes, with zero visual churn on the default path.
//
// The styled Air UX output (fmt.Fprintln with color helpers) is presentation,
// not logging, and deliberately does not route through here.

// logLevel is the process-wide minimum level, adjustable before dispatch.
var logLevel = new(slog.LevelVar)

// initLogging installs the leveled default logger. verbose (the leading
// --verbose/-v flag) forces debug; otherwise $MESHMCP_LOG picks the level
// (debug|info|warn|error, default info — today's behavior).
func initLogging(verbose bool) {
	switch {
	case verbose:
		logLevel.Set(slog.LevelDebug)
	default:
		switch strings.ToLower(strings.TrimSpace(os.Getenv("MESHMCP_LOG"))) {
		case "debug":
			logLevel.Set(slog.LevelDebug)
		case "", "info":
			logLevel.Set(slog.LevelInfo)
		case "warn", "warning":
			logLevel.Set(slog.LevelWarn)
		case "error":
			logLevel.Set(slog.LevelError)
		default:
			logLevel.Set(slog.LevelInfo)
			fmt.Fprintln(os.Stderr, "meshmcp: unknown $MESHMCP_LOG level (want debug|info|warn|error) — using info")
		}
	}
	slog.SetDefault(slog.New(&calmHandler{w: os.Stderr, level: logLevel, mu: &sync.Mutex{}}))
}

// calmHandler renders slog records in the exact shape the stdlib log package
// produced here for years — time, the "meshmcp: " prefix, the message — with
// structured attributes appended as key=value and non-Info levels labeled.
// Format stability is the point: the default experience must not churn.
type calmHandler struct {
	w     *os.File
	level *slog.LevelVar
	attrs []slog.Attr
	mu    *sync.Mutex // shared across WithAttrs copies — one writer lock per sink
}

func (h *calmHandler) Enabled(_ context.Context, l slog.Level) bool {
	return l >= h.level.Level()
}

func (h *calmHandler) Handle(_ context.Context, r slog.Record) error {
	var b strings.Builder
	if !r.Time.IsZero() {
		b.WriteString(r.Time.Format("2006/01/02 15:04:05"))
		b.WriteByte(' ')
	}
	b.WriteString("meshmcp: ")
	// Info is the historical unlabeled level; anything else is called out.
	if r.Level != slog.LevelInfo {
		b.WriteString(r.Level.String())
		b.WriteByte(' ')
	}
	b.WriteString(r.Message)
	for _, a := range h.attrs {
		writeAttr(&b, a)
	}
	r.Attrs(func(a slog.Attr) bool {
		writeAttr(&b, a)
		return true
	})
	b.WriteByte('\n')
	h.mu.Lock()
	defer h.mu.Unlock()
	_, err := h.w.WriteString(b.String())
	return err
}

func writeAttr(b *strings.Builder, a slog.Attr) {
	if a.Equal(slog.Attr{}) {
		return
	}
	b.WriteByte(' ')
	b.WriteString(a.Key)
	b.WriteByte('=')
	b.WriteString(a.Value.String())
}

func (h *calmHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &calmHandler{w: h.w, level: h.level, mu: h.mu,
		attrs: append(append([]slog.Attr(nil), h.attrs...), attrs...)}
}

func (h *calmHandler) WithGroup(string) slog.Handler { return h } // groups add noise, not calm
