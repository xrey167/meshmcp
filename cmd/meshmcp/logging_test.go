package main

import (
	"context"
	"log/slog"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestCalmHandlerKeepsHistoricalFormat proves the no-churn contract: an Info
// record renders exactly like the stdlib log package always did here — time,
// the meshmcp prefix, the message — while other levels are labeled and
// structured attributes append as key=value.
func TestCalmHandlerKeepsHistoricalFormat(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	lv := new(slog.LevelVar)
	h := &calmHandler{w: w, level: lv, mu: &sync.Mutex{}}
	logger := slog.New(h)

	ts := time.Date(2026, 7, 23, 13, 4, 5, 0, time.UTC)
	rec := slog.NewRecord(ts, slog.LevelInfo, "backend \"kb\" ready", 0)
	if err := h.Handle(context.Background(), rec); err != nil {
		t.Fatal(err)
	}
	logger.Warn("disk almost full", "free_mb", 12)
	w.Close()

	buf := make([]byte, 4096)
	n, _ := r.Read(buf)
	out := string(buf[:n])

	if !strings.Contains(out, "2026/07/23 13:04:05 meshmcp: backend \"kb\" ready\n") {
		t.Errorf("Info line format churned:\n%s", out)
	}
	if !strings.Contains(out, "meshmcp: WARN disk almost full free_mb=12") {
		t.Errorf("Warn line missing level label or attrs:\n%s", out)
	}
}

// TestCalmHandlerLevelGate proves the level var actually gates records — the
// mechanism behind $MESHMCP_LOG / --verbose.
func TestCalmHandlerLevelGate(t *testing.T) {
	lv := new(slog.LevelVar)
	h := &calmHandler{w: os.Stderr, level: lv, mu: &sync.Mutex{}}

	lv.Set(slog.LevelWarn)
	if h.Enabled(context.Background(), slog.LevelInfo) {
		t.Error("Info must be gated at warn level")
	}
	if !h.Enabled(context.Background(), slog.LevelError) {
		t.Error("Error must pass at warn level")
	}
	lv.Set(slog.LevelDebug)
	if !h.Enabled(context.Background(), slog.LevelDebug) {
		t.Error("Debug must pass at debug level (--verbose)")
	}
}
