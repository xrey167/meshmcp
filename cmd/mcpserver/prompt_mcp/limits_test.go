package main

import (
	"testing"
	"time"
)

func TestParseLimits(t *testing.T) {
	cfg, err := parseLimits([]byte(`
timeout: 30s
max_concurrent: 8
tools:
  run_command: {timeout: 10s, max_concurrent: 2}
  read_file: {max_concurrent: 4}
`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Global.Timeout != 30*time.Second || cfg.Global.MaxConcurrent != 8 {
		t.Fatalf("global: %+v", cfg.Global)
	}
	rc := cfg.PerTool["run_command"]
	if rc.Timeout != 10*time.Second || rc.MaxConcurrent != 2 {
		t.Fatalf("run_command: %+v", rc)
	}
	rf := cfg.PerTool["read_file"]
	if rf.Timeout != 0 || rf.MaxConcurrent != 4 {
		t.Fatalf("read_file: %+v", rf)
	}
}

func TestParseLimitsRejectsBadDuration(t *testing.T) {
	if _, err := parseLimits([]byte("timeout: soon")); err == nil {
		t.Fatal("bad global duration must error")
	}
	if _, err := parseLimits([]byte("tools:\n  x: {timeout: nope}")); err == nil {
		t.Fatal("bad per-tool duration must error")
	}
}

func TestApplyLimitsFileEmptyPathIsNoop(t *testing.T) {
	if err := applyLimitsFile(nil, ""); err != nil {
		t.Fatal(err)
	}
}
