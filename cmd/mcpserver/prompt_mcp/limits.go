package main

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/xrey167/meshmcp/mcp"
)

// Execution-limit config (--limits limits.yaml): wires the mcp package's
// Timeout / LimitConcurrency middleware from per-backend config.
//
//	timeout: 30s          # global per-call deadline (optional)
//	max_concurrent: 8     # global in-flight cap (optional)
//	tools:                # per-tool overrides, applied inside the global chain
//	  run_command: {timeout: 10s, max_concurrent: 2}
//
// timeout is a cooperative context deadline, not a hard kill: a handler that
// ignores ctx.Done() runs (and holds its concurrency permit) past the
// deadline. max_concurrent queues excess calls until a permit frees or the
// call's context (its own timeout, or the client going away) cancels.

// limitsEntry is one yaml limits block; durations are strings ("30s").
type limitsEntry struct {
	Timeout       string `yaml:"timeout"`
	MaxConcurrent int    `yaml:"max_concurrent"`
}

type limitsFile struct {
	limitsEntry `yaml:",inline"`
	Tools       map[string]limitsEntry `yaml:"tools"`
}

func (e limitsEntry) toolLimits(scope string) (mcp.ToolLimits, error) {
	var l mcp.ToolLimits
	if e.Timeout != "" {
		d, err := time.ParseDuration(e.Timeout)
		if err != nil {
			return l, fmt.Errorf("limits %s: bad timeout %q: %w", scope, e.Timeout, err)
		}
		l.Timeout = d
	}
	l.MaxConcurrent = e.MaxConcurrent
	return l, nil
}

// parseLimits converts yaml bytes into a validated-shape LimitsConfig (value
// validation itself happens in mcp.ApplyLimits).
func parseLimits(data []byte) (mcp.LimitsConfig, error) {
	var f limitsFile
	if err := yaml.Unmarshal(data, &f); err != nil {
		return mcp.LimitsConfig{}, fmt.Errorf("limits: %w", err)
	}
	global, err := f.toolLimits("global")
	if err != nil {
		return mcp.LimitsConfig{}, err
	}
	cfg := mcp.LimitsConfig{Global: global}
	if len(f.Tools) > 0 {
		cfg.PerTool = make(map[string]mcp.ToolLimits, len(f.Tools))
		for name, e := range f.Tools {
			l, err := e.toolLimits(fmt.Sprintf("tool %q", name))
			if err != nil {
				return mcp.LimitsConfig{}, err
			}
			cfg.PerTool[name] = l
		}
	}
	return cfg, nil
}

// applyLimitsFile loads path (empty = no-op) and applies it to s.
func applyLimitsFile(s *mcp.Server, path string) error {
	if path == "" {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("limits: %w", err)
	}
	cfg, err := parseLimits(data)
	if err != nil {
		return err
	}
	return mcp.ApplyLimits(s, cfg)
}
