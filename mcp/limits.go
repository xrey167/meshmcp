package mcp

import (
	"fmt"
	"time"
)

// ToolLimits bounds tool execution: a cooperative deadline and a concurrency
// cap. Zero fields mean "no bound of that kind".
type ToolLimits struct {
	Timeout       time.Duration
	MaxConcurrent int
}

func (l ToolLimits) validate(scope string) error {
	if l.Timeout < 0 {
		return fmt.Errorf("limits %s: timeout must be >= 0, got %s", scope, l.Timeout)
	}
	if l.MaxConcurrent < 0 {
		return fmt.Errorf("limits %s: max_concurrent must be >= 0, got %d", scope, l.MaxConcurrent)
	}
	return nil
}

func (l ToolLimits) empty() bool { return l.Timeout == 0 && l.MaxConcurrent == 0 }

// LimitsConfig is a server's execution-limit configuration: Global applies to
// every tool; PerTool entries wrap the named tool inside the global chain, so
// a per-tool timeout runs within (and may be shorter than) the global one.
type LimitsConfig struct {
	Global  ToolLimits
	PerTool map[string]ToolLimits
}

// ApplyLimits validates cfg and registers the corresponding Timeout /
// LimitConcurrency middleware on s (Use for Global, UseTool for PerTool).
// Nothing is registered when validation fails.
func ApplyLimits(s *Server, cfg LimitsConfig) error {
	if err := cfg.Global.validate("global"); err != nil {
		return err
	}
	for tool, l := range cfg.PerTool {
		if tool == "" {
			return fmt.Errorf("limits: per-tool entry with an empty tool name")
		}
		if err := l.validate(fmt.Sprintf("tool %q", tool)); err != nil {
			return err
		}
	}

	register := func(use func(...ToolMiddleware), l ToolLimits) {
		if l.Timeout > 0 {
			use(Timeout(l.Timeout))
		}
		if l.MaxConcurrent > 0 {
			use(LimitConcurrency(l.MaxConcurrent))
		}
	}
	if !cfg.Global.empty() {
		register(s.Use, cfg.Global)
	}
	for tool, l := range cfg.PerTool {
		if l.empty() {
			continue
		}
		tool := tool
		register(func(mw ...ToolMiddleware) { s.UseTool(tool, mw...) }, l)
	}
	return nil
}
