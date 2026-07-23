package harness

import (
	"fmt"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the harness's single typed configuration (§15). It is layered
// project → user → org and resolved at startup, then validated against policy: a
// config that grants more than policy allows is clamped, with a warning event.
// Secrets never appear here — only reference NAMES the broker resolves.
type Config struct {
	DefaultMode   Mode                          `yaml:"default_mode"`
	Budgets       BudgetConfig                  `yaml:"budgets"`
	Categories    map[Category]CategoryOverride `yaml:"categories"`
	Providers     ProviderConfig                `yaml:"providers"`
	Sandbox       SandboxConfig                 `yaml:"sandbox"`
	Hooks         HooksConfig                   `yaml:"hooks"`
	Skills        SkillsConfig                  `yaml:"skills"`
	Notifications NotifyConfig                  `yaml:"notifications"`
	Themes        map[string]string             `yaml:"themes"`
}

// BudgetConfig is the config form of Budget (durations as strings).
type BudgetConfig struct {
	Tokens     int    `yaml:"tokens"`
	WallClock  string `yaml:"wall_clock"`
	LoopRounds int    `yaml:"loop_rounds"`
	FanOut     int    `yaml:"fan_out"`
	Retries    struct {
		PerWorker int `yaml:"per_worker"`
		PerRun    int `yaml:"per_run"`
	} `yaml:"retries"`
}

// CategoryOverride forces a category's routing (policy-clamped).
type CategoryOverride struct {
	ModelClass string `yaml:"model_class"`
	FanOut     string `yaml:"fan_out"`
	Reviewers  int    `yaml:"reviewers"`
}

// ProviderConfig sets the fallback chain order and cache policy.
type ProviderConfig struct {
	Order          []string `yaml:"order"`
	ModelsDevCache string   `yaml:"models_dev_cache"`
}

// SandboxConfig sets the default and non-main sandbox backends.
type SandboxConfig struct {
	Default string `yaml:"default"`
	NonMain string `yaml:"non_main"`
}

// HooksConfig toggles hooks.
type HooksConfig struct {
	Disable         []string `yaml:"disable"`
	EnableAllSafety bool     `yaml:"enable_all_safety"`
}

// SkillsConfig sets skill scopes.
type SkillsConfig struct {
	Scopes []string `yaml:"scopes"`
}

// NotifyConfig sets notification tags (tokens via the broker).
type NotifyConfig struct {
	Tags []string `yaml:"tags"`
}

// DefaultConfig is the seed configuration.
func DefaultConfig() Config {
	c := Config{
		DefaultMode: ModeTeam,
		Providers:   ProviderConfig{Order: []string{"claude", "codex", "gemini", "local"}, ModelsDevCache: "refresh_daily"},
		Sandbox:     SandboxConfig{Default: "worktree", NonMain: "docker"},
		Hooks:       HooksConfig{EnableAllSafety: true},
		Skills:      SkillsConfig{Scopes: []string{"builtin", "project", "user"}},
	}
	c.Budgets.Tokens = 2_000_000
	c.Budgets.WallClock = "45m"
	c.Budgets.LoopRounds = 12
	c.Budgets.FanOut = 8
	c.Budgets.Retries.PerWorker = 3
	c.Budgets.Retries.PerRun = 20
	return c
}

// LoadConfig parses YAML/JSONC-ish config bytes over the default config, so a
// partial config only overrides what it sets.
func LoadConfig(data []byte) (Config, error) {
	c := DefaultConfig()
	if len(data) > 0 {
		if err := yaml.Unmarshal(data, &c); err != nil {
			return Config{}, fmt.Errorf("harness: parse config: %w", err)
		}
	}
	if err := c.Validate(); err != nil {
		return Config{}, err
	}
	return c, nil
}

// Validate checks the config is internally consistent.
func (c Config) Validate() error {
	if c.DefaultMode != "" && !KnownMode(c.DefaultMode) {
		return fmt.Errorf("harness: unknown default_mode %q", c.DefaultMode)
	}
	if c.Budgets.WallClock != "" {
		if _, err := time.ParseDuration(c.Budgets.WallClock); err != nil {
			return fmt.Errorf("harness: invalid wall_clock %q: %w", c.Budgets.WallClock, err)
		}
	}
	return nil
}

// Budget resolves the config's budget block into a Budget.
func (c Config) Budget() Budget {
	b := DefaultBudget()
	if c.Budgets.Tokens > 0 {
		b.Tokens = c.Budgets.Tokens
	}
	if c.Budgets.WallClock != "" {
		if d, err := time.ParseDuration(c.Budgets.WallClock); err == nil {
			b.WallClock = d
		}
	}
	if c.Budgets.LoopRounds > 0 {
		b.LoopRounds = c.Budgets.LoopRounds
	}
	if c.Budgets.FanOut > 0 {
		b.FanOut = c.Budgets.FanOut
	}
	if c.Budgets.Retries.PerWorker > 0 {
		b.RetryPerWorker = c.Budgets.Retries.PerWorker
	}
	if c.Budgets.Retries.PerRun > 0 {
		b.RetryPerRun = c.Budgets.Retries.PerRun
	}
	return b
}

// CategoryTable builds the routing table from the default overlaid with the
// config's category overrides (policy-clamped downstream).
func (c Config) CategoryTable() CategoryTable {
	t := DefaultCategoryTable()
	for cat, ov := range c.Categories {
		r := t.Route(cat)
		if ov.ModelClass != "" {
			r.ModelClass = ov.ModelClass
		}
		if ov.FanOut != "" {
			r.FanOut = FanOut(ov.FanOut)
		}
		if ov.Reviewers > 0 {
			r.Reviewers = ov.Reviewers
		}
		t[cat] = r
	}
	return t
}
