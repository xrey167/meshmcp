package policy

import (
	"fmt"
	"path"
	"strings"
	"time"
)

// Validate checks a policy for the silent-failure traps that would otherwise
// only surface (or fail open) at request time: unparseable globs that can never
// match, a malformed rate/window that disables a limit or a time gate, and a
// bad timezone. It is called at config load so a mistyped rule is a startup
// error, not a rule that quietly never fires.
func (p *Policy) Validate() error {
	if p == nil {
		return nil
	}
	for i, r := range p.Rules {
		if len(r.Tools) == 0 && len(r.Methods) == 0 {
			return fmt.Errorf("rule #%d: must set either tools or methods", i+1)
		}
		if len(r.Tools) > 0 && len(r.Methods) > 0 {
			return fmt.Errorf("rule #%d: a rule governs tools OR methods, not both", i+1)
		}
		for _, g := range r.Peers {
			pat := strings.TrimPrefix(g, "pubkey:")
			if _, err := path.Match(pat, ""); err != nil {
				return fmt.Errorf("rule #%d: peer pattern %q is not a valid glob: %w", i+1, g, err)
			}
		}
		if err := validateGlobs(i, "tool", r.Tools); err != nil {
			return err
		}
		if err := validateGlobs(i, "method", r.Methods); err != nil {
			return err
		}
		if r.Rate != nil {
			if r.Rate.Max <= 0 {
				return fmt.Errorf("rule #%d: rate.max must be > 0 (got %d — a non-positive max silently disables the limit)", i+1, r.Rate.Max)
			}
			if r.Rate.Per != "" {
				if d, err := time.ParseDuration(r.Rate.Per); err != nil || d <= 0 {
					return fmt.Errorf("rule #%d: rate.per %q is not a positive duration", i+1, r.Rate.Per)
				}
			}
		}
		if r.When != nil {
			if err := r.When.validate(); err != nil {
				return fmt.Errorf("rule #%d: %w", i+1, err)
			}
		}
	}
	return nil
}

func validateGlobs(ruleIdx int, kind string, globs []string) error {
	for _, g := range globs {
		if _, err := path.Match(g, ""); err != nil {
			return fmt.Errorf("rule #%d: %s pattern %q is not a valid glob: %w", ruleIdx+1, kind, g, err)
		}
	}
	return nil
}

// validate checks a time window's weekdays, hours range, and timezone parse.
func (w *Window) validate() error {
	if w.TZ != "" {
		if _, err := time.LoadLocation(w.TZ); err != nil {
			return fmt.Errorf("when.tz %q is not a valid IANA timezone: %w", w.TZ, err)
		}
	}
	for _, d := range w.Days {
		if _, ok := weekdayNames[strings.ToLower(d)]; !ok {
			return fmt.Errorf("when.days entry %q is not a weekday (sun..sat)", d)
		}
	}
	if w.Hours != "" {
		if _, _, ok := parseHourRange(w.Hours); !ok {
			return fmt.Errorf("when.hours %q must be HH:MM-HH:MM", w.Hours)
		}
	}
	return nil
}
