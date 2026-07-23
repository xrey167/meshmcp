package main

import (
	"errors"
	"strings"
	"testing"
)

// TestHintForNamesANextStep pins the error-copy contract for the common
// failure shapes: each hint names a concrete next command, and unknown errors
// get no invented hint.
func TestHintForNamesANextStep(t *testing.T) {
	cases := []struct {
		err  string
		want string // substring of the hint; "" = no hint
	}{
		{"serve: read config meshmcp.yaml: open meshmcp.yaml: no such file or directory", "air init"},
		{"air sessions: dial 100.64.0.9:9600: connect: connection refused", "air up"},
		{"air join: Get http://air-control/v1/pair/status: context deadline exceeded", "air whoami"},
		{"start mesh: management login: invalid setup key", "doctor"},
		{"shared audit log: audit record seq 4 was edited: stored hash \"ab\" != recomputed \"cd\"", "RUNBOOK"},
		{"pairing: on-disk schema version 9 is newer than this build supports (1) — upgrade meshmcp", "upgrade"},
		{"air init: meshmcp.yaml already exists (use --force to overwrite)", ""},
		{"something entirely novel went wrong", ""},
	}
	for _, tc := range cases {
		got := hintFor(errors.New(tc.err))
		if tc.want == "" {
			if got != "" {
				t.Errorf("hintFor(%q) = %q, want no hint", tc.err, got)
			}
			continue
		}
		if !strings.Contains(got, tc.want) {
			t.Errorf("hintFor(%q) = %q, want a hint mentioning %q", tc.err, got, tc.want)
		}
	}
}
