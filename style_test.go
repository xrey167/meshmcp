package main

import (
	"bytes"
	"strings"
	"testing"
)

// TestRenderTableAlignsWithStyledCells proves column alignment is computed from
// plain text, so a styled (coloured) cell never shifts a column. We force
// colour on, render, then assert the plain-text layout is unchanged.
func TestRenderTableAlignsWithStyledCells(t *testing.T) {
	old := colorOn
	colorOn = true
	defer func() { colorOn = old }()

	var buf bytes.Buffer
	renderTable(&buf, []string{"backend", "session", "age"}, [][]cell{
		{styled("fs", bold), styled("9f2a", cyan), styled("42s", dim)},
		{styled("knowledge-graph", bold), styled("1a2b", cyan), styled("5m", dim)},
	})
	// Strip ANSI, then check each data column starts at the same offset.
	plain := stripANSI(buf.String())
	lines := strings.Split(strings.TrimRight(plain, "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("want header+2 rows, got %d: %q", len(lines), plain)
	}
	// "knowledge-graph" is the widest backend (15); the session column must
	// start at the same index on every line.
	col := strings.Index(lines[2], "1a2b")
	if col < 0 || strings.Index(lines[0], "SESSION") != col {
		t.Fatalf("session column misaligned: header %d vs row %d\n%q",
			strings.Index(lines[0], "SESSION"), col, plain)
	}
	if strings.Index(lines[1], "9f2a") != col {
		t.Fatalf("short-backend row misaligned: %q", plain)
	}
}

// TestNoColorWhenOff proves nothing emits escape codes when colour is off
// (piped/redirected/NO_COLOR), so machine-readable output stays clean.
func TestNoColorWhenOff(t *testing.T) {
	old := colorOn
	colorOn = false
	defer func() { colorOn = old }()
	for _, s := range []string{bold("x"), green("y"), dim("z"), okLine("done")} {
		if strings.Contains(s, "\x1b[") {
			t.Fatalf("escape code leaked with colour off: %q", s)
		}
	}
}

func TestHumanAge(t *testing.T) {
	for in, want := range map[int]string{5: "5s", 90: "1m", 7200: "2h", 172800: "2d"} {
		if got := humanAge(in); got != want {
			t.Errorf("humanAge(%d) = %q, want %q", in, got, want)
		}
	}
}

// stripANSI removes SGR sequences for plain-text assertions.
func stripANSI(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\x1b' && i+1 < len(s) && s[i+1] == '[' {
			for i += 2; i < len(s) && s[i] != 'm'; i++ {
			}
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
