package main

import (
	"strings"
	"testing"
)

// TestOneLine covers the browse description collapser: first line only, trimmed
// to a scannable length with an ellipsis.
func TestOneLine(t *testing.T) {
	if got := oneLine("first line\nsecond line"); got != "first line" {
		t.Fatalf("newline collapse: %q", got)
	}
	if got := oneLine("carriage\rreturn"); got != "carriage" {
		t.Fatalf("CR collapse: %q", got)
	}
	if got := oneLine("short"); got != "short" {
		t.Fatalf("short unchanged: %q", got)
	}
	long := strings.Repeat("x", 200)
	got := oneLine(long)
	if !strings.HasSuffix(got, "…") || len([]rune(got)) != 89 {
		t.Fatalf("long not truncated to 88+ellipsis: %d runes", len([]rune(got)))
	}
}
