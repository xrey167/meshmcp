package main

import (
	"fmt"
	"io"
	"os"
	"strings"
)

// This is the terminal-facing styling layer for the human (non-JSON) CLI
// output: colour is emitted ONLY when stdout is a real terminal and NO_COLOR is
// unset, so piped/redirected/`--json` output is never polluted with escape
// codes. Column widths are computed from PLAIN text, so ANSI never breaks
// alignment (the mistake tabwriter makes with coloured cells).

// colorOn is resolved once at startup: a TTY, colour not disabled by env.
var colorOn = detectColor()

func detectColor() bool {
	if os.Getenv("NO_COLOR") != "" || os.Getenv("MESHMCP_NO_COLOR") != "" {
		return false
	}
	fi, err := os.Stdout.Stat()
	if err != nil || fi.Mode()&os.ModeCharDevice == 0 {
		return false // piped or redirected — no colour
	}
	enableVT() // Windows: turn on ANSI processing; no-op elsewhere
	return true
}

// sgr wraps s in an SGR sequence when colour is on, else returns s unchanged.
func sgr(code, s string) string {
	if !colorOn {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

func dim(s string) string   { return sgr("2", s) }
func bold(s string) string  { return sgr("1", s) }
func green(s string) string { return sgr("32", s) }
func red(s string) string   { return sgr("31", s) }
func amber(s string) string { return sgr("33", s) }
func cyan(s string) string  { return sgr("36", s) }
func blue(s string) string  { return sgr("38;5;39", s) } // Apple-ish blue

// okLine formats a success line with a green check, matching the page's ✓.
func okLine(format string, a ...any) string {
	return green("✓") + " " + fmt.Sprintf(format, a...)
}

// dot returns a coloured status dot for a connection state.
func statusDot(connected bool, label string) cell {
	if connected {
		return styled("● "+label, green)
	}
	return styled("○ "+label, amber)
}

// humanAge renders a second count as a compact, human duration (42s, 5m, 3h).
func humanAge(sec int) string {
	switch {
	case sec < 60:
		return fmt.Sprintf("%ds", sec)
	case sec < 3600:
		return fmt.Sprintf("%dm", sec/60)
	case sec < 86400:
		return fmt.Sprintf("%dh", sec/3600)
	default:
		return fmt.Sprintf("%dd", sec/86400)
	}
}

// cell is one table cell: plain text plus an optional colour styler applied
// AFTER width padding, so colour never affects alignment.
type cell struct {
	text  string
	style func(string) string
}

func plain(s string) cell                         { return cell{text: sanitizeCell(s)} }
func styled(s string, f func(string) string) cell { return cell{text: sanitizeCell(s), style: f} }

// sanitizeCell strips control characters (including ESC/0x1b, tab, newline, and
// DEL) from a value before it becomes a table cell, so a hostile or compromised
// remote source — a gateway's catalog entry, a peer's FQDN, a task id — cannot
// inject terminal escape sequences or break the layout. Colour is added by the
// cell's styler AFTER this, so legitimate styling is unaffected; the cell's
// plain text (measured for alignment) is guaranteed escape-free.
func sanitizeCell(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
}

func runeLen(s string) int { return len([]rune(s)) }

func padRight(s string, n int) string {
	if d := n - runeLen(s); d > 0 {
		return s + strings.Repeat(" ", d)
	}
	return s
}

// renderTable writes an aligned table with a dim, spaced header. Widths come
// from the plain text of headers and cells, so styled cells stay aligned. The
// last column is not padded (no trailing runs of spaces).
func renderTable(w io.Writer, headers []string, rows [][]cell) {
	cols := len(headers)
	width := make([]int, cols)
	for i, h := range headers {
		width[i] = runeLen(h)
	}
	for _, r := range rows {
		for i := 0; i < cols && i < len(r); i++ {
			if n := runeLen(r[i].text); n > width[i] {
				width[i] = n
			}
		}
	}
	var b strings.Builder
	for i, h := range headers {
		if i == cols-1 {
			b.WriteString(dim(strings.ToUpper(h)))
		} else {
			b.WriteString(dim(padRight(strings.ToUpper(h), width[i])) + "  ")
		}
	}
	fmt.Fprintln(w, b.String())
	for _, r := range rows {
		b.Reset()
		for i := 0; i < cols; i++ {
			var c cell
			if i < len(r) {
				c = r[i]
			}
			if i == cols-1 {
				s := c.text
				if c.style != nil {
					s = c.style(s)
				}
				b.WriteString(s)
			} else {
				padded := padRight(c.text, width[i])
				if c.style != nil {
					padded = c.style(padded)
				}
				b.WriteString(padded + "  ")
			}
		}
		fmt.Fprintln(w, b.String())
	}
}
