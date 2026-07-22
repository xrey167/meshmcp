package main

import (
	"fmt"
	"io"
	"strings"

	"github.com/xrey167/meshmcp/air"
)

// This is the terminal-facing render for the osint Privacy Report — a single
// Apple-clean screen: a grade, the surface counts, the flagged findings, and the
// per-identity reachability matrix. It is pure (takes an io.Writer, no mesh), so
// it is unit-testable; colour is applied by the style helpers only on a TTY.

// renderOsintReport paints the Privacy Report, showing only findings at or above
// minLevel (0=critical … 3=low).
func renderOsintReport(w io.Writer, report air.ExposureReport, minLevel int) {
	gw := report.Gateway
	if gw == "" {
		gw = "(local config)"
	}
	fmt.Fprintln(w, bold("Privacy Report")+dim(" · gateway ")+bold(gw)+"   "+gradeCell(report.Score.Grade))
	fmt.Fprintln(w)

	nId := len(report.Reach)
	fmt.Fprintln(w, dim("Surface  ")+fmt.Sprintf("%d backend(s) · %d identity(ies)", len(report.Mesh.Backends), nId))
	fmt.Fprintln(w, dim(strings.Repeat("─", 60)))

	shown := 0
	for _, f := range report.Findings {
		if severityLevelOf(f.Severity) > minLevel {
			continue
		}
		shown++
		line := severityDot(f.Severity) + "  " + bold(padRight(string(f.Severity), 8)) + " " + padRight(f.Rule, 21) + " "
		if f.Backend != "" {
			line += dim(f.Backend)
		}
		fmt.Fprintln(w, line)
		fmt.Fprintln(w, dim("            "+f.Detail))
		if len(f.Evidence) > 0 {
			fmt.Fprintln(w, dim("            evidence: "+strings.Join(f.Evidence, ", ")))
		}
	}
	if shown == 0 {
		fmt.Fprintln(w, green("✓ ")+dim("no findings at or above this severity — the surface is clean"))
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, bold("Who can reach what"))
	fmt.Fprintln(w, dim(strings.Repeat("─", 60)))
	if len(report.Reach) == 0 {
		fmt.Fprintln(w, dim("(no configured identities)"))
	}
	for _, r := range report.Reach {
		reach := strings.Join(r.Backends, ", ")
		if reach == "" {
			reach = dim("(reaches nothing)")
		}
		fmt.Fprintln(w, bold(r.Identity))
		fmt.Fprintln(w, "   "+reach)
		if len(r.ViaWildcard) > 0 {
			fmt.Fprintln(w, "   "+amber(fmt.Sprintf("⚠ %d via wildcard: %s", len(r.ViaWildcard), strings.Join(r.ViaWildcard, ", "))))
		}
		if len(r.Secrets) > 0 {
			fmt.Fprintln(w, "   "+red("secrets: "+strings.Join(r.Secrets, ", ")))
		}
		if len(r.RemoteEgress) > 0 {
			fmt.Fprintln(w, "   "+dim("egress: "+strings.Join(r.RemoteEgress, ", ")))
		}
	}

	fmt.Fprintln(w)
	s := report.Score
	fmt.Fprintln(w, dim(fmt.Sprintf("%d critical · %d high · %d medium · %d low", s.Critical, s.High, s.Medium, s.Low)))
}

// renderOsintDelta prints how the surface drifted since the last snapshot:
// new findings red, resolved green, reach changes amber — the air change idiom.
func renderOsintDelta(d air.ExposureDelta) {
	if d.Empty() {
		fmt.Println(dim("no exposure drift since the last snapshot"))
		return
	}
	for _, f := range d.NewFindings {
		fmt.Println(red("+ ") + bold(string(f.Severity)) + " " + f.Rule + dim("  "+f.Backend))
	}
	for _, f := range d.ResolvedFindings {
		fmt.Println(green("- ") + dim("resolved ") + bold(string(f.Severity)) + " " + f.Rule + dim("  "+f.Backend))
	}
	for _, rc := range d.ReachChanges {
		parts := []string{}
		if len(rc.Gained) > 0 {
			parts = append(parts, green("+"+strings.Join(rc.Gained, ",")))
		}
		if len(rc.Lost) > 0 {
			parts = append(parts, red("-"+strings.Join(rc.Lost, ",")))
		}
		fmt.Println(amber("~ ") + bold(rc.Identity) + "  " + strings.Join(parts, " "))
	}
	from, to := d.ScoreFrom.Grade, d.ScoreTo.Grade
	grade := from
	if from != to {
		grade = from + " → " + to
	}
	fmt.Println(dim(d.Summary() + "   grade " + grade))
}

// gradeCell colours the headline grade: A/B green, C/D amber, F red.
func gradeCell(grade string) string {
	label := "grade " + grade
	switch grade {
	case "A", "B":
		return green(label)
	case "C", "D":
		return amber(label)
	default:
		return red(label)
	}
}

// severityDot returns a coloured status dot for a finding's severity.
func severityDot(s air.Severity) string {
	switch s {
	case air.SevCritical:
		return red("●")
	case air.SevHigh:
		return amber("●")
	case air.SevMedium:
		return blue("○")
	default:
		return dim("○")
	}
}
