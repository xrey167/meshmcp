package main

import (
	"fmt"
	"runtime"
	"runtime/debug"
	"strings"
)

// commit and date identify the exact build. Release builds inject them via
// -ldflags "-X main.commit=… -X main.date=…" (see release.yml); a plain
// `go build` from a git checkout falls back to the toolchain's embedded VCS
// stamp, so even a dev build answers "which code is this?".
var (
	commit = ""
	date   = ""
)

// printVersion implements `meshmcp version` / `meshmcp --version`: the version
// on the first line (stable, script-friendly), provenance below.
func printVersion() {
	fmt.Println("meshmcp " + version)
	c, d := commit, date
	if c == "" || d == "" {
		if bi, ok := debug.ReadBuildInfo(); ok {
			modified := false
			for _, s := range bi.Settings {
				switch s.Key {
				case "vcs.revision":
					if c == "" {
						c = s.Value
					}
				case "vcs.time":
					if d == "" {
						d = s.Value
					}
				case "vcs.modified":
					modified = s.Value == "true"
				}
			}
			if modified && c != "" {
				c += " (modified)"
			}
		}
	}
	// Short hash for readability, preserving any "(modified)" marker.
	hash, suffix := c, ""
	if i := strings.IndexByte(c, ' '); i >= 0 {
		hash, suffix = c[:i], c[i:]
	}
	if len(hash) > 12 {
		hash = hash[:12]
	}
	if c = hash + suffix; c != "" {
		line := "  commit  " + c
		if d != "" {
			line += "  (" + d + ")"
		}
		fmt.Println(line)
	}
	fmt.Printf("  go      %s %s/%s\n", runtime.Version(), runtime.GOOS, runtime.GOARCH)
}
