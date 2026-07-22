package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
)

// cmdAirBrowse explores what a backend offers — its tools, resources, and
// prompts — over the mesh. Discovery (catalog/map) tells you a backend EXISTS;
// browse tells you what you can actually CALL there, filtered to your identity
// by the gateway. It is the first concrete step of the Air · Browse vision
// (docs/AIR-VISION.md).
func cmdAirBrowse(args []string) error {
	fs := flag.NewFlagSet("air browse", flag.ExitOnError)
	o := meshFlags(fs)
	asJSON := fs.Bool("json", false, "print the backend's capabilities as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: meshmcp air browse [flags] <backend-ip:port>")
	}
	target := fs.Arg(0)

	mc, cleanup, err := dialMCP(o, target)
	if err != nil {
		return err
	}
	defer cleanup()

	ctx := context.Background()
	// A backend need not implement every list method; treat an error on any one
	// as "none of that kind" rather than failing the whole browse.
	tools, _ := mc.ListTools(ctx)
	resources, _ := mc.ListResources(ctx)
	prompts, _ := mc.ListPrompts(ctx)

	if *asJSON {
		b, err := json.MarshalIndent(map[string]any{
			"target": target, "tools": tools, "resources": resources, "prompts": prompts,
		}, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(b))
		return nil
	}

	fmt.Fprintln(os.Stderr, dim("browsing ")+bold(target))
	browseSection("Tools", len(tools), func() {
		for _, t := range tools {
			printCapability(t.Name, t.Description)
		}
	})
	browseSection("Resources", len(resources), func() {
		for _, r := range resources {
			name := r.Name
			if name == "" {
				name = r.URI
			}
			printCapability(name, r.Description)
		}
	})
	browseSection("Prompts", len(prompts), func() {
		for _, p := range prompts {
			printCapability(p.Name, p.Description)
		}
	})
	if len(tools)+len(resources)+len(prompts) == 0 {
		fmt.Fprintln(os.Stderr, dim("this backend exposes nothing your identity may list"))
	}
	return nil
}

// browseSection prints a dim section header with a count, then its body.
func browseSection(title string, n int, body func()) {
	if n == 0 {
		return
	}
	fmt.Println()
	fmt.Println(dim(fmt.Sprintf("%s (%d)", title, n)))
	body()
}

// printCapability renders one tool/resource/prompt: a bold name and a dimmed,
// sanitized one-line description.
func printCapability(name, desc string) {
	line := "  " + bold(sanitizeCell(name))
	if desc != "" {
		line += "  " + dim(oneLine(sanitizeCell(desc)))
	}
	fmt.Println(line)
}

// oneLine collapses a description to its first line, trimmed to a readable
// length so the browse view stays scannable.
func oneLine(s string) string {
	if i := indexNewline(s); i >= 0 {
		s = s[:i]
	}
	const max = 88
	if runeLen(s) > max {
		return string([]rune(s)[:max]) + "…"
	}
	return s
}

func indexNewline(s string) int {
	for i, r := range s {
		if r == '\n' || r == '\r' {
			return i
		}
	}
	return -1
}
