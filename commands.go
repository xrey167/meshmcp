package main

import (
	"fmt"
	"os"
	"sort"
	"text/tabwriter"
)

// The plugin command registry is the compile-time subcommand seam (S40 / F13).
// A plugin — a Go file compiled into this binary — registers a subcommand from
// its init() with RegisterCommand; main() dispatches to it when no built-in
// command matches. This keeps the built-in switch authoritative (built-ins can
// never be shadowed) while letting extensions add verbs without editing main.go.

type commandEntry struct {
	summary string
	run     func(args []string) error
}

var pluginCommands = map[string]commandEntry{}

// RegisterCommand adds a plugin subcommand. It is intended to be called from an
// init() function. It panics on a duplicate or a name that collides with a
// built-in, since both are programming errors caught at startup.
func RegisterCommand(name, summary string, run func(args []string) error) {
	if name == "" || run == nil {
		panic("RegisterCommand: name and run are required")
	}
	if isBuiltinCommand(name) {
		panic(fmt.Sprintf("RegisterCommand: %q shadows a built-in command", name))
	}
	if _, dup := pluginCommands[name]; dup {
		panic(fmt.Sprintf("RegisterCommand: %q already registered", name))
	}
	pluginCommands[name] = commandEntry{summary: summary, run: run}
}

// dispatchPlugin runs a registered plugin command, reporting whether one
// matched. main() calls it before treating a command as unknown.
func dispatchPlugin(name string, args []string) (bool, error) {
	e, ok := pluginCommands[name]
	if !ok {
		return false, nil
	}
	return true, e.run(args)
}

// isBuiltinCommand reports whether name is one of the binary's built-in
// subcommands, so a plugin can never shadow one.
func isBuiltinCommand(name string) bool {
	for _, c := range builtinCommands {
		if c == name {
			return true
		}
	}
	return false
}

// builtinCommands is the set of names main()'s switch handles. Kept here so the
// plugin registry can refuse to shadow any of them.
var builtinCommands = []string{
	"serve", "connect", "forward", "drop", "peers", "fetch", "push", "probe",
	"ls", "call", "read", "prompt", "functions", "function-call", "router",
	"orchestrate", "graphrag", "control", "federate", "audit", "capability",
	"approve", "approvals", "agent", "secrets", "dash", "room", "mcp",
	"insight", "replay", "config", "status", "doctor", "plugins", "version",
}

// cmdPlugins lists the extensions compiled into this binary: registered plugin
// subcommands (and, in the future, decision hooks and audit sinks declared in
// config). It makes the plugin surface introspectable — "what does this build
// carry."
func cmdPlugins(args []string) error {
	names := make([]string, 0, len(pluginCommands))
	for n := range pluginCommands {
		names = append(names, n)
	}
	sort.Strings(names)
	if len(names) == 0 {
		fmt.Println("no plugin subcommands are compiled into this build")
		fmt.Println("(register one from a Go file's init() with RegisterCommand)")
		return nil
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "COMMAND\tSUMMARY")
	for _, n := range names {
		fmt.Fprintf(tw, "%s\t%s\n", n, pluginCommands[n].summary)
	}
	return tw.Flush()
}
