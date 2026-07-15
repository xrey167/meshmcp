// mcpserver is a real MCP stdio server built on the meshmcp/mcp framework.
// Capabilities are registered modularly: each tool/resource/prompt lives in
// its own file under tools/, resources/, prompts/, aggregated by a
// Register function (the Go equivalent of the *_index.ts + registerX
// pattern). Add a capability by dropping a new file in the right package and
// calling its registerX from that package's Register.
//
// Filesystem tools are sandboxed to --root; run_command is limited to
// --allow-cmd. The server also surfaces the calling mesh peer as a resource.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"meshmcp/cmd/mcpserver/prompts"
	"meshmcp/cmd/mcpserver/resources"
	"meshmcp/cmd/mcpserver/tools"
	"meshmcp/mcp"
)

func main() {
	root := flag.String("root", ".", "filesystem sandbox root for file tools")
	allowCmd := flag.String("allow-cmd", "", "comma-separated allow-list for the run_command tool (e.g. echo,git)")
	flag.Parse()

	absRoot, err := filepath.Abs(*root)
	if err != nil {
		fmt.Fprintln(os.Stderr, "mcpserver: bad root:", err)
		os.Exit(1)
	}
	var allowed []string
	if *allowCmd != "" {
		allowed = strings.Split(*allowCmd, ",")
	}
	fmt.Fprintf(os.Stderr, "mcpserver: started for peer %q, root %s, allow-cmd %v\n",
		os.Getenv("MESHMCP_PEER"), absRoot, allowed)

	s := mcp.New("meshmcp-demo", "0.1.0")
	tools.Register(s, tools.Config{Root: absRoot, AllowedCommands: allowed})
	resources.Register(s, resources.Config{Root: absRoot})
	prompts.Register(s)

	if err := s.Serve(context.Background(), os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "mcpserver:", err)
		os.Exit(1)
	}
}
