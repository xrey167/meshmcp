// Package resources holds one file per resource, each exposing a
// registerX(s) function, aggregated by Register — the Go equivalent of the
// resources/index.ts + server.registerResource(...) pattern.
package resources

import "meshmcp/mcp"

// Config carries per-server settings the resource handlers need.
type Config struct {
	Root string
}

// Register registers every resource on the server.
func Register(s *mcp.Server, cfg Config) {
	registerTime(s)
	registerPeer(s)
	registerInfo(s, cfg.Root)
}
