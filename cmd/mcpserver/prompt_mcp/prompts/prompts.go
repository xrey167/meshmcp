// Package prompts holds one file per prompt, each exposing a registerX(s)
// function, aggregated by Register — the Go equivalent of the
// prompts/index.ts + server.registerPrompt(...) pattern.
package prompts

import "github.com/xrey167/meshmcp/mcp"

// Register registers every prompt on the server.
func Register(s *mcp.Server) {
	registerSummarize(s)
	registerCodeReview(s)
}
