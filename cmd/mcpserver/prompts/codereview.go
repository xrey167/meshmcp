package prompts

import (
	"context"
	"fmt"

	"meshmcp/mcp"
)

func registerCodeReview(s *mcp.Server) {
	s.AddPrompt(mcp.Prompt{
		Name:        "code_review",
		Description: "Review a code snippet for bugs and clarity.",
		Arguments: []mcp.PromptArg{
			{Name: "language", Description: "programming language", Required: true},
			{Name: "code", Description: "the code to review", Required: true},
		},
		Get: func(_ context.Context, args map[string]string) (mcp.PromptResult, error) {
			return mcp.PromptResult{
				Description: "Code review prompt",
				Messages: []mcp.PromptMessage{{
					Role: "user",
					Content: mcp.Text(fmt.Sprintf(
						"Review this %s code for correctness, edge cases, and clarity. Be specific.\n\n```%s\n%s\n```",
						args["language"], args["language"], args["code"])),
				}},
			}, nil
		},
	})
}
