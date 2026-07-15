package prompts

import (
	"context"

	"meshmcp/mcp"
)

func registerSummarize(s *mcp.Server) {
	s.AddPrompt(mcp.Prompt{
		Name:        "summarize",
		Description: "Summarize a block of text.",
		Arguments:   []mcp.PromptArg{{Name: "text", Description: "text to summarize", Required: true}},
		Get: func(_ context.Context, args map[string]string) (mcp.PromptResult, error) {
			return mcp.PromptResult{
				Description: "Summarization prompt",
				Messages: []mcp.PromptMessage{{
					Role:    "user",
					Content: mcp.Text("Summarize the following in 2-3 sentences:\n\n" + args["text"]),
				}},
			}, nil
		},
	})
}
