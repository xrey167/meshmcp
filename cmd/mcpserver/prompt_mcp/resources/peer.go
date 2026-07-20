package resources

import (
	"context"
	"encoding/json"
	"os"

	"github.com/xrey167/meshmcp/mcp"
)

// registerPeer exposes the connected mesh peer's identity, as injected by
// the gateway into the server's environment.
func registerPeer(s *mcp.Server) {
	s.AddResource(mcp.Resource{
		URI:         "meshmcp://peer",
		Name:        "mesh-peer-identity",
		Description: "The mesh identity of the connected peer, as seen by the gateway.",
		MimeType:    "application/json",
		Read: func(_ context.Context) (mcp.ResourceContents, error) {
			b, _ := json.Marshal(map[string]string{
				"peer":      os.Getenv("MESHMCP_PEER"),
				"peer_addr": os.Getenv("MESHMCP_PEER_ADDR"),
				"peer_key":  os.Getenv("MESHMCP_PEER_KEY"),
			})
			return mcp.ResourceContents{Text: string(b)}, nil
		},
	})
}
