package main

import (
	"flag"
	"io"

	"github.com/netbirdio/netbird/client/embed"

	"github.com/xrey167/meshmcp/internal/connectcli"
)

// The mesh join/flag plumbing lives in internal/connectcli so the thin
// meshmcp-connect binary (S45) can share it without pulling in this package.
// These aliases keep every call site in the full binary unchanged.

const defaultManagementURL = connectcli.DefaultManagementURL

// meshOptions holds everything needed to join the mesh as an embedded peer.
type meshOptions = connectcli.MeshOptions

// meshFlags registers the shared mesh flags on a command's flag set.
func meshFlags(fs *flag.FlagSet) *meshOptions { return connectcli.MeshFlags(fs) }

// startMesh creates and starts an embedded NetBird client.
// All NetBird logs are directed to logOut (never stdout: the connect
// command uses stdout as the MCP channel).
func startMesh(o *meshOptions, logOut io.Writer) (*embed.Client, error) {
	return connectcli.StartMesh(o, logOut)
}

func stopMesh(client *embed.Client) { connectcli.StopMesh(client) }
