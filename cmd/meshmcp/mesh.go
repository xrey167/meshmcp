package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/netbirdio/netbird/client/embed"
)

const defaultManagementURL = "https://api.netbird.io:443"

// meshOptions holds everything needed to join the mesh as an embedded peer.
type meshOptions struct {
	DeviceName    string
	ManagementURL string
	SetupKey      string
	ConfigPath    string
	LogLevel      string
	DNSLabels     []string
	BlockInbound  bool
	StartTimeout  time.Duration
	// WireguardPort is the local WireGuard UDP port. 0 means a random
	// port, which is required when several embedded peers run on one host
	// (otherwise they collide on the default 51820).
	WireguardPort int
}

// meshFlags registers the shared mesh flags on a command's flag set.
func meshFlags(fs *flag.FlagSet) *meshOptions {
	o := &meshOptions{}
	fs.StringVar(&o.DeviceName, "device-name", "", "peer name in the mesh (default: meshmcp-<hostname>)")
	fs.StringVar(&o.ManagementURL, "management-url", os.Getenv("NB_MANAGEMENT_URL"), "NetBird management server URL (default: $NB_MANAGEMENT_URL or api.netbird.io)")
	fs.StringVar(&o.SetupKey, "setup-key", os.Getenv("NB_SETUP_KEY"), "NetBird setup key (default: $NB_SETUP_KEY)")
	fs.StringVar(&o.ConfigPath, "nb-config", "", "path to persist the NetBird identity; empty = in-memory, new peer each run")
	fs.StringVar(&o.LogLevel, "log-level", "error", "NetBird client log level")
	fs.DurationVar(&o.StartTimeout, "start-timeout", 2*time.Minute, "timeout for joining the mesh")
	fs.IntVar(&o.WireguardPort, "wg-port", 0, "local WireGuard UDP port; 0 = random (use random when running multiple peers on one host)")
	return o
}

// startMesh creates and starts an embedded NetBird client.
// All NetBird logs are directed to logOut (never stdout: the connect
// command uses stdout as the MCP channel).
func startMesh(o *meshOptions, logOut io.Writer) (*embed.Client, error) {
	if o.DeviceName == "" {
		host, _ := os.Hostname()
		o.DeviceName = "meshmcp-" + strings.ToLower(host)
	}
	if o.ManagementURL == "" {
		o.ManagementURL = defaultManagementURL
	}
	if o.SetupKey == "" {
		return nil, errors.New("setup key required: pass --setup-key, set NB_SETUP_KEY, or set mesh.setup_key in the config")
	}
	if o.StartTimeout <= 0 {
		o.StartTimeout = 2 * time.Minute
	}

	// Always pass a non-nil pointer so 0 selects a random port; a nil
	// pointer would fall back to the fixed default (51820) and collide
	// with any other peer on the same host.
	wgPort := o.WireguardPort
	client, err := embed.New(embed.Options{
		DeviceName:    o.DeviceName,
		ManagementURL: o.ManagementURL,
		SetupKey:      o.SetupKey,
		ConfigPath:    o.ConfigPath,
		LogOutput:     logOut,
		LogLevel:      o.LogLevel,
		DNSLabels:     o.DNSLabels,
		BlockInbound:  o.BlockInbound,
		WireguardPort: &wgPort,
	})
	if err != nil {
		return nil, fmt.Errorf("create embedded netbird client: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), o.StartTimeout)
	defer cancel()
	if err := client.Start(ctx); err != nil {
		return nil, fmt.Errorf("join mesh: %w", err)
	}
	return client, nil
}

func stopMesh(client *embed.Client) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = client.Stop(ctx)
}
