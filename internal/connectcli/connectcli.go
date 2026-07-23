// Package connectcli holds the connect-only slice of the meshmcp CLI: joining
// the mesh as an outbound peer and bridging local stdio to a remote stdio MCP
// backend. It is shared, not forked — the full `meshmcp` binary delegates its
// mesh flags and `connect` subcommand here, and the thin `meshmcp-connect`
// binary (S45) is just this package plus a main, so an MCP client host can
// ship a small bridge without the policy/air/control surface.
package connectcli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/netbirdio/netbird/client/embed"

	"github.com/xrey167/meshmcp/session"
)

// DefaultManagementURL is the NetBird management endpoint used when neither a
// flag nor $NB_MANAGEMENT_URL supplies one.
const DefaultManagementURL = "https://api.netbird.io:443"

// MeshOptions holds everything needed to join the mesh as an embedded peer.
type MeshOptions struct {
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

// MeshFlags registers the shared mesh flags on a command's flag set.
func MeshFlags(fs *flag.FlagSet) *MeshOptions {
	o := &MeshOptions{}
	fs.StringVar(&o.DeviceName, "device-name", "", "peer name in the mesh (default: meshmcp-<hostname>)")
	fs.StringVar(&o.ManagementURL, "management-url", os.Getenv("NB_MANAGEMENT_URL"), "NetBird management server URL (default: $NB_MANAGEMENT_URL or api.netbird.io)")
	fs.StringVar(&o.SetupKey, "setup-key", os.Getenv("NB_SETUP_KEY"), "NetBird setup key (default: $NB_SETUP_KEY)")
	fs.StringVar(&o.ConfigPath, "nb-config", "", "path to persist the NetBird identity; empty = in-memory, new peer each run")
	fs.StringVar(&o.LogLevel, "log-level", "error", "NetBird client log level")
	fs.DurationVar(&o.StartTimeout, "start-timeout", 2*time.Minute, "timeout for joining the mesh")
	fs.IntVar(&o.WireguardPort, "wg-port", 0, "local WireGuard UDP port; 0 = random (use random when running multiple peers on one host)")
	return o
}

// StartMesh creates and starts an embedded NetBird client.
// All NetBird logs are directed to logOut (never stdout: the connect
// command uses stdout as the MCP channel).
func StartMesh(o *MeshOptions, logOut io.Writer) (*embed.Client, error) {
	if o.DeviceName == "" {
		host, _ := os.Hostname()
		o.DeviceName = "meshmcp-" + strings.ToLower(host)
	}
	if o.ManagementURL == "" {
		o.ManagementURL = DefaultManagementURL
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

// StopMesh stops the embedded client, bounded so shutdown cannot hang.
func StopMesh(client *embed.Client) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = client.Stop(ctx)
}

// Connect joins the mesh and bridges stdio to a remote stdio backend.
// This is the command MCP clients (e.g. Claude Code) launch as a "stdio
// MCP server": stdout carries the MCP channel, all logs go to stderr.
func Connect(args []string) error {
	fs := flag.NewFlagSet("connect", flag.ExitOnError)
	o := MeshFlags(fs)
	resumable := fs.Bool("resumable", false, "keep the logical session alive across mesh reconnects (backend must be resumable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: meshmcp connect [flags] <peer-ip:port>")
	}
	target := fs.Arg(0)

	o.BlockInbound = true // outbound-only peer
	client, err := StartMesh(o, os.Stderr)
	if err != nil {
		return err
	}
	defer StopMesh(client)

	if *resumable {
		return connectResumable(client, target)
	}

	conn, err := client.Dial(context.Background(), "tcp", target)
	if err != nil {
		return fmt.Errorf("dial %s over mesh: %w", target, err)
	}
	defer conn.Close()
	log.Printf("connected to %s", target)

	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(conn, os.Stdin)
		conn.Close() // local client hung up: end the session
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(os.Stdout, conn)
		done <- struct{}{}
	}()
	<-done
	return nil
}

// connectResumable bridges local stdio to a resumable mesh session that
// transparently reconnects and resyncs whenever the mesh transport drops.
func connectResumable(client *embed.Client, target string) error {
	dial := func(ctx context.Context) (net.Conn, error) {
		return client.Dial(ctx, "tcp", target)
	}
	sc := session.NewClient(dial, log.Printf)
	log.Printf("resumable session to %s", target)
	return sc.Run(context.Background(), stdio{})
}

// stdio adapts the process's stdin/stdout to an io.ReadWriteCloser.
type stdio struct{}

func (stdio) Read(p []byte) (int, error)  { return os.Stdin.Read(p) }
func (stdio) Write(p []byte) (int, error) { return os.Stdout.Write(p) }
func (stdio) Close() error                { return os.Stdin.Close() }
