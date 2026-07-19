// Package mobile is the gomobile-bindable surface of meshmcp: a thin,
// string/error-only wrapper over the embedded NetBird client and the MCP client,
// so an iOS/Android app can join the mesh with its own WireGuard identity, call
// tools on a backend, and approve held co-sign calls.
//
// It compiles as an ordinary Go package. To produce a mobile framework:
//
//	go install golang.org/x/mobile/cmd/gomobile@latest && gomobile init
//	gomobile bind -target=ios     -o Meshmcp.xcframework ./mobile   # iOS
//	gomobile bind -target=android -o meshmcp.aar          ./mobile   # Android
//
// gomobile requires the iOS/Android toolchain and a device/simulator to run;
// that step is external to this repo. The binding rule this package follows:
// every exported method takes and returns only strings and errors (no Go maps,
// slices of structs, or channels crossing the boundary), so the generated
// Swift/Kotlin API stays simple.
package mobile

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/netbirdio/netbird/client/embed"

	"meshmcp/mcpclient"
)

const defaultManagementURL = "https://api.netbird.io:443"

// Mesh is a joined mesh membership (one WireGuard identity).
type Mesh struct{ c *embed.Client }

// Join brings the device onto the mesh as its own peer. setupKey is required;
// managementURL and deviceName may be empty for defaults; configPath persists
// the identity across launches (empty = a new peer each run). It blocks until
// joined or the 2-minute join timeout elapses.
func Join(setupKey, managementURL, deviceName, configPath string) (*Mesh, error) {
	if setupKey == "" {
		return nil, fmt.Errorf("setup key is required")
	}
	if managementURL == "" {
		managementURL = defaultManagementURL
	}
	if deviceName == "" {
		deviceName = "meshmcp-mobile"
	}
	wgPort := 0 // random; the phone dials out
	c, err := embed.New(embed.Options{
		DeviceName:    deviceName,
		ManagementURL: managementURL,
		SetupKey:      setupKey,
		ConfigPath:    configPath,
		LogOutput:     io.Discard,
		LogLevel:      "error",
		BlockInbound:  true,
		WireguardPort: &wgPort,
	})
	if err != nil {
		return nil, fmt.Errorf("create mesh client: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := c.Start(ctx); err != nil {
		return nil, fmt.Errorf("join mesh: %w", err)
	}
	return &Mesh{c: c}, nil
}

// Identity returns this device's mesh FQDN.
func (m *Mesh) Identity() (string, error) {
	st, err := m.c.Status()
	if err != nil {
		return "", err
	}
	return st.LocalPeerState.FQDN, nil
}

// Close leaves the mesh.
func (m *Mesh) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return m.c.Stop(ctx)
}

// Conn is an initialized MCP client to one backend over the mesh.
type Conn struct{ c *mcpclient.Client }

// Dial connects to a backend (mesh-ip:port) and completes the MCP handshake.
func (m *Mesh) Dial(target string) (*Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	raw, err := m.c.Dial(ctx, "tcp", target)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", target, err)
	}
	cl := mcpclient.New(raw, nil)
	if _, err := cl.Initialize(ctx, "meshmcp-mobile"); err != nil {
		cl.Close()
		return nil, fmt.Errorf("initialize %s: %w", target, err)
	}
	return &Conn{c: cl}, nil
}

// Call invokes a tool. argsJSON is a JSON object string ("{}" for none); the
// result is returned as a JSON string.
func (c *Conn) Call(tool, argsJSON string) (string, error) {
	if strings.TrimSpace(argsJSON) == "" {
		argsJSON = "{}"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	res, err := c.c.CallTool(ctx, tool, json.RawMessage(argsJSON), false)
	if err != nil {
		return "", err
	}
	return string(res), nil
}

// Close closes the connection.
func (c *Conn) Close() error { return c.c.Close() }

// Approvals is the phone-as-approver client: it reaches a gateway's approver
// endpoint over the mesh so the human can co-sign held calls.
type Approvals struct {
	hc   *http.Client
	base string
}

// Approvals returns a client for the approver served at gateway (mesh-ip:port).
func (m *Mesh) Approvals(gateway string) *Approvals {
	return &Approvals{
		base: "http://approvals",
		hc: &http.Client{
			Timeout: 20 * time.Second,
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					return m.c.Dial(ctx, "tcp", gateway)
				},
			},
		},
	}
}

// Pending returns the held co-sign requests as a JSON string.
func (a *Approvals) Pending() (string, error) {
	resp, err := a.hc.Get(a.base + "/v1/pending")
	if err != nil {
		return "", err
	}
	return readBody(resp)
}

// Approve co-signs a held call for (peer, tool).
func (a *Approvals) Approve(peer, tool string) error { return a.decide("/v1/approve", peer, tool) }

// Deny rejects a held call for (peer, tool).
func (a *Approvals) Deny(peer, tool string) error { return a.decide("/v1/deny", peer, tool) }

func (a *Approvals) decide(path, peer, tool string) error {
	body, _ := json.Marshal(map[string]string{"peer": peer, "tool": tool})
	resp, err := a.hc.Post(a.base+path, "application/json", strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	_, err = readBody(resp)
	return err
}

func readBody(resp *http.Response) (string, error) {
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	return string(b), nil
}
