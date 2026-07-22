package session

import (
	"io"
	"os"
	"os/exec"
	"time"
)

// Timing knobs shared by both ends. Values are deliberately generous so a
// phone flipping Wi-Fi/LTE or a laptop resuming from sleep reattaches to
// the same session rather than losing it.
const (
	// idleTimeout is how long pump waits for any frame before treating the
	// transport as dead. Keepalive PINGs keep it from firing on quiet links.
	idleTimeout = 45 * time.Second
	// keepaliveInterval is how often the client sends a PING.
	keepaliveInterval = 15 * time.Second
	// writeTimeout bounds a single frame write, so a stalled/half-open peer
	// cannot hold the endpoint mutex indefinitely on conn.Write.
	writeTimeout = 20 * time.Second
	// defaultMaxSendFrames bounds the unacked send buffer (per direction).
	// Send blocks (backpressure) once this many frames are outstanding.
	defaultMaxSendFrames = 1024
	// maxReplayBytes bounds the migration replay-capture buffer. A resumable
	// session captures inbound peer->backend bytes so another gateway can
	// replay them after a failover; without a cap, a peer that streams input
	// but never finishes the handshake grows this buffer (and, via the
	// per-message checkpoint, its on-disk copy) without bound. Generous for a
	// real MCP handshake + early traffic; a session exceeding it is closed.
	maxReplayBytes = 8 << 20
	// sendOverflowTimeout is how long Send waits on a full buffer before
	// closing the session (the peer is gone or hopelessly behind).
	sendOverflowTimeout = 60 * time.Second
	// DefaultSessionTTL is how long a server keeps a detached session
	// (backend alive, buffers intact) waiting for the client to reattach.
	DefaultSessionTTL = 2 * time.Minute
)

// Meta describes the peer that opened a session. It is passed to the
// backend factory so a spawned subprocess can be told who is calling.
type Meta struct {
	PeerFQDN string
	PeerAddr string
	PeerKey  string
	// SessionID identifies the logical session. A stateful backend can key
	// its own persisted state (its EventStore) on it, so a fresh backend
	// spawned on another gateway during migration restores the same session.
	SessionID string
}

// MigrationMode selects how a session's backend state is reconstructed when
// another gateway resumes the session.
type MigrationMode int

const (
	// MigrateHandshake replays only the client->backend handshake against a
	// fresh backend. Safe for stateless backends (each request independent).
	MigrateHandshake MigrationMode = iota
	// MigrateFull replays the entire client->backend log. Safe for backends
	// whose per-session state is a deterministic function of their input
	// (internal/idempotent) — it re-executes inputs.
	MigrateFull
	// MigrateBackend does not replay: the backend restores its own per-session
	// state from MESHMCP_SESSION_ID (its own EventStore). For truly stateful
	// backends with external side effects.
	MigrateBackend
)

// Backend is one end of an MCP server's stdio: reads carry server->client
// bytes, writes carry client->server bytes. Close terminates it.
type Backend interface {
	io.ReadWriteCloser
}

// BackendFactory creates a fresh backend for a new session.
type BackendFactory func(meta Meta) (Backend, error)

// ExecBackendFactory returns a factory that spawns cmd/args as a
// subprocess, wiring its stdin/stdout to the session and inheriting the
// parent's stderr. The caller's env is extended with MESHMCP_PEER*.
func ExecBackendFactory(name string, args, baseEnv []string) BackendFactory {
	return func(meta Meta) (Backend, error) {
		cmd := exec.Command(name, args...)
		cmd.Stderr = os.Stderr
		cmd.Env = append(append([]string{}, baseEnv...),
			"MESHMCP_PEER="+meta.PeerFQDN,
			"MESHMCP_PEER_ADDR="+meta.PeerAddr,
			"MESHMCP_PEER_KEY="+meta.PeerKey,
			"MESHMCP_SESSION_ID="+meta.SessionID,
		)
		stdin, err := cmd.StdinPipe()
		if err != nil {
			return nil, err
		}
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			return nil, err
		}
		if err := cmd.Start(); err != nil {
			return nil, err
		}
		return &execBackend{cmd: cmd, stdin: stdin, stdout: stdout}, nil
	}
}

type execBackend struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout io.ReadCloser
}

func (b *execBackend) Read(p []byte) (int, error)  { return b.stdout.Read(p) }
func (b *execBackend) Write(p []byte) (int, error) { return b.stdin.Write(p) }

func (b *execBackend) Close() error {
	_ = b.stdin.Close()
	if b.cmd.Process != nil {
		_ = b.cmd.Process.Kill()
	}
	_ = b.stdout.Close()
	_, _ = b.cmd.Process.Wait()
	return nil
}
