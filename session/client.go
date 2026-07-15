package session

import (
	"bufio"
	"context"
	"errors"
	"io"
	"math/rand"
	"net"
	"time"
)

// Dialer opens a fresh transport connection to the backend session server.
// In production this dials over the mesh; in tests it dials loopback.
type Dialer func(ctx context.Context) (net.Conn, error)

// Client runs one resumable session from the caller's side: it bridges a
// local application stream (an MCP client's stdin/stdout) to a remote
// session server, transparently reconnecting and resyncing whenever the
// transport drops.
type Client struct {
	dial Dialer
	logf func(string, ...any)
	ep   *endpoint
}

// NewClient creates a session client. logf may be nil.
func NewClient(dial Dialer, logf func(string, ...any)) *Client {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &Client{
		dial: dial,
		logf: logf,
		ep:   newEndpoint(sessionID{}), // id assigned by the server on first ATTACH_OK
	}
}

// Run bridges local (an MCP client's stdio) to the remote session until
// local hits EOF, the session ends, or ctx is cancelled. local's Read is
// server-bound data source; writes to local carry data from the server.
func (c *Client) Run(ctx context.Context, local io.ReadWriteCloser) error {
	// local stdin -> endpoint (buffered, survives disconnects)
	go func() {
		buf := make([]byte, maxPayload)
		for {
			n, err := local.Read(buf)
			if n > 0 {
				if serr := c.ep.Send(buf[:n]); serr != nil {
					return
				}
			}
			if err != nil {
				// Local client closed: end the logical session gracefully.
				c.ep.sendClose()
				return
			}
		}
	}()
	// endpoint -> local stdout
	go func() {
		for {
			select {
			case p, ok := <-c.ep.Inbound():
				if !ok {
					return
				}
				if _, err := local.Write(p); err != nil {
					c.ep.closeWith(err)
					return
				}
			case <-c.ep.Done():
				return
			}
		}
	}()
	// keepalive so idle sessions don't trip the idle timeout
	go c.keepalive()

	return c.reconnectLoop(ctx)
}

// reconnectLoop maintains a live transport under the endpoint, redialing
// with backoff whenever pump returns because the connection dropped.
func (c *Client) reconnectLoop(ctx context.Context) error {
	backoff := 250 * time.Millisecond
	const maxBackoff = 10 * time.Second
	first := true

	for {
		if c.ep.isClosed() {
			return c.ep.closeErr
		}
		if err := ctx.Err(); err != nil {
			c.ep.closeWith(err)
			return err
		}

		conn, recv, r, err := c.handshake(ctx)
		if err != nil {
			if c.ep.isClosed() {
				return c.ep.closeErr
			}
			c.logf("session: reconnect failed: %v (retrying in %s)", err, backoff)
			if !sleepCtx(ctx, backoff) {
				c.ep.closeWith(ctx.Err())
				return ctx.Err()
			}
			backoff = nextBackoff(backoff, maxBackoff)
			continue
		}
		if !first {
			c.logf("session %s: reattached, resuming", c.ep.id)
		}
		first = false
		backoff = 250 * time.Millisecond

		gen := c.ep.bind(conn, recv)
		// Reuse the handshake reader: the server may have pipelined the
		// replayed backlog right after ATTACH_OK into r's buffer, and a
		// fresh reader would discard it.
		err = c.ep.pumpReader(conn, r, gen)
		if c.ep.isClosed() {
			return c.ep.closeErr
		}
		if errors.Is(err, errRebound) {
			continue
		}
		c.logf("session %s: transport dropped (%v), reconnecting", c.ep.id, err)
	}
}

// handshake dials a fresh connection and performs the ATTACH / ATTACH_OK
// exchange, returning the connection, the server's receive cursor, and the
// buffered reader used for the exchange (which the pump must reuse so any
// replay bytes read-ahead after ATTACH_OK are not lost).
func (c *Client) handshake(ctx context.Context) (net.Conn, uint64, *bufio.Reader, error) {
	conn, err := c.dial(ctx)
	if err != nil {
		return nil, 0, nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(idleTimeout))

	w := bufio.NewWriter(conn)
	if err := writeFrame(w, frame{typ: frameAttack, id: c.ep.id, seq: c.ep.recvCursor()}); err != nil {
		conn.Close()
		return nil, 0, nil, err
	}
	r := bufio.NewReaderSize(conn, maxPayload+64)
	f, err := readFrame(r)
	if err != nil {
		conn.Close()
		return nil, 0, nil, err
	}
	if f.typ == frameError {
		conn.Close()
		return nil, 0, nil, errors.New("server rejected attach: " + string(f.payload))
	}
	if f.typ != frameAttachOK {
		conn.Close()
		return nil, 0, nil, errors.New("session: expected ATTACH_OK")
	}
	if c.ep.id.isZero() {
		c.ep.id = f.id
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, f.seq, r, nil
}

func (c *Client) keepalive() {
	t := time.NewTicker(keepaliveInterval)
	defer t.Stop()
	for {
		select {
		case <-c.ep.Done():
			return
		case <-t.C:
			c.ep.writeControl(frame{typ: framePing})
		}
	}
}

// SessionID returns the negotiated session id (empty until the first
// successful handshake).
func (c *Client) SessionID() string { return c.ep.id.String() }

func nextBackoff(cur, max time.Duration) time.Duration {
	next := cur * 2
	if next > max {
		next = max
	}
	// jitter ±20% to avoid synchronized reconnect storms
	j := time.Duration(rand.Int63n(int64(next) / 5))
	return next - next/10 + j
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
