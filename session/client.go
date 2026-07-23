package session

import (
	"bufio"
	"context"
	"errors"
	"fmt"
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
	dial                 Dialer
	logf                 func(string, ...any)
	ep                   *endpoint
	drainWait            time.Duration
	initialAttachTimeout time.Duration
}

var (
	errAttachRejected   = errors.New("session: server rejected attach")
	errInvalidSessionID = errors.New("session: server returned an invalid logical session id")
	errSessionChanged   = errors.New("session: resumed server changed the logical session id")
)

// NewClient creates a session client. logf may be nil.
func NewClient(dial Dialer, logf func(string, ...any)) *Client {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &Client{
		dial:      dial,
		logf:      logf,
		ep:        newEndpoint(sessionID{}), // id assigned by the server on first ATTACH_OK
		drainWait: drainTimeout,
	}
}

// WithInitialAttachTimeout bounds the time spent establishing the first
// session attachment, including dial failures, handshake failures, and retry
// backoff. A non-positive duration disables the bound, which is the default
// for backward compatibility. Configure the client before calling Run.
func (c *Client) WithInitialAttachTimeout(d time.Duration) *Client {
	if d < 0 {
		d = 0
	}
	c.initialAttachTimeout = d
	return c
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
					c.ep.closeWith(serr)
					return
				}
			}
			if err != nil {
				// Local client closed: end the logical session gracefully.
				// Wait (bounded) for the peer to acknowledge everything we
				// sent first — closing the transport with peer ACKs still
				// unread in our receive buffer turns the close into a TCP
				// RST, which can discard our in-flight DATA/CLOSE frames in
				// the peer's receive buffer (a drop then never finalizes).
				if derr := c.awaitDrain(); derr != nil {
					c.ep.closeWith(derr)
					return
				}
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
	var initialCtx context.Context
	var cancelInitial context.CancelFunc
	if c.initialAttachTimeout > 0 {
		initialCtx, cancelInitial = context.WithTimeout(ctx, c.initialAttachTimeout)
		defer cancelInitial()
	}
	initialTimedOut := func() bool {
		if initialCtx == nil {
			return false
		}
		if initialCtx.Err() != nil {
			return true
		}
		deadline, ok := initialCtx.Deadline()
		return ok && !time.Now().Before(deadline)
	}
	initialTimeoutError := func() error {
		return fmt.Errorf("session: initial attach timed out after %s: %w", c.initialAttachTimeout, context.DeadlineExceeded)
	}

	for {
		if c.ep.isClosed() {
			return c.ep.closeError()
		}
		if err := ctx.Err(); err != nil {
			c.ep.closeWith(err)
			return err
		}
		if first && initialTimedOut() {
			err := initialTimeoutError()
			c.ep.closeWith(err)
			return err
		}

		attemptCtx := ctx
		if first && initialCtx != nil {
			attemptCtx = initialCtx
		}
		conn, recv, r, err := c.handshake(attemptCtx)
		if err != nil {
			if errors.Is(err, errAttachRejected) || errors.Is(err, errInvalidSessionID) || errors.Is(err, errSessionChanged) {
				c.ep.closeWith(err)
				return err
			}
			if c.ep.isClosed() {
				return c.ep.closeError()
			}
			if ctx.Err() != nil {
				c.ep.closeWith(ctx.Err())
				return ctx.Err()
			}
			if first && initialTimedOut() {
				err = initialTimeoutError()
				c.ep.closeWith(err)
				return err
			}
			c.logf("session: reconnect failed: %v (retrying in %s)", err, backoff)
			if !sleepCtx(attemptCtx, c.ep.Done(), backoff) {
				if c.ep.isClosed() {
					return c.ep.closeError()
				}
				if ctx.Err() != nil {
					c.ep.closeWith(ctx.Err())
					return ctx.Err()
				}
				if first && initialTimedOut() {
					err = initialTimeoutError()
					c.ep.closeWith(err)
					return err
				}
				continue
			}
			backoff = nextBackoff(backoff, maxBackoff)
			continue
		}
		if !first {
			c.logf("session %s: reattached, resuming", c.ep.id)
		}
		if first && cancelInitial != nil {
			cancelInitial()
			cancelInitial = nil
			initialCtx = nil
		}
		first = false
		backoff = 250 * time.Millisecond

		gen := c.ep.bind(conn, recv)
		// Reuse the handshake reader: the server may have pipelined the
		// replayed backlog right after ATTACH_OK into r's buffer, and a
		// fresh reader would discard it.
		err = c.ep.pumpReader(conn, r, gen)
		if c.ep.isClosed() {
			return c.ep.closeError()
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
	// Until bind installs conn on the endpoint, closeWith cannot reach it. A
	// silent or protocol-incompatible peer could otherwise hold readFrame until
	// the long idle deadline even after the caller or finite-send drain expired.
	watchDone := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-c.ep.Done():
			_ = conn.Close()
		case <-watchDone:
		}
	}()
	defer close(watchDone)
	deadline := time.Now().Add(idleTimeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	_ = conn.SetDeadline(deadline)

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
		prefix := errAttachRejected.Error() + ": "
		message := sanitizeErrorText(f.payload, maxPeerErrorBytes-len(prefix))
		return nil, 0, nil, fmt.Errorf("%w: %s", errAttachRejected, message)
	}
	if f.typ != frameAttachOK {
		conn.Close()
		return nil, 0, nil, errors.New("session: expected ATTACH_OK")
	}
	if f.id.isZero() {
		conn.Close()
		return nil, 0, nil, errInvalidSessionID
	}
	if !c.ep.id.isZero() && f.id != c.ep.id {
		conn.Close()
		return nil, 0, nil, errSessionChanged
	}
	if c.ep.id.isZero() {
		c.ep.id = f.id
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, f.seq, r, nil
}

// drainTimeout bounds how long a closing client waits for the peer to
// acknowledge all sent data before closing the transport anyway.
const drainTimeout = 10 * time.Second

var (
	errDrainTimeout = errors.New("session: peer did not acknowledge sent data before close timeout")
	errDrainClosed  = errors.New("session: peer closed before acknowledging sent data")
)

// awaitDrain blocks until every sent DATA frame is acknowledged, the session
// ends, or the bounded drain wait passes. An unacknowledged timeout is an
// error: callers must never report a one-shot Push/Drop/Ring as delivered when
// no receiver accepted its transport frames.
func (c *Client) awaitDrain() error {
	if c.ep.drained() {
		return nil
	}
	wait := c.drainWait
	if wait <= 0 {
		wait = drainTimeout
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-c.ep.Done():
			if c.ep.drained() {
				return nil
			}
			if err := c.ep.closeError(); err != nil {
				return err
			}
			return errDrainClosed
		case <-timer.C:
			if c.ep.drained() {
				return nil
			}
			return errDrainTimeout
		case <-tick.C:
			if c.ep.drained() {
				return nil
			}
		}
	}
}

// WaitForDrain waits until the peer has transport-acknowledged every DATA frame
// currently queued by this client. Callers that need application-level
// completion can use this to begin their response deadline only after outbound
// bytes have reached the peer's session endpoint.
func (c *Client) WaitForDrain(ctx context.Context) error {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		c.ep.mu.Lock()
		drained := c.ep.acked >= c.ep.sendSeq
		closed := c.ep.closed
		closeErr := c.ep.closeErr
		c.ep.mu.Unlock()
		if drained {
			return nil
		}
		if closed {
			if closeErr != nil {
				return closeErr
			}
			return errors.New("session closed before outbound data was acknowledged")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
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

func sleepCtx(ctx context.Context, done <-chan struct{}, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-done:
		return false
	case <-t.C:
		return true
	}
}
