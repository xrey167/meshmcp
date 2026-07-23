package session

import (
	"bufio"
	"errors"
	"net"
	"sync"
	"time"
)

// errRebound is returned by pump when the endpoint's connection was
// replaced by a newer bind (a concurrent reattach). The old pump exits
// quietly; the new one is already running.
var errRebound = errors.New("session: connection rebound")

// errSendOverflow closes a session whose peer fell too far behind: the
// bounded send buffer stayed full past sendOverflowTimeout.
var errSendOverflow = errors.New("session: send buffer overflow (peer too slow / gone)")

// endpoint is the shared reliable-delivery core used by both the client
// and each server-side session. It provides ordered, exactly-once
// application-byte delivery over a transport connection that may be
// swapped out at any time via bind.
type endpoint struct {
	id sessionID

	mu       sync.Mutex
	conn     net.Conn
	w        *bufio.Writer
	connGen  uint64  // incremented on every bind; identifies the live conn
	sendSeq  uint64  // seq of the last DATA we assigned
	acked    uint64  // peer has acknowledged our DATA up to here
	sendBuf  []frame // unacked outbound DATA frames, ascending seq
	recvSeq  uint64  // highest contiguous inbound DATA seq delivered
	closed   bool
	closeErr error

	inbound  chan []byte // ordered, exactly-once inbound application bytes
	closeC   chan struct{}
	closeOne sync.Once

	// slots is a semaphore bounding the unacked send buffer: one token per
	// free buffer frame. Send takes a token; an ack returns tokens. When
	// empty, Send blocks (backpressure) instead of growing without bound.
	slots chan struct{}

	// afterAck, if set, is called after an inbound ACK advances the send
	// cursor — the consistent point to checkpoint for session migration.
	afterAck func()
}

func newEndpoint(id sessionID) *endpoint {
	return newEndpointCap(id, defaultMaxSendFrames)
}

// newEndpointCap bounds the unacked send buffer to cap frames. Send applies
// backpressure when the buffer is full and closes the session only if the
// peer stays too far behind past sendOverflowTimeout.
func newEndpointCap(id sessionID, cap int) *endpoint {
	if cap <= 0 {
		cap = defaultMaxSendFrames
	}
	slots := make(chan struct{}, cap)
	for i := 0; i < cap; i++ {
		slots <- struct{}{}
	}
	return &endpoint{
		id:      id,
		inbound: make(chan []byte, 256),
		closeC:  make(chan struct{}),
		slots:   slots,
	}
}

// Send queues application bytes for exactly-once delivery to the peer.
// It always buffers (so nothing is lost while disconnected) and writes
// immediately if a connection is currently bound. A write failure is
// swallowed here: the frame stays buffered and is replayed after the
// next successful bind.
func (e *endpoint) Send(p []byte) error {
	if len(p) == 0 {
		return nil
	}
	// Flow control: take a buffer slot before appending. On the fast path a
	// slot is free; otherwise Send blocks (backpressure to the producer)
	// until acks free one, or closes the session if the peer stays too far
	// behind for sendOverflowTimeout.
	select {
	case <-e.slots:
	case <-e.closeC:
		return e.closeErr
	default:
		timer := time.NewTimer(sendOverflowTimeout)
		select {
		case <-e.slots:
			timer.Stop()
		case <-e.closeC:
			timer.Stop()
			return e.closeErr
		case <-timer.C:
			e.closeWith(errSendOverflow)
			return errSendOverflow
		}
	}

	// Copy: the caller's buffer (a read buffer) will be reused.
	b := make([]byte, len(p))
	copy(b, p)

	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return e.closeErr
	}
	e.sendSeq++
	f := frame{typ: frameData, seq: e.sendSeq, payload: b}
	e.sendBuf = append(e.sendBuf, f)
	if e.w != nil {
		if err := e.writeFrameLocked(f); err != nil {
			// Drop the dead connection; pump will notice and reconnect.
			e.dropConnLocked()
		}
	}
	return nil
}

// writeFrameLocked writes a frame to the bound connection with a write
// deadline, so a stalled/half-open peer cannot block the endpoint mutex
// indefinitely. The caller holds e.mu and has checked e.w != nil.
func (e *endpoint) writeFrameLocked(f frame) error {
	if e.conn != nil {
		_ = e.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	}
	return writeFrame(e.w, f)
}

// Inbound delivers application bytes received from the peer, in order,
// exactly once. Closed when the session ends.
func (e *endpoint) Inbound() <-chan []byte { return e.inbound }

// Done is closed when the endpoint is permanently closed.
func (e *endpoint) Done() <-chan struct{} { return e.closeC }

// bind installs a new transport connection and (re)sends any unacked
// outbound frames the peer has not confirmed. peerRecv is the peer's
// reported highest received seq (from an ATTACH / ATTACH_OK handshake),
// which also acknowledges everything up to peerRecv. It returns the
// generation of this binding; the pump uses it to tell a genuine drop of
// its own connection from being replaced by a newer bind.
func (e *endpoint) bind(conn net.Conn, peerRecv uint64) uint64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.ackLocked(peerRecv)
	// Close any previous connection so its pump unblocks and exits promptly,
	// bounding the window in which two pumps run against one endpoint.
	if e.conn != nil {
		_ = e.conn.Close()
	}
	e.conn = conn
	e.w = bufio.NewWriter(conn)
	e.connGen++
	gen := e.connGen
	// Replay everything the peer hasn't acknowledged.
	for _, f := range e.sendBuf {
		if err := e.writeFrameLocked(f); err != nil {
			e.dropConnLocked()
			break
		}
	}
	return gen
}

// pumpReader reads frames using a caller-supplied reader, so a reader that
// already consumed the handshake frame (and possibly replay bytes after it)
// continues seamlessly. gen is this connection's bind generation.
func (e *endpoint) pumpReader(conn net.Conn, r *bufio.Reader, gen uint64) error {
	for {
		if e.isClosed() {
			return e.closeErr
		}
		// Detect roaming/half-open transports: no frame (not even a
		// keepalive PING) within the idle window means the link is dead.
		_ = conn.SetReadDeadline(time.Now().Add(idleTimeout))
		f, err := readFrame(r)
		if err != nil {
			e.mu.Lock()
			rebound := e.connGen != gen
			e.mu.Unlock()
			if rebound {
				return errRebound
			}
			return err
		}

		switch f.typ {
		case frameData:
			e.mu.Lock()
			if f.seq == e.recvSeq+1 {
				e.recvSeq = f.seq
				seqNow := e.recvSeq
				e.mu.Unlock()
				// Acknowledge endpoint receipt before handing the payload to the
				// application. The application may immediately emit reverse DATA;
				// delivering first can make both transport readers synchronously
				// write ACKs at each other and deadlock on an unbuffered/full link.
				e.sendAck(seqNow)
				select {
				case e.inbound <- f.payload:
				case <-e.closeC:
					return e.closeErr
				}
			} else {
				// Duplicate from a replay (seq <= recvSeq) or an
				// impossible gap on an ordered transport: re-ack our
				// cursor so the peer can advance and stop resending.
				cur := e.recvSeq
				e.mu.Unlock()
				e.sendAck(cur)
			}
		case frameAck:
			e.mu.Lock()
			e.ackLocked(f.seq)
			cb := e.afterAck
			e.mu.Unlock()
			// The peer confirmed receipt up to f.seq, so a checkpoint taken
			// now has sendSeq >= what the peer has — a resuming gateway
			// won't reuse sequence numbers the peer already consumed.
			if cb != nil {
				cb()
			}
		case framePing:
			e.writeControl(frame{typ: framePong})
		case framePong:
			// liveness only; the read deadline reset above is the effect
		case frameClose:
			e.closeWith(nil)
			return nil
		case frameError:
			err := errors.New("session: peer error: " + string(f.payload))
			e.closeWith(err)
			return err
		}
	}
}

// sendAck writes an ACK for the given cursor on the current connection.
func (e *endpoint) sendAck(seq uint64) {
	e.writeControl(frame{typ: frameAck, seq: seq})
}

// writeControl writes a small control frame under the lock, tolerating a
// dead connection (the frame is best-effort; state is the source of truth).
func (e *endpoint) writeControl(f frame) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.w == nil {
		return
	}
	if err := e.writeFrameLocked(f); err != nil {
		e.dropConnLocked()
	}
}

// ackLocked drops buffered outbound frames the peer has confirmed.
func (e *endpoint) ackLocked(upto uint64) {
	if upto <= e.acked {
		return
	}
	e.acked = upto
	i := 0
	for i < len(e.sendBuf) && e.sendBuf[i].seq <= upto {
		i++
	}
	if i > 0 {
		e.sendBuf = append(e.sendBuf[:0], e.sendBuf[i:]...)
		// Return one slot per acknowledged frame so blocked Sends proceed.
		for k := 0; k < i; k++ {
			select {
			case e.slots <- struct{}{}:
			default:
			}
		}
	}
}

// dropConnLocked detaches the current connection; the caller holds mu.
func (e *endpoint) dropConnLocked() {
	if e.conn != nil {
		_ = e.conn.Close()
		e.conn = nil
		e.w = nil
	}
}

func (e *endpoint) recvCursor() uint64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.recvSeq
}

// drained reports whether the peer has acknowledged every DATA frame sent.
func (e *endpoint) drained() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.acked >= e.sendSeq
}

func (e *endpoint) isClosed() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.closed
}

func (e *endpoint) closeError() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.closeErr
}

// closeWith permanently closes the endpoint. It closes closeC exactly once
// and never closes inbound: a pump goroutine may be parked on a send to
// inbound, and closing it would let select choose the send arm and panic.
// Consumers of Inbound() exit via Done() instead.
func (e *endpoint) closeWith(err error) {
	e.closeOne.Do(func() {
		e.mu.Lock()
		e.closed = true
		e.closeErr = err
		e.dropConnLocked()
		e.mu.Unlock()
		close(e.closeC)
	})
}

// sendClose tries to tell the peer the session is ending, then closes.
func (e *endpoint) sendClose() {
	e.writeControl(frame{typ: frameClose})
	e.closeWith(nil)
}
