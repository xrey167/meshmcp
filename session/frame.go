// Package session provides a resumable, exactly-once session layer over a
// replaceable byte-stream transport. It lets a logical MCP session survive
// the underlying mesh connection being dropped and re-established (peer
// roaming, sleep/wake, TURN relay switch) without the MCP client or server
// observing any interruption.
//
// The model mirrors the reliability core of Tencent's Mars STN: each side
// numbers the application chunks it sends, buffers them until the peer
// acknowledges receipt, and on reconnect replays whatever the peer reports
// it never saw. Delivery to the application is strictly ordered and
// exactly-once in both directions.
package session

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
)

type frameType uint8

const (
	frameAttach   frameType = 1 // ATTACH: client -> server, open or resume a session
	frameAttachOK frameType = 2 // ATTACH_OK: server -> client, session id + server's recv cursor
	frameData     frameType = 3 // DATA: application bytes with a sequence number
	frameAck      frameType = 4 // ACK: highest contiguous seq received
	framePing     frameType = 5
	framePong     frameType = 6
	frameClose    frameType = 7 // graceful end of the logical session
	frameError    frameType = 8 // fatal protocol error, carries a message
)

const (
	sessionIDLen = 16
	// maxPayload bounds a single DATA frame; also the read chunk size.
	maxPayload = 64 * 1024
)

type sessionID [sessionIDLen]byte

func (s sessionID) String() string { return fmt.Sprintf("%x", s[:]) }

func (s sessionID) isZero() bool {
	for _, b := range s {
		if b != 0 {
			return false
		}
	}
	return true
}

// frame is a decoded protocol frame. Only the fields relevant to typ are set.
type frame struct {
	typ     frameType
	id      sessionID // ATTACH, ATTACH_OK
	seq     uint64    // DATA, or the recv cursor on ATTACH / ATTACH_OK, or ACK
	payload []byte    // DATA, ERROR
}

// writeFrame encodes f to w and flushes. All multi-byte integers are
// big-endian. w must be a *bufio.Writer so each frame is flushed promptly.
func writeFrame(w *bufio.Writer, f frame) error {
	if err := w.WriteByte(byte(f.typ)); err != nil {
		return err
	}
	switch f.typ {
	case frameAttach, frameAttachOK:
		if _, err := w.Write(f.id[:]); err != nil {
			return err
		}
		if err := binary.Write(w, binary.BigEndian, f.seq); err != nil {
			return err
		}
	case frameData:
		if len(f.payload) > maxPayload {
			return fmt.Errorf("session: data frame too large: %d", len(f.payload))
		}
		if err := binary.Write(w, binary.BigEndian, f.seq); err != nil {
			return err
		}
		if err := binary.Write(w, binary.BigEndian, uint32(len(f.payload))); err != nil {
			return err
		}
		if _, err := w.Write(f.payload); err != nil {
			return err
		}
	case frameAck:
		if err := binary.Write(w, binary.BigEndian, f.seq); err != nil {
			return err
		}
	case framePing, framePong, frameClose:
		// type byte only
	case frameError:
		if err := binary.Write(w, binary.BigEndian, uint32(len(f.payload))); err != nil {
			return err
		}
		if _, err := w.Write(f.payload); err != nil {
			return err
		}
	default:
		return fmt.Errorf("session: unknown frame type %d", f.typ)
	}
	return w.Flush()
}

// readFrame decodes one frame from r.
func readFrame(r *bufio.Reader) (frame, error) {
	t, err := r.ReadByte()
	if err != nil {
		return frame{}, err
	}
	f := frame{typ: frameType(t)}
	switch f.typ {
	case frameAttach, frameAttachOK:
		if _, err := io.ReadFull(r, f.id[:]); err != nil {
			return frame{}, err
		}
		if err := binary.Read(r, binary.BigEndian, &f.seq); err != nil {
			return frame{}, err
		}
	case frameData:
		if err := binary.Read(r, binary.BigEndian, &f.seq); err != nil {
			return frame{}, err
		}
		var n uint32
		if err := binary.Read(r, binary.BigEndian, &n); err != nil {
			return frame{}, err
		}
		if n > maxPayload {
			return frame{}, fmt.Errorf("session: data frame too large: %d", n)
		}
		f.payload = make([]byte, n)
		if _, err := io.ReadFull(r, f.payload); err != nil {
			return frame{}, err
		}
	case frameAck:
		if err := binary.Read(r, binary.BigEndian, &f.seq); err != nil {
			return frame{}, err
		}
	case framePing, framePong, frameClose:
		// type byte only
	case frameError:
		var n uint32
		if err := binary.Read(r, binary.BigEndian, &n); err != nil {
			return frame{}, err
		}
		if n > maxPayload {
			return frame{}, fmt.Errorf("session: error frame too large: %d", n)
		}
		f.payload = make([]byte, n)
		if _, err := io.ReadFull(r, f.payload); err != nil {
			return frame{}, err
		}
	default:
		return frame{}, fmt.Errorf("session: unknown frame type %d", t)
	}
	return f, nil
}
