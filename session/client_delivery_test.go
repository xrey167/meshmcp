package session

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

type oneShotLocal struct{ *bytes.Reader }

func (oneShotLocal) Write(p []byte) (int, error) { return len(p), nil }
func (oneShotLocal) Close() error                { return nil }

// A finite send-only stream is successful only after the peer acknowledges
// every DATA frame. This protects Push, Drop, Cast, Screen, and Ring callers
// from presenting an optimistic success while the destination is unreachable.
func TestClientFiniteStreamFailsWhenDeliveryIsUnacknowledged(t *testing.T) {
	offline := errors.New("receiver offline")
	client := NewClient(func(context.Context) (net.Conn, error) {
		return nil, offline
	}, nil)
	client.drainWait = 40 * time.Millisecond

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	start := time.Now()
	err := client.Run(ctx, oneShotLocal{Reader: bytes.NewReader([]byte("ring\n"))})
	if !errors.Is(err, errDrainTimeout) {
		t.Fatalf("finite send error = %v, want %v", err, errDrainTimeout)
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("unacknowledged send ignored endpoint close during backoff: %v", elapsed)
	}
}

// A connection can be established but never complete the ATTACH handshake.
// The finite-send drain deadline must close that not-yet-bound connection too,
// rather than leave the caller waiting for the much longer idle deadline.
func TestClientFiniteStreamTimeoutInterruptsSilentHandshake(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	releasePeer := make(chan struct{})
	peerRead := make(chan error, 1)
	go func() {
		defer serverConn.Close()
		_, err := readFrame(bufio.NewReader(serverConn))
		peerRead <- err
		if err == nil {
			<-releasePeer
		}
	}()

	client := NewClient(func(context.Context) (net.Conn, error) {
		return clientConn, nil
	}, nil)
	client.drainWait = 40 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	runErr := make(chan error, 1)
	start := time.Now()
	go func() {
		runErr <- client.Run(ctx, oneShotLocal{Reader: bytes.NewReader([]byte("ring\n"))})
	}()

	select {
	case err := <-runErr:
		close(releasePeer)
		if !errors.Is(err, errDrainTimeout) {
			t.Fatalf("silent handshake error = %v, want %v", err, errDrainTimeout)
		}
		if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
			t.Fatalf("silent handshake outlived drain timeout: %v", elapsed)
		}
	case <-time.After(500 * time.Millisecond):
		cancel()
		close(releasePeer)
		t.Fatal("silent handshake did not stop at the finite-send drain timeout")
	}

	if err := <-peerRead; err != nil {
		t.Fatalf("silent peer could not read ATTACH: %v", err)
	}
}

var _ io.ReadWriteCloser = oneShotLocal{}
