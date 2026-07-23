package session

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"
)

func hostileErrorPayload() []byte {
	payload := []byte("denied\x1b[31m\n\xff")
	payload = append(payload, 0xc2, 0x85) // valid UTF-8 C1 control
	payload = append(payload, 0x7f)       // DEL
	payload = append(payload, bytes.Repeat([]byte("界"), 3000)...)
	return payload
}

func assertSafeErrorText(t *testing.T, text string, maxBytes int) {
	t.Helper()
	if len(text) > maxBytes {
		t.Fatalf("error text has %d bytes, want <= %d", len(text), maxBytes)
	}
	if !utf8.ValidString(text) {
		t.Fatalf("error text is not valid UTF-8: %q", text)
	}
	for _, r := range text {
		if r <= 0x1f || (r >= 0x7f && r <= 0x9f) {
			t.Fatalf("error text contains control U+%04X", r)
		}
	}
}

func TestSanitizeErrorText(t *testing.T) {
	got := sanitizeErrorText(hostileErrorPayload(), 64)
	assertSafeErrorText(t, got, 64)
	if !strings.Contains(got, "?") {
		t.Fatalf("sanitized text %q does not replace invalid UTF-8", got)
	}
	if !strings.HasSuffix(got, "...") {
		t.Fatalf("sanitized text %q does not show truncation", got)
	}
}

func TestAttachErrorIsSafeAndTerminal(t *testing.T) {
	payload := hostileErrorPayload()
	var dials int32
	serverErr := make(chan error, 1)
	dial := func(context.Context) (net.Conn, error) {
		atomic.AddInt32(&dials, 1)
		clientConn, serverConn := net.Pipe()
		go func() {
			defer serverConn.Close()
			if _, err := readFrame(bufio.NewReader(serverConn)); err != nil {
				serverErr <- err
				return
			}
			serverErr <- writeFrame(bufio.NewWriter(serverConn), frame{
				typ: frameError, payload: payload,
			})
		}()
		return clientConn, nil
	}

	client := NewClient(dial, nil).WithInitialAttachTimeout(time.Second)
	err := client.reconnectLoop(context.Background())
	if !errors.Is(err, errAttachRejected) {
		t.Fatalf("reconnectLoop error = %v, want attach rejection", err)
	}
	if got := atomic.LoadInt32(&dials); got != 1 {
		t.Fatalf("attach rejection caused %d dials, want exactly 1", got)
	}
	assertSafeErrorText(t, err.Error(), maxPeerErrorBytes)
	if !strings.Contains(err.Error(), "?") {
		t.Fatalf("attach error %q does not replace invalid UTF-8", err)
	}
	select {
	case err := <-serverErr:
		if err != nil {
			t.Fatalf("rejecting server: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("rejecting server did not finish")
	}
}

func TestChangedResumeSessionIDIsTerminal(t *testing.T) {
	var original sessionID
	original[0] = 1
	var replacement sessionID
	replacement[0] = 2
	var dials int32
	dial := func(context.Context) (net.Conn, error) {
		atomic.AddInt32(&dials, 1)
		clientConn, serverConn := net.Pipe()
		go func() {
			defer serverConn.Close()
			_, _ = readFrame(bufio.NewReader(serverConn))
			_ = writeFrame(bufio.NewWriter(serverConn), frame{typ: frameAttachOK, id: replacement})
		}()
		return clientConn, nil
	}
	client := NewClient(dial, nil)
	client.ep.id = original
	err := client.reconnectLoop(context.Background())
	if !errors.Is(err, errSessionChanged) {
		t.Fatalf("changed resume id = %v", err)
	}
	if got := atomic.LoadInt32(&dials); got != 1 {
		t.Fatalf("changed resume id caused %d dials, want 1", got)
	}
}

func TestZeroInitialSessionIDIsTerminal(t *testing.T) {
	var dials int32
	dial := func(context.Context) (net.Conn, error) {
		atomic.AddInt32(&dials, 1)
		clientConn, serverConn := net.Pipe()
		go func() {
			defer serverConn.Close()
			_, _ = readFrame(bufio.NewReader(serverConn))
			_ = writeFrame(bufio.NewWriter(serverConn), frame{typ: frameAttachOK})
		}()
		return clientConn, nil
	}
	err := NewClient(dial, nil).reconnectLoop(context.Background())
	if !errors.Is(err, errInvalidSessionID) {
		t.Fatalf("zero initial session id = %v", err)
	}
	if got := atomic.LoadInt32(&dials); got != 1 {
		t.Fatalf("zero session id caused %d dials, want 1", got)
	}
}

func TestLivePeerErrorIsSafe(t *testing.T) {
	clientConn, peerConn := net.Pipe()
	defer peerConn.Close()
	ep := newEndpoint(sessionID{})
	gen := ep.bind(clientConn, 0)
	pumpErr := make(chan error, 1)
	go func() {
		pumpErr <- ep.pumpReader(clientConn, bufio.NewReader(clientConn), gen)
	}()
	go func() {
		_ = writeFrame(bufio.NewWriter(peerConn), frame{
			typ: frameError, payload: hostileErrorPayload(),
		})
	}()

	select {
	case err := <-pumpErr:
		if err == nil {
			t.Fatal("pumpReader returned nil, want peer error")
		}
		assertSafeErrorText(t, err.Error(), maxPeerErrorBytes)
		if !strings.Contains(err.Error(), "?") {
			t.Fatalf("peer error %q does not replace invalid UTF-8", err)
		}
	case <-time.After(time.Second):
		t.Fatal("pumpReader did not return peer error")
	}
}

func TestWriteErrSanitizesAndBoundsPayload(t *testing.T) {
	writer, reader := net.Pipe()
	defer reader.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer writer.Close()
		writeErr(writer, string(hostileErrorPayload()))
	}()

	f, err := readFrame(bufio.NewReader(reader))
	if err != nil {
		t.Fatalf("read outbound error frame: %v", err)
	}
	if f.typ != frameError {
		t.Fatalf("frame type = %d, want frameError", f.typ)
	}
	text := string(f.payload)
	assertSafeErrorText(t, text, maxPeerErrorBytes)
	if !strings.Contains(text, "?") {
		t.Fatalf("outbound error %q does not replace invalid UTF-8", text)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("writeErr did not finish")
	}
}

func TestInitialAttachTimeoutCoversRetries(t *testing.T) {
	var dials int32
	dial := func(context.Context) (net.Conn, error) {
		atomic.AddInt32(&dials, 1)
		return nil, errors.New("offline")
	}
	client := NewClient(dial, nil).WithInitialAttachTimeout(400 * time.Millisecond)
	started := time.Now()
	err := client.reconnectLoop(context.Background())
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("reconnectLoop error = %v, want deadline exceeded", err)
	}
	if !strings.Contains(err.Error(), "initial attach timed out") {
		t.Fatalf("reconnectLoop error = %q, want initial timeout context", err)
	}
	if got := atomic.LoadInt32(&dials); got < 2 {
		t.Fatalf("initial timeout covered only %d dial, want repeated attempts", got)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("initial attach timeout returned after %s", elapsed)
	}
}

func TestInitialAttachTimeoutCoversHandshake(t *testing.T) {
	dial := func(ctx context.Context) (net.Conn, error) {
		clientConn, serverConn := net.Pipe()
		go func() {
			defer serverConn.Close()
			_, _ = readFrame(bufio.NewReader(serverConn))
			<-ctx.Done()
		}()
		return clientConn, nil
	}
	client := NewClient(dial, nil).WithInitialAttachTimeout(50 * time.Millisecond)
	err := client.reconnectLoop(context.Background())
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("reconnectLoop error = %v, want deadline exceeded", err)
	}
	if !strings.Contains(err.Error(), "initial attach timed out") {
		t.Fatalf("reconnectLoop error = %q, want initial timeout context", err)
	}
}

func TestInitialAttachTimeoutDefaultsToCallerContext(t *testing.T) {
	var dials int32
	dial := func(context.Context) (net.Conn, error) {
		atomic.AddInt32(&dials, 1)
		return nil, errors.New("offline")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	err := NewClient(dial, nil).reconnectLoop(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("reconnectLoop error = %v, want caller deadline", err)
	}
	if strings.Contains(err.Error(), "initial attach timed out") {
		t.Fatalf("default client unexpectedly used an initial timeout: %v", err)
	}
	if got := atomic.LoadInt32(&dials); got == 0 {
		t.Fatal("default client did not attempt a dial")
	}
}
