package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/xrey167/meshmcp/session"
)

const (
	dropCompletionSchemaV1   = "meshmcp.drop-completion/v1"
	dropCompletionInstalled  = "installed"
	dropCompletionRejected   = "rejected"
	maxDropCompletionBytes   = 4 << 10
	dropCompletionTimeout    = 2 * time.Minute
	initialDropAttachTimeout = 20 * time.Second
	maxDropAttemptDuration   = 15 * time.Minute
)

// dropCompletion is the receiver's application-level proof that the framed
// payloads were parsed, hash-checked, and installed. It deliberately carries
// counts only: receiver filesystem paths and raw errors never cross the wire.
type dropCompletion struct {
	Schema            string `json:"schema"`
	Status            string `json:"status"`
	Nonce             string `json:"nonce,omitempty"`
	InstalledPayloads int    `json:"installed_payloads"`
	InstalledBytes    int64  `json:"installed_bytes"`
}

// dropCompletionSink is the receiver half of the completion handshake. Once
// parsing finishes it publishes exactly one result line, then keeps Read and
// Write alive until the peer consumes that line and closes the session. This
// prevents the generic session pumps from racing the result with a graceful
// transport CLOSE.
type dropCompletionSink struct {
	pw           *io.PipeWriter
	done         chan struct{}
	closed       chan struct{}
	closeOnce    sync.Once
	err          error
	result       []byte
	resultOffset int
}

func newDropCompletionSink(pw *io.PipeWriter) *dropCompletionSink {
	return &dropCompletionSink{pw: pw, done: make(chan struct{}), closed: make(chan struct{})}
}

func (d *dropCompletionSink) Write(p []byte) (int, error) {
	select {
	case <-d.done:
		return len(p), nil
	default:
	}
	n, err := d.pw.Write(p)
	if err != nil {
		select {
		case <-d.done:
			return len(p), nil
		default:
		}
	}
	return n, err
}

func (d *dropCompletionSink) Read(p []byte) (int, error) {
	<-d.done
	if len(p) == 0 {
		return 0, nil
	}
	if d.resultOffset < len(d.result) {
		n := copy(p, d.result[d.resultOffset:])
		d.resultOffset += n
		return n, nil
	}
	<-d.closed
	return 0, io.EOF
}

func (d *dropCompletionSink) Close() error {
	d.closeOnce.Do(func() {
		close(d.closed)
		_ = d.pw.Close()
	})
	<-d.done
	return d.err
}

func (d *dropCompletionSink) finish(err error, nonce string, installedPayloads int, installedBytes int64) {
	d.err = err
	status := dropCompletionInstalled
	if err != nil {
		status = dropCompletionRejected
	}
	result, marshalErr := json.Marshal(dropCompletion{
		Schema: dropCompletionSchemaV1, Status: status, Nonce: nonce,
		InstalledPayloads: installedPayloads, InstalledBytes: installedBytes,
	})
	if marshalErr != nil {
		result = []byte(`{"schema":"meshmcp.drop-completion/v1","status":"rejected","installed_payloads":0,"installed_bytes":0}`)
	}
	d.result = append(result, '\n')
	close(d.done)
}

func (c dropCompletion) validate() error {
	if c.Schema != dropCompletionSchemaV1 {
		return fmt.Errorf("drop completion schema must be %q", dropCompletionSchemaV1)
	}
	if c.Status != dropCompletionInstalled && c.Status != dropCompletionRejected {
		return errors.New("drop completion has an unknown status")
	}
	if c.Nonce != "" && !validDropCompletionNonce(c.Nonce) {
		return errors.New("drop completion has an invalid nonce")
	}
	if c.InstalledPayloads < 0 || c.InstalledBytes < 0 {
		return errors.New("drop completion has invalid installed totals")
	}
	return nil
}

func newDropCompletionNonce() (string, error) {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", fmt.Errorf("create drop completion nonce: %w", err)
	}
	return hex.EncodeToString(nonce[:]), nil
}

func validDropCompletionNonce(nonce string) bool {
	if len(nonce) != 32 {
		return false
	}
	decoded, err := hex.DecodeString(nonce)
	return err == nil && len(decoded) == 16
}

// writeDropCompletionEnd terminates a receiver-confirmed transfer. Size is
// intentionally negative: a receiver that predates this protocol rejects the
// marker before treating it as a file, while a current receiver recognizes End
// before applying ordinary file-size validation.
func writeDropCompletionEnd(w io.Writer, nonce string) error {
	if !validDropCompletionNonce(nonce) {
		return errors.New("invalid drop completion nonce")
	}
	b, err := json.Marshal(dropHeader{Size: -1, End: true, Nonce: nonce})
	if err != nil {
		return err
	}
	_, err = w.Write(append(b, '\n'))
	return err
}

func normalizedDropWireName(name string) string {
	return strings.ToLower(path.Clean(strings.ReplaceAll(name, "\\", "/")))
}

func validDropWireNameEncoding(name string) bool { return utf8.ValidString(name) }

func dropWireNamesConflict(a, b string) bool {
	return a == b || strings.HasPrefix(a, b+"/") || strings.HasPrefix(b, a+"/")
}

// dropNameTrie rejects duplicate and file/directory-prefix collisions in time
// proportional to the total path length, even for the legacy receiver's large
// file-count allowance.
type dropNameTrie struct {
	terminal bool
	children map[string]*dropNameTrie
}

type dropNameBudget struct {
	total int64
}

func (b *dropNameBudget) add(name string) error {
	if len(name) > maxDropNameBytes {
		return fmt.Errorf("drop file name exceeds %d bytes", maxDropNameBytes)
	}
	b.total += int64(len(name))
	if b.total > maxDropNamesBytes {
		return fmt.Errorf("transfer file names exceed the %d-byte aggregate limit", maxDropNamesBytes)
	}
	return nil
}

func (t *dropNameTrie) reserve(normalizedName string) bool {
	node := t
	for _, segment := range strings.Split(normalizedName, "/") {
		if node.terminal {
			return false
		}
		if node.children == nil {
			node.children = map[string]*dropNameTrie{}
		}
		next := node.children[segment]
		if next == nil {
			next = &dropNameTrie{}
			node.children[segment] = next
		}
		node = next
	}
	if node.terminal || len(node.children) != 0 {
		return false
	}
	node.terminal = true
	return true
}

// dropCompletionStream bridges the resumable session while holding local EOF
// until the receiver's application response arrives. That distinction is what
// turns a transport ACK into an honest installation acknowledgement.
type dropCompletionStream struct {
	reader        *io.PipeReader
	input         *io.PipeWriter
	expectedNonce string

	mu         sync.Mutex
	buffer     []byte
	completion dropCompletion
	have       bool
	err        error

	responseDone chan struct{}
	responseOnce sync.Once
	inputOnce    sync.Once
	markerQueued chan struct{}
	markerOnce   sync.Once
	producerDone bool
	readWaiting  bool
	readBytes    int64
	writtenBytes int64
}

func newDropCompletionStream(reader *io.PipeReader, input *io.PipeWriter, nonce string) *dropCompletionStream {
	return &dropCompletionStream{
		reader: reader, input: input, expectedNonce: nonce,
		responseDone: make(chan struct{}), markerQueued: make(chan struct{}),
	}
}

func (s *dropCompletionStream) Read(p []byte) (int, error) {
	s.mu.Lock()
	s.readWaiting = true
	queued := s.producerDone && s.readBytes >= s.writtenBytes
	s.mu.Unlock()
	if queued {
		s.markerOnce.Do(func() { close(s.markerQueued) })
	}
	n, err := s.reader.Read(p)
	s.mu.Lock()
	s.readWaiting = false
	s.readBytes += int64(n)
	s.mu.Unlock()
	return n, err
}

func (s *dropCompletionStream) markProducerDone(written int64) {
	s.mu.Lock()
	s.producerDone = true
	s.writtenBytes = written
	queued := s.readWaiting && s.readBytes >= s.writtenBytes
	s.mu.Unlock()
	if queued {
		s.markerOnce.Do(func() { close(s.markerQueued) })
	}
}

func (s *dropCompletionStream) Write(p []byte) (int, error) {
	closeInput := false
	s.mu.Lock()
	if s.have || s.err != nil {
		if len(bytes.TrimSpace(p)) > 0 && s.err == nil {
			s.err = errors.New("receiver sent data after its drop completion")
		}
		s.mu.Unlock()
		return len(p), nil
	}
	if len(p) > maxDropCompletionBytes-len(s.buffer) {
		s.err = fmt.Errorf("receiver drop completion exceeds %d bytes", maxDropCompletionBytes)
		closeInput = true
	} else {
		s.buffer = append(s.buffer, p...)
		if newline := bytes.IndexByte(s.buffer, '\n'); newline >= 0 {
			line := append([]byte(nil), s.buffer[:newline]...)
			trailing := bytes.TrimSpace(s.buffer[newline+1:])
			if len(trailing) != 0 {
				s.err = errors.New("receiver sent extra data with its drop completion")
			} else {
				var completion dropCompletion
				decoder := json.NewDecoder(bytes.NewReader(line))
				decoder.DisallowUnknownFields()
				if err := decoder.Decode(&completion); err != nil {
					s.err = errors.New("receiver sent an invalid drop completion")
				} else {
					var extra json.RawMessage
					if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
						s.err = errors.New("receiver sent an invalid drop completion")
					} else if err := completion.validate(); err != nil {
						s.err = err
					} else if completion.Nonce != "" && completion.Nonce != s.expectedNonce {
						s.err = errors.New("receiver drop completion nonce does not match this delivery")
					} else if completion.Status == dropCompletionInstalled && completion.Nonce != s.expectedNonce {
						s.err = errors.New("receiver did not bind its drop completion to this delivery")
					} else {
						s.completion = completion
						s.have = true
					}
				}
			}
			closeInput = true
		}
	}
	s.mu.Unlock()
	if closeInput {
		s.finishResponse()
	}
	return len(p), nil
}

func (s *dropCompletionStream) finishResponse() {
	s.responseOnce.Do(func() { close(s.responseDone) })
	s.inputOnce.Do(func() { _ = s.input.Close() })
}

func (s *dropCompletionStream) fail(err error) {
	s.mu.Lock()
	if !s.have && s.err == nil {
		s.err = err
	}
	s.mu.Unlock()
	s.finishResponse()
}

func (s *dropCompletionStream) outcome() (dropCompletion, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.completion, s.have, s.err
}

func (s *dropCompletionStream) Close() error {
	s.inputOnce.Do(func() { _ = s.input.Close() })
	_ = s.reader.Close()
	return nil
}

func evaluateDropCompletion(completion dropCompletion, expectedPayloads int, expectedBytes int64) error {
	if completion.Status == dropCompletionRejected {
		if completion.InstalledPayloads > 0 || completion.InstalledBytes > 0 {
			return fmt.Errorf(
				"receiver rejected delivery after installing %d of %d payloads (%d of %d bytes); do not retry blindly",
				completion.InstalledPayloads, expectedPayloads, completion.InstalledBytes, expectedBytes,
			)
		}
		return errors.New("receiver rejected delivery before installing any payload")
	}
	if completion.InstalledPayloads != expectedPayloads || completion.InstalledBytes != expectedBytes {
		return fmt.Errorf(
			"receiver completion totals do not match this delivery (payloads %d/%d, bytes %d/%d); installation may have occurred—do not retry blindly",
			completion.InstalledPayloads, expectedPayloads, completion.InstalledBytes, expectedBytes,
		)
	}
	return nil
}

type dropCountingWriter struct {
	w io.Writer
	n int64
}

func (w *dropCountingWriter) Write(p []byte) (int, error) {
	n, err := w.w.Write(p)
	w.n += int64(n)
	return n, err
}

// runDropWithCompletion sends one already-bounded payload stream and returns
// only after the receiver confirms exact installed totals. The completion timer
// starts after the producer has written the end marker, so slow/resumed payload
// transfer time is governed by ctx rather than a misleading short deadline.
func runDropWithCompletion(
	ctx context.Context,
	dial session.Dialer,
	writePayloads func(io.Writer) error,
	expectedPayloads int,
	expectedBytes int64,
	logf func(string, ...any),
) error {
	if expectedPayloads <= 0 || expectedBytes < 0 {
		return errors.New("invalid expected drop completion totals")
	}
	nonce, err := newDropCompletionNonce()
	if err != nil {
		return err
	}
	reader, input := io.Pipe()
	stream := newDropCompletionStream(reader, input, nonce)
	runCtx, cancel := context.WithTimeout(ctx, maxDropAttemptDuration)
	defer cancel()

	client := session.NewClient(dial, logf).WithInitialAttachTimeout(initialDropAttachTimeout)
	var writeErr error
	writeDone := make(chan struct{})
	go func() {
		writer := &dropCountingWriter{w: input}
		writeErr = writePayloads(writer)
		if writeErr == nil {
			writeErr = writeDropCompletionEnd(writer, nonce)
		}
		if writeErr == nil {
			stream.markProducerDone(writer.n)
		}
		if writeErr != nil {
			_ = input.CloseWithError(writeErr)
		}
		close(writeDone)
	}()

	go func() {
		select {
		case <-stream.markerQueued:
		case <-runCtx.Done():
			return
		}
		if err := client.WaitForDrain(runCtx); err != nil {
			stream.fail(fmt.Errorf("outbound delivery was not transport-confirmed; installation may have occurred—do not retry blindly: %w", err))
			cancel()
			return
		}
		timer := time.NewTimer(dropCompletionTimeout)
		defer timer.Stop()
		select {
		case <-stream.responseDone:
		case <-runCtx.Done():
		case <-timer.C:
			stream.fail(fmt.Errorf(
				"receiver completion timed out after %s; installation may have occurred—do not retry blindly",
				dropCompletionTimeout,
			))
			cancel()
		}
	}()

	runErr := client.Run(runCtx, stream)
	cancel()
	_ = stream.Close()
	<-writeDone

	completion, haveCompletion, completionErr := stream.outcome()
	if completionErr != nil {
		if strings.Contains(completionErr.Error(), "do not retry blindly") {
			return completionErr
		}
		return fmt.Errorf("receiver completion was not trustworthy; installation may have occurred—do not retry blindly: %w", completionErr)
	}
	if haveCompletion {
		return evaluateDropCompletion(completion, expectedPayloads, expectedBytes)
	}
	cause := ctx.Err()
	if cause == nil {
		cause = runErr
	}
	if cause == nil {
		cause = writeErr
	}
	if cause != nil {
		return fmt.Errorf("delivery completion was not confirmed; installation may have occurred—do not retry blindly: %w", cause)
	}
	return errors.New("receiver closed without confirming payload installation; installation may have occurred—do not retry blindly")
}
