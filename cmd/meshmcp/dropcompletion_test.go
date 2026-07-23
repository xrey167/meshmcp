package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xrey167/meshmcp/session"
)

func dropTestDialer(t *testing.T, factory session.BackendFactory) session.Dialer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	srv := session.NewServer(factory, time.Minute, nil)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go srv.Handle(conn, session.Meta{PeerFQDN: "sender.mesh", PeerKey: "sender-key"})
		}
	}()
	return func(ctx context.Context) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", ln.Addr().String())
	}
}

type noCompletionBackend struct {
	reader *io.PipeReader
	writer *io.PipeWriter
	mu     sync.Mutex
	wire   []byte
	once   sync.Once
}

func newNoCompletionBackend() *noCompletionBackend {
	reader, writer := io.Pipe()
	return &noCompletionBackend{reader: reader, writer: writer}
}

func (b *noCompletionBackend) Read(p []byte) (int, error) { return b.reader.Read(p) }

func (b *noCompletionBackend) Write(p []byte) (int, error) {
	b.mu.Lock()
	b.wire = append(b.wire, p...)
	ended := bytes.Contains(b.wire, []byte(`"end":true`))
	b.mu.Unlock()
	if ended {
		b.once.Do(func() { _ = b.writer.Close() })
	}
	return len(p), nil
}

func (b *noCompletionBackend) Close() error {
	b.once.Do(func() { _ = b.writer.Close() })
	_ = b.reader.Close()
	return nil
}

func TestRunDropWithCompletionWaitsForInstallation(t *testing.T) {
	dst := t.TempDir()
	placeStarted := make(chan struct{})
	releasePlace := make(chan struct{})
	var once sync.Once
	place := func(hdr dropHeader, _ string) (string, error) {
		once.Do(func() { close(placeStarted) })
		<-releasePlace
		return sanitizeDest(dst, hdr.Name)
	}
	dial := dropTestDialer(t, newDropFactory(place, dropLimits{}, nil))
	payload := []byte("receiver-confirmed")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- runDropWithCompletion(ctx, dial, func(w io.Writer) error {
			return sendData(w, "proof.txt", payload)
		}, 1, int64(len(payload)), nil)
	}()

	select {
	case <-placeStarted:
	case <-ctx.Done():
		t.Fatal("receiver never reached installation")
	}
	select {
	case err := <-done:
		t.Fatalf("delivery returned before installation completed: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(releasePlace)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("confirmed delivery: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("confirmed delivery did not finish")
	}
	got, err := os.ReadFile(filepath.Join(dst, "proof.txt"))
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("installed payload = %q, err=%v", got, err)
	}
}

func TestRunDropWithCompletionReportsRejectionBeforeInstall(t *testing.T) {
	dial := dropTestDialer(t, newDropFactory(dirPlacer(t.TempDir()), dropLimits{PerFile: 2}, nil))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := runDropWithCompletion(ctx, dial, func(w io.Writer) error {
		return sendData(w, "too-big.txt", []byte("abc"))
	}, 1, 3, nil)
	if err == nil || !strings.Contains(err.Error(), "before installing any payload") {
		t.Fatalf("rejection = %v", err)
	}
	if strings.Contains(err.Error(), "do not retry blindly") {
		t.Fatalf("zero-install rejection should be safely retryable: %v", err)
	}
}

func TestRunDropWithCompletionReportsPartialInstall(t *testing.T) {
	dial := dropTestDialer(t, newDropFactory(dirPlacer(t.TempDir()), dropLimits{PerFile: 2}, nil))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := runDropWithCompletion(ctx, dial, func(w io.Writer) error {
		if err := sendData(w, "first.txt", []byte("a")); err != nil {
			return err
		}
		return sendData(w, "second.txt", []byte("bbb"))
	}, 2, 4, nil)
	if err == nil || !strings.Contains(err.Error(), "after installing 1 of 2 payloads") || !strings.Contains(err.Error(), "do not retry blindly") {
		t.Fatalf("partial rejection = %v", err)
	}
}

func TestRunDropWithCompletionRefusesSilentReceiverClose(t *testing.T) {
	dial := dropTestDialer(t, func(session.Meta) (session.Backend, error) {
		return newNoCompletionBackend(), nil
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := runDropWithCompletion(ctx, dial, func(w io.Writer) error {
		return sendData(w, "unconfirmed.txt", []byte("x"))
	}, 1, 1, nil)
	if err == nil || !strings.Contains(err.Error(), "do not retry blindly") {
		t.Fatalf("silent receiver close = %v", err)
	}
}

func TestRunDropWithCompletionTreatsReceiverRestartAfterPartialInstallAsUncertain(t *testing.T) {
	dst := t.TempDir()
	firstServer := session.NewServer(newDropFactory(dirPlacer(dst), dropLimits{}, nil), 100*time.Millisecond, nil)
	restartedServer := session.NewServer(newDropFactory(dirPlacer(dst), dropLimits{}, nil), 100*time.Millisecond, nil)
	firstListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer firstListener.Close()
	restartedListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer restartedListener.Close()
	serve := func(ln net.Listener, server *session.Server) {
		go func() {
			for {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				go server.Handle(conn, session.Meta{PeerFQDN: "sender.mesh", PeerKey: "sender-key"})
			}
		}()
	}
	serve(firstListener, firstServer)
	serve(restartedListener, restartedServer)
	firstTransport := make(chan net.Conn, 1)
	var dialMu sync.Mutex
	dialCount := 0
	dial := func(ctx context.Context) (net.Conn, error) {
		dialMu.Lock()
		dialCount++
		attempt := dialCount
		dialMu.Unlock()
		addr := restartedListener.Addr().String()
		if attempt == 1 {
			addr = firstListener.Addr().String()
		}
		conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
		if err == nil && attempt == 1 {
			firstTransport <- conn
		}
		return conn, err
	}

	releaseSecond := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseSecond) }) }
	defer release()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- runDropWithCompletion(ctx, dial, func(w io.Writer) error {
			if err := sendData(w, "first.txt", []byte("one")); err != nil {
				return err
			}
			<-releaseSecond
			return sendData(w, "second.txt", []byte("two"))
		}, 2, 6, nil)
	}()

	conn := <-firstTransport
	firstPath := filepath.Join(dst, "first.txt")
	deadline := time.Now().Add(5 * time.Second)
	for {
		if got, err := os.ReadFile(firstPath); err == nil && string(got) == "one" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("first payload was not installed before simulated restart")
		}
		time.Sleep(10 * time.Millisecond)
	}
	_ = conn.Close()
	release()

	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "do not retry blindly") {
			t.Fatalf("restart after partial install = %v", err)
		}
	case <-ctx.Done():
		t.Fatal("delivery did not fail after receiver restart")
	}
	dialMu.Lock()
	attempts := dialCount
	dialMu.Unlock()
	if attempts < 2 {
		t.Fatalf("receiver restart test made %d dial, want a resume attempt", attempts)
	}
	if _, err := os.Stat(filepath.Join(dst, "second.txt")); !os.IsNotExist(err) {
		t.Fatalf("restarted receiver unexpectedly installed the suffix: %v", err)
	}
}

func TestDropCompletionStreamRejectsUntrustedResponses(t *testing.T) {
	nonce := strings.Repeat("a", 32)
	otherNonce := strings.Repeat("b", 32)
	tests := []struct {
		name string
		line []byte
	}{
		{"malformed JSON", []byte("not-json\n")},
		{"unknown field", []byte(fmt.Sprintf(`{"schema":%q,"status":"installed","nonce":%q,"installed_payloads":1,"installed_bytes":1,"extra":true}`+"\n", dropCompletionSchemaV1, nonce))},
		{"wrong nonce", []byte(fmt.Sprintf(`{"schema":%q,"status":"installed","nonce":%q,"installed_payloads":1,"installed_bytes":1}`+"\n", dropCompletionSchemaV1, otherNonce))},
		{"missing installed nonce", []byte(fmt.Sprintf(`{"schema":%q,"status":"installed","installed_payloads":1,"installed_bytes":1}`+"\n", dropCompletionSchemaV1))},
		{"extra response", []byte(fmt.Sprintf(`{"schema":%q,"status":"installed","nonce":%q,"installed_payloads":1,"installed_bytes":1}`+"\n{}\n", dropCompletionSchemaV1, nonce))},
		{"oversized", bytes.Repeat([]byte("x"), maxDropCompletionBytes+1)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader, input := io.Pipe()
			stream := newDropCompletionStream(reader, input, nonce)
			defer stream.Close()
			if _, err := stream.Write(tt.line); err != nil {
				t.Fatal(err)
			}
			_, _, err := stream.outcome()
			if err == nil {
				t.Fatal("untrusted completion was accepted")
			}
		})
	}
}

func TestDropCompletionStreamAcceptsFragmentedBoundResponse(t *testing.T) {
	nonce := strings.Repeat("a", 32)
	line := []byte(fmt.Sprintf(`{"schema":%q,"status":"installed","nonce":%q,"installed_payloads":2,"installed_bytes":9}`+"\n", dropCompletionSchemaV1, nonce))
	reader, input := io.Pipe()
	stream := newDropCompletionStream(reader, input, nonce)
	defer stream.Close()
	mid := len(line) / 2
	_, _ = stream.Write(line[:mid])
	select {
	case <-stream.responseDone:
		t.Fatal("partial response completed early")
	default:
	}
	_, _ = stream.Write(line[mid:])
	<-stream.responseDone
	completion, have, err := stream.outcome()
	if err != nil || !have || completion.InstalledPayloads != 2 || completion.InstalledBytes != 9 {
		t.Fatalf("completion = %+v, have=%v, err=%v", completion, have, err)
	}
}

func TestEvaluateDropCompletionMismatchWarnsAgainstRetry(t *testing.T) {
	err := evaluateDropCompletion(dropCompletion{
		Schema: dropCompletionSchemaV1, Status: dropCompletionInstalled,
		InstalledPayloads: 1, InstalledBytes: 7,
	}, 2, 8)
	if err == nil || !strings.Contains(err.Error(), "do not retry blindly") {
		t.Fatalf("mismatch = %v", err)
	}
}

func TestRecvFilesWithCompletionKeepsLegacyEOF(t *testing.T) {
	var wire bytes.Buffer
	if err := sendData(&wire, "legacy.txt", []byte("ok")); err != nil {
		t.Fatal(err)
	}
	nonce, err := recvFilesWithCompletion(&wire, dirPlacer(t.TempDir()), dropLimits{}, nil)
	if err != nil || nonce != "" {
		t.Fatalf("legacy receive nonce=%q err=%v", nonce, err)
	}
}

func TestDropNameTrieAndBudget(t *testing.T) {
	var trie dropNameTrie
	if !trie.reserve("a/b") || trie.reserve("a") || trie.reserve("a/b") || trie.reserve("a/b/c") {
		t.Fatal("trie did not reject duplicate and ancestor conflicts")
	}
	var reverse dropNameTrie
	if !reverse.reserve("a") || reverse.reserve("a/b") {
		t.Fatal("trie did not reject descendant under an installed file")
	}
	var budget dropNameBudget
	if err := budget.add(strings.Repeat("x", maxDropNameBytes+1)); err == nil {
		t.Fatal("overlong name accepted")
	}
	budget = dropNameBudget{total: maxDropNamesBytes - 1}
	if err := budget.add("xy"); err == nil || !strings.Contains(err.Error(), "aggregate") {
		t.Fatalf("aggregate budget error = %v", err)
	}
}

func TestCASDropAllowsDuplicateWireNames(t *testing.T) {
	dst := t.TempDir()
	var wire bytes.Buffer
	if err := sendData(&wire, "same.txt", []byte("one")); err != nil {
		t.Fatal(err)
	}
	if err := sendData(&wire, "same.txt", []byte("two")); err != nil {
		t.Fatal(err)
	}
	if err := recvFiles(&wire, casPlacer(dst), dropLimits{NameIndependent: true}, nil); err != nil {
		t.Fatalf("CAS duplicate names: %v", err)
	}
	for _, data := range [][]byte{[]byte("one"), []byte("two")} {
		p, err := (casStore{dir: dst}).blobPath(sha(data))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("missing CAS blob %s: %v", p, err)
		}
	}
}
