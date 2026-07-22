package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xrey167/meshmcp/policy"
	"github.com/xrey167/meshmcp/session"
)

// syncBuffer is a goroutine-safe io.Writer for capturing the audit stream that
// a background receiver writes while the test reads it.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

func (s *syncBuffer) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Len()
}

// writeTemp creates a file with the given bytes under dir and returns its path.
func writeTemp(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatalf("write %s: %v", p, err)
	}
	return p
}

func sha(data []byte) string {
	s := sha256.Sum256(data)
	return hex.EncodeToString(s[:])
}

// TestDropRoundTrip streams several files (including binary) through the wire
// protocol and verifies content, hashes, and the per-file callback.
func TestDropRoundTrip(t *testing.T) {
	src := t.TempDir()
	dst := t.TempDir()

	files := map[string][]byte{
		"hello.txt":  []byte("hello mesh"),
		"binary.dat": {0x00, 0x01, 0x02, 0xff, 0xfe, 0x10, 0x00},
		"empty":      {},
	}
	var paths []string
	for name, data := range files {
		paths = append(paths, writeTemp(t, src, name, data))
	}

	pr, pw := io.Pipe()
	go func() { pw.CloseWithError(sendFiles(pw, paths)) }()

	got := map[string]recvInfo{}
	if err := recvFiles(pr, dirPlacer(dst), dropLimits{}, func(fi recvInfo) { got[fi.Name] = fi }); err != nil {
		t.Fatalf("recvFiles: %v", err)
	}

	if len(got) != len(files) {
		t.Fatalf("received %d files, want %d", len(got), len(files))
	}
	for name, data := range files {
		fi, ok := got[name]
		if !ok {
			t.Fatalf("missing received file %q", name)
		}
		if fi.SHA256 != sha(data) {
			t.Errorf("%q: reported hash %s, want %s", name, fi.SHA256, sha(data))
		}
		onDisk, err := os.ReadFile(filepath.Join(dst, name))
		if err != nil {
			t.Fatalf("read received %q: %v", name, err)
		}
		if !bytes.Equal(onDisk, data) {
			t.Errorf("%q: content mismatch", name)
		}
	}
}

// TestDropDirectory streams a directory tree and verifies the structure is
// reproduced on the receiver with relative paths preserved.
func TestDropDirectory(t *testing.T) {
	src := t.TempDir()
	dst := t.TempDir()

	// Build a small tree: photos/a.txt, photos/sub/b.txt, plus a top-level file.
	tree := map[string][]byte{
		"photos/a.txt":     []byte("alpha"),
		"photos/sub/b.txt": []byte("bravo"),
		"photos/c.bin":     {0x00, 0xff, 0x01},
	}
	for rel, data := range tree {
		full := filepath.Join(src, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	pr, pw := io.Pipe()
	go func() { pw.CloseWithError(sendFiles(pw, []string{filepath.Join(src, "photos")})) }()

	got := map[string]recvInfo{}
	if err := recvFiles(pr, dirPlacer(dst), dropLimits{}, func(fi recvInfo) { got[fi.Name] = fi }); err != nil {
		t.Fatalf("recvFiles: %v", err)
	}
	if len(got) != len(tree) {
		t.Fatalf("received %d files, want %d: %v", len(got), len(tree), got)
	}
	for rel, data := range tree {
		if fi, ok := got[rel]; !ok || fi.SHA256 != sha(data) {
			t.Fatalf("file %q: ok=%v info=%+v", rel, ok, fi)
		}
		onDisk, err := os.ReadFile(filepath.Join(dst, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatalf("read received %q: %v", rel, err)
		}
		if !bytes.Equal(onDisk, data) {
			t.Errorf("%q: content mismatch", rel)
		}
	}
}

// TestPushPayload verifies a stdin-style payload (sendData) is received and
// verified like any drop — the universal-clipboard path.
func TestPushPayload(t *testing.T) {
	dst := t.TempDir()
	payload := []byte("meet at 15:00 — pushed from the clipboard")

	pr, pw := io.Pipe()
	go func() { pw.CloseWithError(sendData(pw, "clip.txt", payload)) }()

	var got recvInfo
	if err := recvFiles(pr, dirPlacer(dst), dropLimits{}, func(fi recvInfo) { got = fi }); err != nil {
		t.Fatalf("recvFiles: %v", err)
	}
	if got.SHA256 != sha(payload) {
		t.Errorf("hash mismatch: %s vs %s", got.SHA256, sha(payload))
	}
	onDisk, _ := os.ReadFile(filepath.Join(dst, "clip.txt"))
	if !bytes.Equal(onDisk, payload) {
		t.Errorf("pushed payload not received intact")
	}
}

// TestDropRejectsPathTraversal ensures a malicious file name cannot escape the
// destination directory.
func TestDropRejectsPathTraversal(t *testing.T) {
	dir := t.TempDir()
	for _, bad := range []string{"../escape", "../../etc/passwd", "/abs/path", "a/../../b"} {
		if _, err := sanitizeDest(dir, bad); err == nil {
			t.Errorf("sanitizeDest(%q) allowed an escape", bad)
		}
	}
	// A nested but contained path is allowed.
	if _, err := sanitizeDest(dir, "sub/dir/file.txt"); err != nil {
		t.Errorf("sanitizeDest rejected a contained path: %v", err)
	}
}

// TestDropDetectsCorruption verifies a content/hash mismatch is caught and the
// file is not installed.
func TestDropDetectsCorruption(t *testing.T) {
	dst := t.TempDir()
	// Hand-craft a stream whose trailer hash does not match the content.
	var buf bytes.Buffer
	buf.WriteString(`{"name":"x","size":3,"mode":420}` + "\n")
	buf.WriteString("abc")
	buf.WriteString(`{"sha256":"deadbeef"}` + "\n")

	err := recvFiles(&buf, dirPlacer(dst), dropLimits{}, nil)
	if err == nil || !strings.Contains(err.Error(), "hash mismatch") {
		t.Fatalf("expected hash mismatch error, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(dst, "x")); !os.IsNotExist(err) {
		t.Errorf("corrupt file should not have been installed")
	}
}

// TestDropEnforcesMaxBytes verifies the per-file cap is honored.
func TestDropEnforcesMaxBytes(t *testing.T) {
	src, dst := t.TempDir(), t.TempDir()
	p := writeTemp(t, src, "big.dat", bytes.Repeat([]byte{7}, 4096))
	pr, pw := io.Pipe()
	go func() { pw.CloseWithError(sendFiles(pw, []string{p})) }()
	if err := recvFiles(pr, dirPlacer(dst), dropLimits{PerFile: 1024}, nil); err == nil || !strings.Contains(err.Error(), "over the") {
		t.Fatalf("expected size-limit error, got %v", err)
	}
}

// TestDropBoundsFramingLine ensures an oversized header line (a sender that
// never sends a newline) is rejected instead of buffered unboundedly.
func TestDropBoundsFramingLine(t *testing.T) {
	dst := t.TempDir()
	var buf bytes.Buffer
	buf.Write(bytes.Repeat([]byte("A"), maxDropFrameLine+16)) // no newline: an unbounded "header"
	err := recvFiles(&buf, dirPlacer(dst), dropLimits{}, nil)
	if err == nil || !strings.Contains(err.Error(), "framing line exceeds") {
		t.Fatalf("expected framing-line bound error, got %v", err)
	}
}

// TestDropEnforcesFileCount ensures a transfer is refused once it exceeds the
// file-count cap.
func TestDropEnforcesFileCount(t *testing.T) {
	src, dst := t.TempDir(), t.TempDir()
	var paths []string
	for i := 0; i < 5; i++ {
		paths = append(paths, writeTemp(t, src, "f"+string(rune('a'+i))+".txt", []byte("x")))
	}
	pr, pw := io.Pipe()
	go func() { pw.CloseWithError(sendFiles(pw, paths)) }()
	err := recvFiles(pr, dirPlacer(dst), dropLimits{MaxFiles: 3}, nil)
	if err == nil || !strings.Contains(err.Error(), "file limit") {
		t.Fatalf("expected file-count limit error, got %v", err)
	}
}

// TestDropOverSession exercises the full flagship path: a drop delivered over
// the resumable session layer on a loopback listener, through the real
// dropSink backend factory, with an audit record written per file.
func TestDropOverSession(t *testing.T) {
	src, dst := t.TempDir(), t.TempDir()
	payload := bytes.Repeat([]byte("mesh-airdrop-"), 500) // ~6.5 KiB, spans frames
	p := writeTemp(t, src, "report.bin", payload)

	auditBuf := &syncBuffer{}
	audit := policy.NewAuditLog(auditBuf, func() string { return "t" })

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	srv := session.NewServer(newDropFactory(dirPlacer(dst), dropLimits{}, audit), 2*time.Minute, nil)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go srv.Handle(conn, session.Meta{PeerFQDN: "sender.netbird.cloud", PeerKey: "PUBKEYabc", PeerAddr: "100.0.0.9:5"})
		}
	}()

	dial := func(ctx context.Context) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", ln.Addr().String())
	}
	pr, pw := io.Pipe()
	go func() { pw.CloseWithError(sendFiles(pw, []string{p})) }()

	sc := session.NewClient(dial, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := sc.Run(ctx, sendStream{r: pr}); err != nil {
		t.Fatalf("session run: %v", err)
	}

	// The receiver finalizes asynchronously; wait for the installed file. The
	// deadline is generous so the test never false-fails under a loaded -race
	// run (it normally completes in tens of milliseconds).
	dstFile := filepath.Join(dst, "report.bin")
	deadline := time.Now().Add(20 * time.Second)
	for {
		if b, err := os.ReadFile(dstFile); err == nil {
			if !bytes.Equal(b, payload) {
				t.Fatalf("received content mismatch (%d vs %d bytes)", len(b), len(payload))
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("file not received before deadline")
		}
		time.Sleep(20 * time.Millisecond)
	}

	// An audit record with the content hash must have been written.
	for time.Now().Before(deadline) && auditBuf.Len() == 0 {
		time.Sleep(20 * time.Millisecond)
	}
	if !strings.Contains(auditBuf.String(), sha(payload)) {
		t.Fatalf("audit log missing content hash %s; got: %s", sha(payload), auditBuf.String())
	}
	if !strings.Contains(auditBuf.String(), `"method":"drop/recv"`) {
		t.Errorf("audit record missing drop/recv method: %s", auditBuf.String())
	}
}
