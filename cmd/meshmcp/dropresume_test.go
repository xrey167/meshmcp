package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xrey167/meshmcp/session"
)

// deliverToBuffer simulates a receiver that confirms installation: payloads
// land in buf and delivery reports success.
func deliverToBuffer(buf *bytes.Buffer) func(func(io.Writer) error, int, int64) error {
	return func(writePayloads func(io.Writer) error, _ int, _ int64) error {
		return writePayloads(buf)
	}
}

// receiptedSend runs one receipted send of paths against a confirming
// receiver, returning the wire stream, the progress lines, and the sent count.
func receiptedSend(t *testing.T, paths []string, rec *receiptLog, resume bool) (*bytes.Buffer, []string, int) {
	t.Helper()
	entries, err := enumerateSendable(paths)
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	logf := func(format string, args ...any) { lines = append(lines, fmt.Sprintf(format, args...)) }
	var buf bytes.Buffer
	sent, err := runReceiptedSend(entries, rec, resume, logf, deliverToBuffer(&buf))
	if err != nil {
		t.Fatal(err)
	}
	return &buf, lines, sent
}

// recvNames parses a sender stream into dir and returns the received names.
func recvNames(t *testing.T, stream *bytes.Buffer, dir string) []string {
	t.Helper()
	var names []string
	err := recvFiles(stream, dirPlacer(dir), dropLimits{}, func(fi recvInfo) { names = append(names, fi.Name) })
	if err != nil {
		t.Fatal(err)
	}
	return names
}

func TestDropReceiptsAndResume(t *testing.T) {
	src := t.TempDir()
	for _, f := range []string{"a.txt", "b.txt", "c.txt"} {
		if err := os.WriteFile(filepath.Join(src, f), []byte("data-"+f), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	paths := []string{
		filepath.Join(src, "a.txt"),
		filepath.Join(src, "b.txt"),
		filepath.Join(src, "c.txt"),
	}
	receiptPath := filepath.Join(t.TempDir(), "drop.receipts")

	// First send: everything goes out, one receipt per file, progress [i/3].
	rec, err := openReceiptLog(receiptPath, "100.1.1.9:9200")
	if err != nil {
		t.Fatal(err)
	}
	stream, lines, sent := receiptedSend(t, paths, rec, false)
	rec.close()
	if sent != 3 {
		t.Fatalf("first send sent %d files", sent)
	}
	got := recvNames(t, stream, t.TempDir())
	if len(got) != 3 {
		t.Fatalf("first send delivered %v", got)
	}
	if len(lines) != 3 || !strings.Contains(lines[0], "[1/3]") || !strings.Contains(lines[2], "[3/3]") {
		t.Fatalf("progress lines: %v", lines)
	}
	data, err := os.ReadFile(receiptPath)
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(data), "\n"); n != 3 {
		t.Fatalf("receipt lines: %d (%s)", n, data)
	}

	// Resume against the same target: everything is receipted, nothing resent.
	rec, err = openReceiptLog(receiptPath, "100.1.1.9:9200")
	if err != nil {
		t.Fatal(err)
	}
	stream, lines, sent = receiptedSend(t, paths, rec, true)
	rec.close()
	if sent != 0 {
		t.Fatalf("resume resent %d files", sent)
	}
	if got := recvNames(t, stream, t.TempDir()); len(got) != 0 {
		t.Fatalf("resume resent %v", got)
	}
	if len(lines) != 3 || !strings.Contains(lines[0], "skipping") {
		t.Fatalf("skip lines: %v", lines)
	}

	// Change b.txt's content (same size): resume must resend exactly b.txt.
	if err := os.WriteFile(filepath.Join(src, "b.txt"), []byte("DATA-b.txt"), 0o644); err != nil {
		t.Fatal(err)
	}
	rec, err = openReceiptLog(receiptPath, "100.1.1.9:9200")
	if err != nil {
		t.Fatal(err)
	}
	stream, _, _ = receiptedSend(t, paths, rec, true)
	rec.close()
	if got := recvNames(t, stream, t.TempDir()); len(got) != 1 || got[0] != "b.txt" {
		t.Fatalf("changed-file resume resent %v, want [b.txt]", got)
	}

	// Receipts are target-scoped: a different target starts from zero.
	rec, err = openReceiptLog(receiptPath, "100.2.2.2:9200")
	if err != nil {
		t.Fatal(err)
	}
	stream, _, _ = receiptedSend(t, paths, rec, true)
	rec.close()
	if got := recvNames(t, stream, t.TempDir()); len(got) != 3 {
		t.Fatalf("other-target resume delivered %v, want all 3", got)
	}
}

// TestDropReceiptsRequireConfirmedDelivery is the S53 honesty guarantee: a
// delivery whose payloads were fully written out (flushed) but never
// receiver-confirmed — a crash with bytes parked in the session send buffer,
// a transport that dropped mid-reconnect, a rejecting receiver — must record
// NO receipts, so --resume re-sends everything.
func TestDropReceiptsRequireConfirmedDelivery(t *testing.T) {
	src := t.TempDir()
	path := filepath.Join(src, "a.txt")
	if err := os.WriteFile(path, []byte("payload"), 0o644); err != nil {
		t.Fatal(err)
	}
	receiptPath := filepath.Join(t.TempDir(), "drop.receipts")
	rec, err := openReceiptLog(receiptPath, "100.1.1.9:9200")
	if err != nil {
		t.Fatal(err)
	}
	entries, err := enumerateSendable([]string{path})
	if err != nil {
		t.Fatal(err)
	}
	boom := errors.New("delivery was never receiver-confirmed")
	_, err = runReceiptedSend(entries, rec, false, func(string, ...any) {},
		func(writePayloads func(io.Writer) error, _ int, _ int64) error {
			// The payload IS fully handed over and flushed — and yet the
			// receiver never confirms. Exactly the interrupted-transfer case.
			var sink bytes.Buffer
			if err := writePayloads(&sink); err != nil {
				return err
			}
			return boom
		})
	rec.close()
	if !errors.Is(err, boom) {
		t.Fatalf("unconfirmed delivery must surface the error, got %v", err)
	}
	if data, err := os.ReadFile(receiptPath); err != nil || len(data) != 0 {
		t.Fatalf("unconfirmed delivery must record no receipts, got %q (err=%v)", data, err)
	}

	// A --resume re-run therefore re-sends the file instead of skipping it.
	rec, err = openReceiptLog(receiptPath, "100.1.1.9:9200")
	if err != nil {
		t.Fatal(err)
	}
	stream, _, sent := receiptedSend(t, []string{path}, rec, true)
	rec.close()
	if sent != 1 {
		t.Fatalf("resume after unconfirmed delivery sent %d files, want 1", sent)
	}
	if got := recvNames(t, stream, t.TempDir()); len(got) != 1 || got[0] != "a.txt" {
		t.Fatalf("resume delivered %v, want [a.txt]", got)
	}
}

// TestDropReceiptsEndToEndReceiverOutcomes runs the real completion handshake
// over a session: a receiver that rejects installation (per-file limit) leaves
// no receipt even though the bytes reached its session endpoint; a confirming
// receiver installs the file and yields a receipt.
func TestDropReceiptsEndToEndReceiverOutcomes(t *testing.T) {
	src := t.TempDir()
	path := filepath.Join(src, "f.txt")
	if err := os.WriteFile(path, []byte("abc"), 0o644); err != nil {
		t.Fatal(err)
	}
	entries, err := enumerateSendable([]string{path})
	if err != nil {
		t.Fatal(err)
	}
	deliverVia := func(dial session.Dialer) func(func(io.Writer) error, int, int64) error {
		return func(writePayloads func(io.Writer) error, payloads int, totalBytes int64) error {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			return runDropWithCompletion(ctx, dial, writePayloads, payloads, totalBytes, nil)
		}
	}
	receiptPath := filepath.Join(t.TempDir(), "r.jsonl")

	// Rejecting receiver: transfer fails, no receipt.
	rejectDial := dropTestDialer(t, newDropFactory(dirPlacer(t.TempDir()), dropLimits{PerFile: 2}, nil))
	rec, err := openReceiptLog(receiptPath, "peer:9200")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runReceiptedSend(entries, rec, false, func(string, ...any) {}, deliverVia(rejectDial)); err == nil {
		t.Fatal("rejecting receiver must fail the delivery")
	}
	rec.close()
	if data, err := os.ReadFile(receiptPath); err != nil || len(data) != 0 {
		t.Fatalf("rejected delivery must record no receipts, got %q (err=%v)", data, err)
	}

	// Confirming receiver: file installed AND receipted.
	dst := t.TempDir()
	okDial := dropTestDialer(t, newDropFactory(dirPlacer(dst), dropLimits{}, nil))
	rec, err = openReceiptLog(receiptPath, "peer:9200")
	if err != nil {
		t.Fatal(err)
	}
	sent, err := runReceiptedSend(entries, rec, false, func(string, ...any) {}, deliverVia(okDial))
	rec.close()
	if err != nil || sent != 1 {
		t.Fatalf("confirmed delivery: sent=%d err=%v", sent, err)
	}
	if got, err := os.ReadFile(filepath.Join(dst, "f.txt")); err != nil || string(got) != "abc" {
		t.Fatalf("installed = %q, err=%v", got, err)
	}
	rec, err = openReceiptLog(receiptPath, "peer:9200")
	if err != nil {
		t.Fatal(err)
	}
	defer rec.close()
	if _, ok := rec.sentSHA("f.txt", 3); !ok {
		t.Fatal("confirmed delivery must be receipted")
	}
}

func TestCountSendableWalksDirs(t *testing.T) {
	src := t.TempDir()
	if err := os.MkdirAll(filepath.Join(src, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"x", filepath.Join("sub", "y"), filepath.Join("sub", "z")} {
		if err := os.WriteFile(filepath.Join(src, f), []byte("1"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	n, err := countSendable([]string{src})
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Fatalf("countSendable = %d, want 3", n)
	}
}
