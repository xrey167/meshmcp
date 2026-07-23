package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"time"
)

// Sender-side transfer receipts for `meshmcp drop` (S53).
//
// With --receipts <file>, the sender records one JSONL receipt per file — but
// only AFTER the receiver confirmed the whole transfer's installed totals via
// the drop completion handshake (runDropWithCompletion). A "flushed to the
// transport" receipt would lie: a flush only proves the bytes reached the
// session layer's send buffer, which survives disconnects precisely by holding
// unacknowledged data — a crash there would receipt a file the receiver never
// got, and --resume would then skip it forever. A receipt therefore means "the
// receiver confirmed installing a transfer that included exactly this file";
// the receiver's audit ledger remains the installed-side truth. An interrupted
// or rejected transfer records NO receipts, so --resume re-sends everything
// unconfirmed. With --resume, files whose (target, name, size, sha256) already
// appear in the receipt file are skipped; skipping re-hashes the local file,
// so a file whose content changed since the receipt is honestly re-sent.

// dropReceipt is one durable sender-side receipt line.
type dropReceipt struct {
	Target string `json:"target"`
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
	SentAt string `json:"sent_at"`
}

// receiptLog is an append-only JSONL receipt file scoped to one target.
type receiptLog struct {
	f      *os.File
	target string
	sent   map[string]string // name + "\x00" + size -> last receipted sha256
}

func receiptKey(name string, size int64) string {
	return fmt.Sprintf("%s\x00%d", name, size)
}

// openReceiptLog loads existing receipts for target (later lines win) and
// opens the file for appending. A missing file starts an empty log.
func openReceiptLog(path, target string) (*receiptLog, error) {
	l := &receiptLog{target: target, sent: map[string]string{}}
	if data, err := os.Open(path); err == nil {
		sc := bufio.NewScanner(data)
		sc.Buffer(make([]byte, 64*1024), 1<<20)
		for sc.Scan() {
			if len(sc.Bytes()) == 0 {
				continue
			}
			var r dropReceipt
			if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
				data.Close()
				return nil, fmt.Errorf("receipts %s: bad line: %w", path, err)
			}
			if r.Target == target {
				l.sent[receiptKey(r.Name, r.Size)] = r.SHA256
			}
		}
		if err := sc.Err(); err != nil {
			data.Close()
			return nil, fmt.Errorf("receipts %s: %w", path, err)
		}
		data.Close()
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("receipts %s: %w", path, err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("receipts %s: %w", path, err)
	}
	l.f = f
	return l, nil
}

func (l *receiptLog) close() {
	if l != nil && l.f != nil {
		_ = l.f.Close()
	}
}

// sentSHA returns the receipted hash for (name, size) against this target.
func (l *receiptLog) sentSHA(name string, size int64) (string, bool) {
	sha, ok := l.sent[receiptKey(name, size)]
	return sha, ok
}

// record appends one receipt and syncs it, so a receipt survives the process
// being killed right after the file went out.
func (l *receiptLog) record(name string, size int64, sha string) error {
	b, err := json.Marshal(dropReceipt{
		Target: l.target, Name: name, Size: size, SHA256: sha,
		SentAt: time.Now().UTC().Format(time.RFC3339),
	})
	if err != nil {
		return err
	}
	if _, err := l.f.Write(append(b, '\n')); err != nil {
		return fmt.Errorf("append receipt: %w", err)
	}
	if err := l.f.Sync(); err != nil {
		return fmt.Errorf("sync receipts: %w", err)
	}
	l.sent[receiptKey(name, size)] = sha
	return nil
}

// fileSHA256 hashes a local file (used to verify a resume skip candidate).
func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// sendEntry is one regular file scheduled for a send: its local path, wire
// name, and the FileInfo captured at enumeration (the header/size source).
type sendEntry struct {
	path string
	name string
	fi   os.FileInfo
}

// enumerateSendable lists the regular files sendFiles would stream, in the
// same order and under the same wire names (mirrors sendFiles/sendDir).
func enumerateSendable(paths []string) ([]sendEntry, error) {
	var entries []sendEntry
	for _, p := range paths {
		p = filepath.Clean(p)
		fi, err := os.Stat(p)
		if err != nil {
			return nil, fmt.Errorf("stat %s: %w", p, err)
		}
		if !fi.IsDir() {
			entries = append(entries, sendEntry{path: p, name: filepath.Base(p), fi: fi})
			continue
		}
		root := filepath.Dir(p)
		err = filepath.WalkDir(p, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !d.Type().IsRegular() {
				return nil
			}
			rel, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			info, err := d.Info()
			if err != nil {
				return err
			}
			entries = append(entries, sendEntry{path: path, name: filepath.ToSlash(rel), fi: info})
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return entries, nil
}

// countSendable counts the regular files a send of paths will stream, so
// progress can say [i/n].
func countSendable(paths []string) (int, error) {
	entries, err := enumerateSendable(paths)
	if err != nil {
		return 0, err
	}
	return len(entries), nil
}

// progressHooks logs one [i/n] line per sent file (plain, receipt-less drops).
// logf defaults to log.Printf.
func progressHooks(total int, logf func(string, ...any)) sendHooks {
	if logf == nil {
		logf = log.Printf
	}
	done := 0
	return sendHooks{
		sent: func(name, _ string, fi os.FileInfo, _ string) error {
			done++
			logf("[%d/%d] sent %s (%d bytes)", done, total, name, fi.Size())
			return nil
		},
	}
}

// receiptedAlready reports whether e is covered by a prior receipt for this
// target AND its local content still hashes to the receipted sha — a changed
// file (even at the same size) is honestly re-sent.
func receiptedAlready(rec *receiptLog, e sendEntry) (bool, error) {
	want, ok := rec.sentSHA(e.name, e.fi.Size())
	if !ok {
		return false, nil
	}
	got, err := fileSHA256(e.path)
	if err != nil {
		return false, fmt.Errorf("resume: hash %s: %w", e.path, err)
	}
	return got == want, nil
}

// runReceiptedSend is the --receipts/--resume send path. It filters entries
// against the receipt log (when resume is set), streams the remainder through
// deliver, and records receipts ONLY after deliver returns nil. deliver must
// return nil only once the receiver confirmed installing exactly the given
// payload/byte totals (see runDropWithCompletion) — a receipt written on
// anything weaker (a flush, a transport ack) could cover a file the receiver
// never installed, which --resume would then skip forever. Returns how many
// files were sent (0 = everything was already receipted; deliver not called).
func runReceiptedSend(
	entries []sendEntry,
	rec *receiptLog,
	resume bool,
	logf func(string, ...any),
	deliver func(writePayloads func(io.Writer) error, payloads int, totalBytes int64) error,
) (int, error) {
	if logf == nil {
		logf = log.Printf
	}
	total := len(entries)
	done := 0
	var toSend []sendEntry
	var sendBytes int64
	for _, e := range entries {
		if resume {
			skip, err := receiptedAlready(rec, e)
			if err != nil {
				return 0, err
			}
			if skip {
				done++
				logf("[%d/%d] %s — already sent, skipping (--resume)", done, total, e.name)
				continue
			}
		}
		toSend = append(toSend, e)
		sendBytes += e.fi.Size()
	}
	if len(toSend) == 0 {
		return 0, nil
	}

	var pending []dropReceipt
	writePayloads := func(w io.Writer) error {
		bw := bufio.NewWriter(w)
		for _, e := range toSend {
			sum, err := sendOneFile(bw, e.path, e.name, e.fi)
			if err != nil {
				return err
			}
			if err := bw.Flush(); err != nil {
				return err
			}
			done++
			logf("[%d/%d] sent %s (%d bytes)", done, total, e.name, e.fi.Size())
			pending = append(pending, dropReceipt{Name: e.name, Size: e.fi.Size(), SHA256: sum})
		}
		return nil
	}
	if err := deliver(writePayloads, len(toSend), sendBytes); err != nil {
		return 0, err
	}
	// The receiver confirmed the exact totals: the receipts are now true.
	for _, r := range pending {
		if err := rec.record(r.Name, r.Size, r.SHA256); err != nil {
			return len(toSend), err
		}
	}
	return len(toSend), nil
}
