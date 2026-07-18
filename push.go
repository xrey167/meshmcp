package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"time"

	"meshmcp/session"
)

// meshmcp push — the universal clipboard / push-to-agent primitive (F10).
//
// It streams a small payload from stdin to a peer's drop inbox over the same
// resumable, audited channel as `drop`, so anything on one device's clipboard
// (or a task pushed to an agent) lands on another by identity:
//
//	echo "meet at 15:00" | meshmcp push 100.x.y.z:9110
//	pbpaste | meshmcp push --name clip.txt 100.x.y.z:9110
//
// The receiver is an ordinary `meshmcp drop --config` daemon.

// sendData writes one drop record (header + content + trailer) for in-memory
// bytes — the building block for pushing a clipboard/stdin payload.
func sendData(w io.Writer, name string, data []byte) error {
	hdr := dropHeader{Name: name, Size: int64(len(data)), Mode: 0o644}
	hb, _ := json.Marshal(hdr)
	if _, err := w.Write(append(hb, '\n')); err != nil {
		return err
	}
	if _, err := w.Write(data); err != nil {
		return err
	}
	sum := sha256.Sum256(data)
	tb, _ := json.Marshal(dropTrailer{SHA256: hex.EncodeToString(sum[:])})
	_, err := w.Write(append(tb, '\n'))
	return err
}

// cmdPush reads a payload from stdin and pushes it to a peer's drop inbox.
func cmdPush(args []string) error {
	fs := flag.NewFlagSet("push", flag.ExitOnError)
	o := meshFlags(fs)
	name := fs.String("name", "", "name for the pushed payload (default: clip-<unix>.txt)")
	maxBytes := fs.Int64("max-bytes", 16<<20, "reject a stdin payload larger than this")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: <stdin> | meshmcp push [flags] <peer-ip:port>")
	}
	target := fs.Arg(0)

	data, err := io.ReadAll(io.LimitReader(os.Stdin, *maxBytes+1))
	if err != nil {
		return fmt.Errorf("read stdin: %w", err)
	}
	if int64(len(data)) > *maxBytes {
		return fmt.Errorf("payload exceeds %d bytes (use drop for large files)", *maxBytes)
	}
	if len(data) == 0 {
		return errors.New("nothing on stdin to push")
	}
	payloadName := *name
	if payloadName == "" {
		payloadName = fmt.Sprintf("clip-%d.txt", time.Now().Unix())
	}

	o.BlockInbound = true
	client, err := startMesh(o, os.Stderr)
	if err != nil {
		return err
	}
	defer stopMesh(client)

	pr, pw := io.Pipe()
	go func() { pw.CloseWithError(sendData(pw, payloadName, data)) }()

	dial := func(ctx context.Context) (net.Conn, error) { return client.Dial(ctx, "tcp", target) }
	sc := session.NewClient(dial, log.Printf)
	if err := sc.Run(context.Background(), sendStream{r: pr}); err != nil {
		return fmt.Errorf("push to %s: %w", target, err)
	}
	log.Printf("pushed %q (%d bytes) to %s", payloadName, len(data), target)
	return nil
}
