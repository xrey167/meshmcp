package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"github.com/xrey167/meshmcp/policy"
	"github.com/xrey167/meshmcp/session"
)

// Air · Screen — a governed, resumable screen-share.
//
// The "Deeper" form of Air Vision: instead of viewing static drops that
// accumulated in an inbox, a sender streams a LIVE sequence of frames to a peer,
// who watches the newest one update in place. HONEST BOUNDARY: capturing the
// local screen is EXTERNAL (a screenshot loop — scrot/screencapture/ffmpeg —
// writes a frame file); Air owns only what it owns for every payload: governed
// transport (one resumable session, roam-resumable, frames arrive in order),
// identity-gated viewing (deny-by-default sender ACL), and per-frame hash audit.
//
// The receiver keeps ONE rolling frame per sender (dir/<sender>/current.<ext>),
// so disk stays bounded to one live frame each and the full ordered frame
// history is provable in the ledger even though only the latest persists. View
// it with `air serve --cast <dir>` (the newest frame is the "Now Showing" slot).
//
//	SENDER:   meshmcp air screen <peer-ip:port> --watch <frame-file> [--interval 500ms] [--max-frames N]
//	RECEIVER: meshmcp air screen --recv --dir <dir> --allow <id> [--port 9121] [--audit f]
func cmdAirScreen(args []string) error {
	fs := flag.NewFlagSet("air screen", flag.ExitOnError)
	o := meshFlags(fs)
	recv := fs.Bool("recv", false, "run a screen receiver (writes dir/<sender>/current.<ext>)")
	dir := fs.String("dir", "", "receiver: directory to write rolling frames into")
	watch := fs.String("watch", "", "sender: image file to stream each time it changes")
	port := fs.Int("port", 9121, "receiver: mesh port to receive frames on")
	interval := fs.Duration("interval", 500*time.Millisecond, "sender: how often to check the watched file for a new frame")
	maxFrames := fs.Int("max-frames", 0, "sender: stop after N frames (0 = until Ctrl-C)")
	auditPath := fs.String("audit", "", "receiver: append every frame to this JSONL ledger")
	allow := multiFlag{}
	fs.Var(&allow, "allow", "receiver: identity permitted to share their screen to you (repeatable; REQUIRED)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *recv {
		return screenReceive(o, *dir, allow, *port, *auditPath)
	}
	if fs.NArg() != 1 {
		return errors.New("usage: meshmcp air screen [flags] <peer-ip:port> --watch <frame-file>   (or --recv --dir <dir> --allow <id>)")
	}
	if *watch == "" {
		return errors.New("air screen: --watch <frame-file> is required for the sender")
	}
	if _, ok := imageType(*watch); !ok {
		return fmt.Errorf("air screen: --watch %q is not an image", filepath.Base(*watch))
	}
	peer := fs.Arg(0)

	o.BlockInbound = true
	client, err := startMesh(o, os.Stderr)
	if err != nil {
		return err
	}
	defer stopMesh(client)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	fmt.Fprintln(os.Stderr, dim("sharing ")+bold(*watch)+dim(" → "+peer+" · Ctrl-C to stop"))

	pr, pw := io.Pipe()
	go func() { pw.CloseWithError(streamScreen(ctx, pw, *watch, *interval, *maxFrames)) }()
	dial := func(ctx context.Context) (net.Conn, error) { return client.Dial(ctx, "tcp", peer) }
	if err := session.NewClient(dial, log.Printf).Run(ctx, sendStream{r: pr}); err != nil {
		return fmt.Errorf("air screen to %s: %w", peer, err)
	}
	return nil
}

// streamScreen streams the watched image file as an ordered sequence of drop
// records, one per detected change (mtime advance), until ctx ends or maxFrames
// is reached. Each frame is bounded by maxAirImage and must stay an image.
func streamScreen(ctx context.Context, w io.Writer, file string, interval time.Duration, maxFrames int) error {
	if interval <= 0 {
		interval = 500 * time.Millisecond
	}
	ext := strings.ToLower(filepath.Ext(file))
	if _, ok := imageContentTypes[ext]; !ok {
		return fmt.Errorf("watched file %q is not an image", file)
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	var last time.Time
	seq := 0
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			fi, err := os.Stat(file)
			if err != nil || !fi.ModTime().After(last) {
				continue
			}
			data, err := os.ReadFile(file)
			if err != nil || len(data) == 0 || int64(len(data)) > maxAirImage {
				continue
			}
			if err := sendData(w, fmt.Sprintf("frame-%06d%s", seq, ext), data); err != nil {
				return err
			}
			last = fi.ModTime()
			seq++
			if maxFrames > 0 && seq >= maxFrames {
				return nil
			}
		}
	}
}

// screenReceive runs the receiver daemon: it admits senders deny-by-default,
// writes each sender's frames to one rolling file, and audits every frame.
func screenReceive(o *meshOptions, dir string, allow multiFlag, port int, auditPath string) error {
	if dir == "" {
		return errors.New("air screen --recv: --dir <dir> is required")
	}
	if len(allow) == 0 {
		return errors.New("air screen --recv: --allow <id> is required (who may share their screen to you); deny-by-default")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("air screen: create dir %s: %w", dir, err)
	}

	o.BlockInbound = false
	client, err := startMesh(o, os.Stderr)
	if err != nil {
		return err
	}
	defer stopMesh(client)

	var audit *policy.AuditLog
	if auditPath != "" {
		f, err := os.OpenFile(auditPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return fmt.Errorf("air screen: open audit log: %w", err)
		}
		defer f.Close()
		audit = policy.NewAuditLog(f, func() string { return time.Now().UTC().Format(time.RFC3339) })
	}

	ln, err := client.ListenTCP(fmt.Sprintf(":%d", port))
	if err != nil {
		return fmt.Errorf("air screen: listen on mesh port %d: %w", port, err)
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	go func() { <-sig; ln.Close() }()

	checker := newACL(allow)
	fmt.Fprintf(os.Stderr, "receiving screens into %s on mesh port %d (view with: meshmcp air serve --cast %s)\n", dir, port, dir)
	srv := session.NewServer(newScreenFactory(dir, audit), 2*time.Minute, log.Printf)
	for {
		conn, err := ln.Accept()
		if err != nil {
			return nil
		}
		pubKey, fqdn := peerIdentity(client, conn.RemoteAddr())
		if !checker.allows(pubKey, fqdn) {
			log.Printf("screen DENIED from %s (%s): not in allow list", fqdn, shortKey(pubKey))
			conn.Close()
			continue
		}
		go srv.Handle(conn, session.Meta{PeerFQDN: fqdn, PeerAddr: conn.RemoteAddr().String(), PeerKey: pubKey})
	}
}

// newScreenFactory returns a session backend factory whose backends receive a
// sender's frame stream, verify each hash, write it to that sender's rolling
// current frame, and audit each — the same send-only receive shape as drop.
func newScreenFactory(dir string, audit *policy.AuditLog) session.BackendFactory {
	return func(meta session.Meta) (session.Backend, error) {
		pr, pw := io.Pipe()
		d := &dropSink{pw: pw, done: make(chan struct{})}
		place := screenPlacer(dir, meta.PeerFQDN)
		go func() {
			err := recvFiles(pr, place, dropLimits{PerFile: maxAirImage, MaxFiles: 1_000_000, MaxTotal: 1 << 40}, func(fi recvInfo) {
				if audit != nil {
					audit.Append(policy.AuditRecord{
						Backend: "screen", Peer: meta.PeerFQDN, PeerKey: meta.PeerKey, PeerAddr: meta.PeerAddr,
						Method: "screen/frame", Tool: fi.SHA256, Decision: "allow",
						Reason: fmt.Sprintf("frame %q (%d bytes)", fi.Name, fi.Bytes), Rule: -1,
					})
				}
			})
			pr.CloseWithError(err)
			d.finish(err)
		}()
		return d, nil
	}
}

// screenPlacer names every frame from a sender to that sender's single rolling
// file dir/<sender>/current.<ext>, so disk is bounded to one live frame per
// sender (the drop receiver's atomic temp+rename gives a torn-free swap). The
// frame's extension must be a known image type, and the sender segment is
// sanitized to a single safe path component.
func screenPlacer(dir, sender string) placer {
	return func(hdr dropHeader, _ string) (string, error) {
		ext := strings.ToLower(filepath.Ext(hdr.Name))
		if _, ok := imageContentTypes[ext]; !ok {
			return "", fmt.Errorf("screen frame %q is not an image", hdr.Name)
		}
		return sanitizeDest(dir, filepath.Join(screenSubdir(sender), "current"+ext))
	}
}

// screenSubdir reduces a sender FQDN to one safe path segment.
func screenSubdir(sender string) string {
	if sender == "" {
		return "peer"
	}
	return strings.NewReplacer("/", "_", "\\", "_", ":", "_", "..", "_").Replace(sender)
}
