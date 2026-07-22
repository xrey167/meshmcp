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
	"path/filepath"

	"github.com/xrey167/meshmcp/session"
)

// Air · Cast — show-on-their-screen: present an image on a peer's Air page.
//
// AirPlay/Chromecast the Air way. Unlike a drop (which lands in an inbox the
// recipient scrolls) or Vision (which renders everything received as a gallery),
// a cast is sender INTENT: "show THIS now" — the image rides the same resumable,
// ACL'd, hash-audited drop transport into the peer's cast inbox, and their
// `air serve --cast <dir>` renders the newest one in a single prominent "Now
// Showing" slot. The peer runs a drop receiver pointed at that dir.
//
//	meshmcp air cast <peer-ip:port> <image>
func cmdAirCast(args []string) error {
	fs := flag.NewFlagSet("air cast", flag.ExitOnError)
	o := meshFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		return errors.New("usage: meshmcp air cast [flags] <peer-ip:port> <image>")
	}
	peer := fs.Arg(0)
	imagePath := fs.Arg(1)

	// Cast is for visual context: refuse a non-image up front (the receiver would
	// still store it, but the "Now Showing" slot only renders images).
	if _, ok := imageType(imagePath); !ok {
		return fmt.Errorf("air cast: %q is not an image (want png/jpg/gif/webp/…)", filepath.Base(imagePath))
	}
	fi, err := os.Stat(imagePath)
	if err != nil {
		return fmt.Errorf("air cast: cannot cast %s: %w", imagePath, err)
	}
	if fi.Size() > maxAirImage {
		return fmt.Errorf("air cast: %s is %s, over the %s cast limit", filepath.Base(imagePath), humanBytes(fi.Size()), humanBytes(maxAirImage))
	}

	o.BlockInbound = true
	client, err := startMesh(o, os.Stderr)
	if err != nil {
		return err
	}
	defer stopMesh(client)

	pr, pw := io.Pipe()
	go func() { pw.CloseWithError(sendFiles(pw, []string{imagePath})) }()
	dial := func(ctx context.Context) (net.Conn, error) { return client.Dial(ctx, "tcp", peer) }
	if err := session.NewClient(dial, log.Printf).Run(context.Background(), sendStream{r: pr}); err != nil {
		return fmt.Errorf("air cast to %s: %w", peer, err)
	}
	fmt.Println(okLine("casting %s → %s", filepath.Base(imagePath), peer))
	return nil
}
