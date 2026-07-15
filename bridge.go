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

	"github.com/netbirdio/netbird/client/embed"

	"meshmcp/session"
)

// cmdConnect joins the mesh and bridges stdio to a remote stdio backend.
// This is the command MCP clients (e.g. Claude Code) launch as a "stdio
// MCP server": stdout carries the MCP channel, all logs go to stderr.
func cmdConnect(args []string) error {
	fs := flag.NewFlagSet("connect", flag.ExitOnError)
	o := meshFlags(fs)
	resumable := fs.Bool("resumable", false, "keep the logical session alive across mesh reconnects (backend must be resumable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: meshmcp connect [flags] <peer-ip:port>")
	}
	target := fs.Arg(0)

	o.BlockInbound = true // outbound-only peer
	client, err := startMesh(o, os.Stderr)
	if err != nil {
		return err
	}
	defer stopMesh(client)

	if *resumable {
		return connectResumable(client, target)
	}

	conn, err := client.Dial(context.Background(), "tcp", target)
	if err != nil {
		return fmt.Errorf("dial %s over mesh: %w", target, err)
	}
	defer conn.Close()
	log.Printf("connected to %s", target)

	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(conn, os.Stdin)
		conn.Close() // local client hung up: end the session
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(os.Stdout, conn)
		done <- struct{}{}
	}()
	<-done
	return nil
}

// connectResumable bridges local stdio to a resumable mesh session that
// transparently reconnects and resyncs whenever the mesh transport drops.
func connectResumable(client *embed.Client, target string) error {
	dial := func(ctx context.Context) (net.Conn, error) {
		return client.Dial(ctx, "tcp", target)
	}
	sc := session.NewClient(dial, log.Printf)
	log.Printf("resumable session to %s", target)
	return sc.Run(context.Background(), stdio{})
}

// stdio adapts the process's stdin/stdout to an io.ReadWriteCloser.
type stdio struct{}

func (stdio) Read(p []byte) (int, error)  { return os.Stdin.Read(p) }
func (stdio) Write(p []byte) (int, error) { return os.Stdout.Write(p) }
func (stdio) Close() error                { return os.Stdin.Close() }

// cmdForward joins the mesh and forwards a local TCP listener to a mesh
// peer — the way to reach remote HTTP (Streamable HTTP) MCP backends:
// point the MCP client at http://127.0.0.1:<local-port>/... .
func cmdForward(args []string) error {
	fs := flag.NewFlagSet("forward", flag.ExitOnError)
	o := meshFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		return errors.New("usage: meshmcp forward [flags] <local-addr> <peer-ip:port>  (e.g. 127.0.0.1:8090 100.92.1.5:9102)")
	}
	local, target := fs.Arg(0), fs.Arg(1)

	o.BlockInbound = true
	client, err := startMesh(o, os.Stderr)
	if err != nil {
		return err
	}
	defer stopMesh(client)

	ln, err := net.Listen("tcp", local)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", local, err)
	}
	log.Printf("forwarding %s -> mesh %s", ln.Addr(), target)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	go func() {
		<-sig
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				log.Println("shutting down")
				return nil
			}
			return err
		}
		go func(conn net.Conn) {
			defer conn.Close()
			remote, err := client.Dial(context.Background(), "tcp", target)
			if err != nil {
				log.Printf("dial %s over mesh: %v", target, err)
				return
			}
			defer remote.Close()

			done := make(chan struct{}, 2)
			go func() { _, _ = io.Copy(remote, conn); remote.Close(); done <- struct{}{} }()
			go func() { _, _ = io.Copy(conn, remote); conn.Close(); done <- struct{}{} }()
			<-done
			<-done
		}(conn)
	}
}
