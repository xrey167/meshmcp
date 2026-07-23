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

	"github.com/xrey167/meshmcp/internal/connectcli"
)

// cmdConnect joins the mesh and bridges stdio to a remote stdio backend.
// The implementation lives in internal/connectcli, shared with the thin
// meshmcp-connect binary (S45).
func cmdConnect(args []string) error { return connectcli.Connect(args) }

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
	signal.Notify(sig, shutdownSignals...)
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
