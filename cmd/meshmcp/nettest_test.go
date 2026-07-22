package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"testing"

	"github.com/xrey167/meshmcp/mcp"
	"github.com/xrey167/meshmcp/mcpclient"
)

// startLoopbackServer serves an mcp.Server (configured by the caller) on a
// loopback TCP listener, so router/orchestrator logic can be tested end to
// end without the mesh. Returns the address and a stop func.
func startLoopbackServer(t *testing.T, configure func(*mcp.Server)) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := mcp.New("upstream", "1.0")
	configure(s)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = s.Serve(context.Background(), c, c)
			}(conn)
		}
	}()
	return ln.Addr().String(), func() { ln.Close() }
}

// loopbackDial dials plain loopback TCP (the test stand-in for a mesh dial).
func loopbackDial(_ context.Context, addr string) (net.Conn, error) {
	return net.Dial("tcp", addr)
}

// rwPair adapts a read half and a write half into one io.ReadWriteCloser.
type rwPair struct {
	r *io.PipeReader
	w *io.PipeWriter
}

func (p rwPair) Read(b []byte) (int, error)  { return p.r.Read(b) }
func (p rwPair) Write(b []byte) (int, error) { return p.w.Write(b) }
func (p rwPair) Close() error                { p.r.Close(); return p.w.Close() }

// clientTo drives an in-process mcp.Server with an mcpclient over pipes.
func clientTo(s *mcp.Server) *mcpclient.Client {
	c2sR, c2sW := io.Pipe()
	s2cR, s2cW := io.Pipe()
	go func() { _ = s.Serve(context.Background(), c2sR, s2cW); s2cW.Close() }()
	return mcpclient.New(rwPair{r: s2cR, w: c2sW}, nil)
}

// addTool / echoTool are simple upstream tools reused across tests.
func addTool() mcp.Tool {
	return mcp.Tool{
		Name: "add",
		Handler: func(_ context.Context, args json.RawMessage) (mcp.ToolResult, error) {
			var a struct{ A, B float64 }
			_ = json.Unmarshal(args, &a)
			return mcp.ToolResult{Content: []mcp.Content{mcp.Text(fmt.Sprintf("%v", a.A+a.B))}}, nil
		},
	}
}

func echoTool() mcp.Tool {
	return mcp.Tool{
		Name: "echo",
		Handler: func(_ context.Context, args json.RawMessage) (mcp.ToolResult, error) {
			var a struct {
				Text string `json:"text"`
			}
			_ = json.Unmarshal(args, &a)
			return mcp.ToolResult{Content: []mcp.Content{mcp.Text(a.Text)}}, nil
		},
	}
}

// firstText extracts the first text content from a tools/call result.
func firstText(raw json.RawMessage) string {
	var r struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(raw, &r); err != nil || len(r.Content) == 0 {
		return string(raw)
	}
	return r.Content[0].Text
}
