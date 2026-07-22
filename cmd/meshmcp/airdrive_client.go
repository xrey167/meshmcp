package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"path/filepath"

	"github.com/xrey167/meshmcp/air"
)

// -------- client --------

// driveDial joins the mesh outbound-only and dials the drive daemon, returning
// the raw conn and a cleanup that closes it and leaves the mesh.
func driveDial(o *meshOptions, target string) (net.Conn, func(), error) {
	o.BlockInbound = true
	client, err := startMesh(o, os.Stderr)
	if err != nil {
		return nil, nil, err
	}
	conn, err := client.Dial(context.Background(), "tcp", target)
	if err != nil {
		stopMesh(client)
		return nil, nil, fmt.Errorf("dial %s over mesh: %w", target, err)
	}
	cleanup := func() { conn.Close(); stopMesh(client) }
	return conn, cleanup, nil
}

// driveErr renders a failed DriveResp as an error.
func driveErr(r air.DriveResp) error {
	msg := r.Error
	if msg == "" {
		msg = "drive error"
	}
	if r.Code != "" {
		return fmt.Errorf("%s (%s)", msg, r.Code)
	}
	return errors.New(msg)
}

// driveClientList sends a list request and returns the entries.
func driveClientList(conn net.Conn, dirPath string) ([]air.DriveEntry, error) {
	if err := air.WriteDriveReq(conn, air.DriveReq{Op: air.OpList, Path: dirPath}); err != nil {
		return nil, err
	}
	resp, err := air.ReadDriveResp(bufio.NewReader(conn))
	if err != nil {
		return nil, err
	}
	if !resp.OK {
		return nil, driveErr(resp)
	}
	return resp.Entries, nil
}

// driveClientGet pulls one file, verifying the server-declared size (bounded by
// maxBytes) and content hash — the fetchBlob shape.
func driveClientGet(conn net.Conn, filePath string, maxBytes int64) ([]byte, string, error) {
	if err := air.WriteDriveReq(conn, air.DriveReq{Op: air.OpGet, Path: filePath}); err != nil {
		return nil, "", err
	}
	br := bufio.NewReader(conn)
	resp, err := air.ReadDriveResp(br)
	if err != nil {
		return nil, "", err
	}
	if !resp.OK {
		return nil, "", driveErr(resp)
	}
	if resp.Size < 0 {
		return nil, "", fmt.Errorf("server declared a negative size %d", resp.Size)
	}
	if maxBytes > 0 && resp.Size > maxBytes {
		return nil, "", fmt.Errorf("file size %d exceeds the %d-byte limit (raise --max-bytes)", resp.Size, maxBytes)
	}
	h := sha256.New()
	buf := make([]byte, 0, resp.Size)
	w := &bytesCollector{buf: &buf}
	if _, err := io.CopyN(io.MultiWriter(w, h), io.LimitReader(br, resp.Size), resp.Size); err != nil {
		return nil, "", fmt.Errorf("receive file: %w", err)
	}
	got := hex.EncodeToString(h.Sum(nil))
	if resp.SHA256 != "" && got != resp.SHA256 {
		return nil, "", fmt.Errorf("hash mismatch: server said %s, received %s", resp.SHA256, got)
	}
	return buf, got, nil
}

// bytesCollector is a tiny io.Writer that appends to a caller-owned slice, so
// the get body can be both hashed and captured in one CopyN.
type bytesCollector struct{ buf *[]byte }

func (c *bytesCollector) Write(p []byte) (int, error) {
	*c.buf = append(*c.buf, p...)
	return len(p), nil
}

// driveClientPut streams one file to the drive as a single self-delimiting drop
// record, then half-closes the write side, then reads the DriveResp.
func driveClientPut(conn net.Conn, destPath, name string, data []byte) (air.DriveResp, error) {
	if err := air.WriteDriveReq(conn, air.DriveReq{Op: air.OpPut, Path: destPath}); err != nil {
		return air.DriveResp{}, err
	}
	if err := sendData(conn, name, data); err != nil {
		return air.DriveResp{}, err
	}
	// Half-close: the record above is self-delimiting (the terminator), so this
	// is defensive — it signals "no more request bytes" while leaving the read
	// half open for the DriveResp. gVisor's gonet.TCPConn and *net.TCPConn both
	// implement CloseWrite; a conn that doesn't is simply left as-is.
	if cw, ok := conn.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
	resp, err := air.ReadDriveResp(bufio.NewReader(conn))
	if err != nil {
		return air.DriveResp{}, err
	}
	return resp, nil
}

// driveClientRm deletes one file.
func driveClientRm(conn net.Conn, filePath string) (air.DriveResp, error) {
	if err := air.WriteDriveReq(conn, air.DriveReq{Op: air.OpRm, Path: filePath}); err != nil {
		return air.DriveResp{}, err
	}
	resp, err := air.ReadDriveResp(bufio.NewReader(conn))
	if err != nil {
		return air.DriveResp{}, err
	}
	return resp, nil
}

// -------- client CLI wrappers --------

func cmdAirDriveLs(args []string) error {
	fs := flag.NewFlagSet("air drive ls", flag.ExitOnError)
	o := meshFlags(fs)
	asJSON := fs.Bool("json", false, "print the listing as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 1 {
		return errors.New("usage: meshmcp air drive ls [flags] <host:port> [path]")
	}
	target := fs.Arg(0)
	dirPath := ""
	if fs.NArg() > 1 {
		dirPath = fs.Arg(1)
	}
	conn, cleanup, err := driveDial(o, target)
	if err != nil {
		return err
	}
	defer cleanup()

	ents, err := driveClientList(conn, dirPath)
	if err != nil {
		return fmt.Errorf("air drive ls: %w", err)
	}
	if *asJSON {
		b, _ := json.MarshalIndent(map[string]any{"entries": ents}, "", "  ")
		fmt.Println(string(b))
		return nil
	}
	if len(ents) == 0 {
		fmt.Fprintln(os.Stderr, dim("empty"))
		return nil
	}
	var rows [][]cell
	for _, e := range ents {
		name := e.Name
		if e.Dir {
			name += "/"
		}
		size := styled("—", dim)
		if !e.Dir {
			size = plain(humanBytes(e.Size))
		}
		rows = append(rows, []cell{styled(name, bold), size, styled(e.ModTime, dim)})
	}
	renderTable(os.Stdout, []string{"name", "size", "modified"}, rows)
	fmt.Fprintln(os.Stderr, dim(fmt.Sprintf("%d entr%s", len(ents), plural(len(ents)))))
	return nil
}

func plural(n int) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}

func cmdAirDriveGet(args []string) error {
	fs := flag.NewFlagSet("air drive get", flag.ExitOnError)
	o := meshFlags(fs)
	out := fs.String("out", "", "write the file here (default: the path's base name in the current directory)")
	maxBytes := fs.Int64("max-bytes", defaultDriveMaxBytes, "reject a file larger than this many bytes (0 = no limit)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		return errors.New("usage: meshmcp air drive get [flags] <host:port> <path>")
	}
	target, remotePath := fs.Arg(0), fs.Arg(1)
	dest := *out
	if dest == "" {
		dest = filepath.Base(filepath.FromSlash(remotePath))
	}
	conn, cleanup, err := driveDial(o, target)
	if err != nil {
		return err
	}
	defer cleanup()

	data, sum, err := driveClientGet(conn, remotePath, *maxBytes)
	if err != nil {
		return fmt.Errorf("air drive get: %w", err)
	}
	if err := os.WriteFile(dest, data, 0o644); err != nil {
		return fmt.Errorf("air drive get: write %s: %w", dest, err)
	}
	fmt.Println(okLine("got %s", remotePath) + dim(fmt.Sprintf(" · %s · sha %s → %s", humanBytes(int64(len(data))), shortKey(sum), dest)))
	return nil
}

func cmdAirDrivePut(args []string) error {
	fs := flag.NewFlagSet("air drive put", flag.ExitOnError)
	o := meshFlags(fs)
	maxBytes := fs.Int64("max-bytes", 64<<20, "reject a local payload larger than this before sending")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 2 || fs.NArg() > 3 {
		return errors.New("usage: meshmcp air drive put [flags] <host:port> <path> [localfile]   (stdin if no localfile)")
	}
	target, remotePath := fs.Arg(0), fs.Arg(1)
	var data []byte
	var err error
	if fs.NArg() == 3 {
		local := fs.Arg(2)
		data, err = os.ReadFile(local)
		if err != nil {
			return fmt.Errorf("air drive put: read %s: %w", local, err)
		}
	} else {
		data, err = io.ReadAll(io.LimitReader(os.Stdin, *maxBytes+1))
		if err != nil {
			return fmt.Errorf("air drive put: read stdin: %w", err)
		}
	}
	if *maxBytes > 0 && int64(len(data)) > *maxBytes {
		return fmt.Errorf("air drive put: payload is %s, over the %s limit (raise --max-bytes)", humanBytes(int64(len(data))), humanBytes(*maxBytes))
	}
	conn, cleanup, err := driveDial(o, target)
	if err != nil {
		return err
	}
	defer cleanup()

	resp, err := driveClientPut(conn, remotePath, path.Base(remotePath), data)
	if err != nil {
		return fmt.Errorf("air drive put: %w", err)
	}
	if !resp.OK {
		return fmt.Errorf("air drive put: %w", driveErr(resp))
	}
	fmt.Println(okLine("put %s", remotePath) + dim(fmt.Sprintf(" · %s · sha %s", humanBytes(resp.Size), shortKey(resp.SHA256))))
	return nil
}

func cmdAirDriveRm(args []string) error {
	fs := flag.NewFlagSet("air drive rm", flag.ExitOnError)
	o := meshFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		return errors.New("usage: meshmcp air drive rm [flags] <host:port> <path>")
	}
	target, remotePath := fs.Arg(0), fs.Arg(1)
	conn, cleanup, err := driveDial(o, target)
	if err != nil {
		return err
	}
	defer cleanup()

	resp, err := driveClientRm(conn, remotePath)
	if err != nil {
		return fmt.Errorf("air drive rm: %w", err)
	}
	if !resp.OK {
		return fmt.Errorf("air drive rm: %w", driveErr(resp))
	}
	fmt.Println(okLine("removed %s", remotePath))
	return nil
}
