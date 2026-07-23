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
	"path/filepath"
	"strings"

	"github.com/netbirdio/netbird/client/embed"
)

// Content-addressed artifact mesh (F11).
//
// A CAS-enabled drop receiver stores every received file under its SHA-256
// content hash instead of its name — so identical bytes are stored once
// (dedup) and any file is addressable by hash. A holder can serve those blobs
// to peers by hash:
//
//	meshmcp fetch <peer-ip:port> <sha256> [--out file]
//
// Integrity is intrinsic: the fetcher recomputes the hash and rejects a blob
// whose bytes do not match what it asked for. Because the address IS the hash,
// a fetch is idempotent and safe to retry — no resumable session needed.

// casStore is a sharded content-addressed blob store rooted at Dir.
type casStore struct{ dir string }

// blobPath returns the on-disk path for a hash: <dir>/<aa>/<full-hash>.
func (c casStore) blobPath(hash string) (string, error) {
	if len(hash) != 64 || !isHex(hash) {
		return "", fmt.Errorf("invalid sha256 %q", hash)
	}
	return filepath.Join(c.dir, hash[:2], hash), nil
}

func (c casStore) has(hash string) bool {
	p, err := c.blobPath(hash)
	if err != nil {
		return false
	}
	_, err = os.Stat(p)
	return err == nil
}

// casPlacer stores a received file by its content hash (ignores the name).
func casPlacer(dir string) placer {
	c := casStore{dir: dir}
	return func(_ dropHeader, hash string) (string, error) { return c.blobPath(hash) }
}

func isHex(s string) bool {
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return false
		}
	}
	return true
}

// fetchReq is the single request line a fetcher sends.
type fetchReq struct {
	Hash string `json:"hash"`
}

// fetchResp is the response header preceding the blob bytes.
type fetchResp struct {
	Found bool   `json:"found"`
	Size  int64  `json:"size"`
	Error string `json:"error,omitempty"`
}

// serveFetch answers one fetch request on conn from the store.
func serveFetch(conn net.Conn, store casStore) {
	defer conn.Close()
	dec := json.NewDecoder(conn)
	var req fetchReq
	if err := dec.Decode(&req); err != nil {
		writeFetchResp(conn, fetchResp{Error: "bad request"})
		return
	}
	p, err := store.blobPath(req.Hash)
	if err != nil {
		writeFetchResp(conn, fetchResp{Error: err.Error()})
		return
	}
	f, err := os.Open(p)
	if err != nil {
		writeFetchResp(conn, fetchResp{Found: false})
		return
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		writeFetchResp(conn, fetchResp{Error: "stat failed"})
		return
	}
	if err := writeFetchResp(conn, fetchResp{Found: true, Size: fi.Size()}); err != nil {
		return
	}
	// Note: dec may have buffered bytes past the JSON request, but a fetcher
	// sends nothing after it, so streaming the file directly to conn is safe.
	_, _ = io.Copy(conn, f)
}

func writeFetchResp(conn net.Conn, r fetchResp) error {
	b, _ := json.Marshal(r)
	_, err := conn.Write(append(b, '\n'))
	return err
}

// serveFetchListener starts a background listener that answers fetch-by-hash
// requests from the store, gated by the same sender ACL as drops.
func serveFetchListener(client *embed.Client, port int, store casStore, checker acl) error {
	ln, err := client.ListenTCP(fmt.Sprintf(":%d", port))
	if err != nil {
		return fmt.Errorf("listen on fetch port %d: %w", port, err)
	}
	log.Printf("content-addressed fetch server on mesh port %d", port)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			pubKey, fqdn := peerIdentity(client, conn.RemoteAddr())
			if !checker.allows(pubKey, fqdn) {
				log.Printf("fetch DENIED from %s (%s)", fqdn, shortKey(pubKey))
				conn.Close()
				continue
			}
			go serveFetch(conn, store)
		}
	}()
	return nil
}

// cmdFetch retrieves a blob by hash from a peer's content-addressed store.
// With --gc it instead prunes a LOCAL store under explicit age/size bounds
// (dry-run unless --apply; see casgc.go for the no-reference-model rationale).
func cmdFetch(args []string) error {
	fs := flag.NewFlagSet("fetch", flag.ExitOnError)
	o := meshFlags(fs)
	out := fs.String("out", "", "write the blob here (default: <hash> in the current directory)")
	maxBytes := fs.Int64("max-bytes", defaultFetchMaxBytes, "reject a blob larger than this many bytes (0 = no limit)")
	gc := fs.Bool("gc", false, "garbage-collect a local CAS directory instead of fetching (dry run unless --apply)")
	gcDir := fs.String("dir", "", "with --gc: the local CAS directory to prune")
	gcMaxAge := fs.Duration("max-age", 0, "with --gc: delete blobs not modified within this duration (e.g. 720h)")
	gcMaxTotal := fs.Int64("max-total-bytes", 0, "with --gc: after age pruning, delete oldest blobs until the store fits this many bytes")
	gcApply := fs.Bool("apply", false, "with --gc: actually delete (default is a dry run)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *gc {
		if fs.NArg() != 0 {
			return errors.New("usage: meshmcp fetch --gc --dir <cas-dir> [--max-age 720h] [--max-total-bytes N] [--apply]")
		}
		return cmdFetchGC(*gcDir, *gcMaxAge, *gcMaxTotal, *gcApply)
	}
	if fs.NArg() != 2 {
		return errors.New("usage: meshmcp fetch [flags] <peer-ip:port> <sha256>")
	}
	target, hash := fs.Arg(0), strings.ToLower(fs.Arg(1))
	if len(hash) != 64 || !isHex(hash) {
		return fmt.Errorf("%q is not a sha256 hash", hash)
	}
	dest := *out
	if dest == "" {
		dest = hash
	}

	o.BlockInbound = true
	client, err := startMesh(o, os.Stderr)
	if err != nil {
		return err
	}
	defer stopMesh(client)

	conn, err := client.Dial(context.Background(), "tcp", target)
	if err != nil {
		return fmt.Errorf("dial %s over mesh: %w", target, err)
	}
	defer conn.Close()

	if err := json.NewEncoder(conn).Encode(fetchReq{Hash: hash}); err != nil {
		return fmt.Errorf("send request: %w", err)
	}
	got, err := fetchBlob(conn, hash, dest, *maxBytes)
	if err != nil {
		return err
	}
	log.Printf("fetched %s (%d bytes) -> %s", hash, got, dest)
	return nil
}

// defaultFetchMaxBytes bounds a fetched blob by default: the size is declared
// by the serving peer, so an unbounded copy lets a malicious holder stream
// arbitrary bytes and fill the requester's disk before the hash is even
// checked. Override with --max-bytes (0 disables the limit).
const defaultFetchMaxBytes = 256 << 20 // 256 MiB

// fetchBlob reads a fetch response from r and writes the verified blob to dest.
// maxBytes rejects a peer-declared size larger than the limit before any bytes
// are streamed (0 = no limit).
func fetchBlob(r io.Reader, wantHash, dest string, maxBytes int64) (int64, error) {
	br := newLineReader(r)
	line, err := br.readLine()
	if err != nil {
		return 0, fmt.Errorf("read response: %w", err)
	}
	var resp fetchResp
	if err := json.Unmarshal(line, &resp); err != nil {
		return 0, fmt.Errorf("bad response: %w", err)
	}
	if resp.Error != "" {
		return 0, fmt.Errorf("peer error: %s", resp.Error)
	}
	if !resp.Found {
		return 0, fmt.Errorf("peer does not have blob %s", wantHash)
	}
	if resp.Size < 0 {
		return 0, fmt.Errorf("peer declared a negative blob size %d", resp.Size)
	}
	if maxBytes > 0 && resp.Size > maxBytes {
		return 0, fmt.Errorf("peer-declared blob size %d exceeds the %d-byte limit (raise --max-bytes to allow)", resp.Size, maxBytes)
	}

	tmp, err := os.CreateTemp(filepath.Dir(mustAbsDir(dest)), ".fetch-*")
	if err != nil {
		return 0, err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	h := sha256.New()
	// io.CopyN stops at resp.Size, which is now bounded by maxBytes above; the
	// LimitReader is belt-and-suspenders against a peer streaming past it.
	n, err := io.CopyN(io.MultiWriter(tmp, h), io.LimitReader(br, resp.Size), resp.Size)
	if err != nil {
		tmp.Close()
		return 0, fmt.Errorf("receive blob: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return 0, err
	}
	got := hex.EncodeToString(h.Sum(nil))
	if got != wantHash {
		return 0, fmt.Errorf("hash mismatch: asked for %s, received %s", wantHash, got)
	}
	if err := os.Rename(tmpName, dest); err != nil {
		if cerr := copyFile(tmpName, dest, 0o644); cerr != nil {
			return 0, cerr
		}
	}
	return n, nil
}

func mustAbsDir(dest string) string {
	if d := filepath.Dir(dest); d != "" {
		return dest
	}
	return "./" + dest
}

// lineReader reads a single newline-delimited header then hands back the
// remaining buffered + underlying bytes as a stream.
type lineReader struct {
	r   io.Reader
	buf []byte
}

func newLineReader(r io.Reader) *lineReader { return &lineReader{r: r} }

func (l *lineReader) readLine() ([]byte, error) {
	for {
		if i := indexNL(l.buf); i >= 0 {
			line := l.buf[:i]
			l.buf = l.buf[i+1:]
			return line, nil
		}
		tmp := make([]byte, 4096)
		n, err := l.r.Read(tmp)
		l.buf = append(l.buf, tmp[:n]...)
		if err != nil {
			if i := indexNL(l.buf); i >= 0 {
				line := l.buf[:i]
				l.buf = l.buf[i+1:]
				return line, nil
			}
			return nil, err
		}
	}
}

func (l *lineReader) Read(p []byte) (int, error) {
	if len(l.buf) > 0 {
		n := copy(p, l.buf)
		l.buf = l.buf[n:]
		return n, nil
	}
	return l.r.Read(p)
}

func indexNL(b []byte) int {
	for i, c := range b {
		if c == '\n' {
			return i
		}
	}
	return -1
}
