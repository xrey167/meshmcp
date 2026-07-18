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
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"meshmcp/policy"
	"meshmcp/session"
)

// meshmcp drop — AirDrop across mesh instances.
//
// A drop streams files to a mesh peer by cryptographic identity: end-to-end
// encrypted by WireGuard, resumable over the session layer (survives a roam
// mid-transfer), gated by the receiver's sender ACL, and audited (a content
// hash of every received file lands in the ledger). No cloud, no open ports.
//
//	meshmcp drop <peer-ip:port> <file...>     send files to a peer
//	meshmcp drop --config drop.yaml           run a drop receiver
//
// The transfer wire is a stream of per-file records:
//
//	<header-json>\n              {"name","size","mode"}
//	<size bytes of content>
//	<trailer-json>\n             {"sha256"}
//
// terminated by EOF. The receiver hashes the content as it lands and rejects
// a file whose trailer hash does not match — corruption and truncation are
// detected, and the recorded hash makes "who sent what to whom" provable.

// dropHeader precedes each file's content.
type dropHeader struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
	Mode uint32 `json:"mode"`
}

// dropTrailer follows each file's content and carries its content hash.
type dropTrailer struct {
	SHA256 string `json:"sha256"`
}

// recvInfo describes one successfully received file.
type recvInfo struct {
	Name   string
	SHA256 string
	Bytes  int64
	Path   string // where it was installed on disk
}

// sendFiles streams each path to w as header + content + trailer records.
func sendFiles(w io.Writer, paths []string) error {
	bw := bufio.NewWriter(w)
	for _, p := range paths {
		fi, err := os.Stat(p)
		if err != nil {
			return fmt.Errorf("stat %s: %w", p, err)
		}
		if fi.IsDir() {
			return fmt.Errorf("%s is a directory (directory drops are not yet supported)", p)
		}
		f, err := os.Open(p)
		if err != nil {
			return fmt.Errorf("open %s: %w", p, err)
		}
		hdr := dropHeader{Name: filepath.Base(p), Size: fi.Size(), Mode: uint32(fi.Mode().Perm())}
		hb, _ := json.Marshal(hdr)
		if _, err := bw.Write(append(hb, '\n')); err != nil {
			f.Close()
			return err
		}
		h := sha256.New()
		n, err := io.CopyN(io.MultiWriter(bw, h), f, fi.Size())
		f.Close()
		if err != nil {
			return fmt.Errorf("read %s: %w", p, err)
		}
		if n != fi.Size() {
			return fmt.Errorf("%s: short read (%d of %d bytes)", p, n, fi.Size())
		}
		tb, _ := json.Marshal(dropTrailer{SHA256: hex.EncodeToString(h.Sum(nil))})
		if _, err := bw.Write(append(tb, '\n')); err != nil {
			return err
		}
	}
	return bw.Flush()
}

// placer decides the final on-disk path for a received file given its header
// and verified content hash. The default names files in a directory; the CAS
// placer names them by hash (content-addressed, dedup-automatic).
type placer func(hdr dropHeader, hash string) (string, error)

// dirPlacer stores a received file under its (sanitized) name in dir.
func dirPlacer(dir string) placer {
	return func(hdr dropHeader, _ string) (string, error) { return sanitizeDest(dir, hdr.Name) }
}

// recvFiles parses the stream on r, writing verified files via place. maxBytes
// (>0) caps any single file. onFile is called once per received file.
func recvFiles(r io.Reader, place placer, maxBytes int64, onFile func(recvInfo)) error {
	br := bufio.NewReader(r)
	for {
		line, err := br.ReadBytes('\n')
		if len(line) == 0 && errors.Is(err, io.EOF) {
			return nil // clean end of stream
		}
		if err != nil {
			return fmt.Errorf("read header: %w", err)
		}
		var hdr dropHeader
		if err := json.Unmarshal(line[:len(line)-1], &hdr); err != nil {
			return fmt.Errorf("bad header: %w", err)
		}
		if hdr.Size < 0 {
			return fmt.Errorf("bad file size %d", hdr.Size)
		}
		if maxBytes > 0 && hdr.Size > maxBytes {
			return fmt.Errorf("file %q is %d bytes, over the %d-byte limit", hdr.Name, hdr.Size, maxBytes)
		}
		info, err := recvOne(br, place, hdr)
		if err != nil {
			return err
		}
		if onFile != nil {
			onFile(info)
		}
	}
}

// recvOne reads exactly hdr.Size content bytes plus the trailer, verifies the
// hash, then places the file at the path chosen by place (atomic rename).
func recvOne(br *bufio.Reader, place placer, hdr dropHeader) (recvInfo, error) {
	tmp, err := os.CreateTemp("", ".drop-*")
	if err != nil {
		return recvInfo{}, err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after a successful rename

	h := sha256.New()
	if _, err := io.CopyN(io.MultiWriter(tmp, h), br, hdr.Size); err != nil {
		tmp.Close()
		return recvInfo{}, fmt.Errorf("receive %q: %w", hdr.Name, err)
	}
	if err := tmp.Close(); err != nil {
		return recvInfo{}, err
	}

	line, err := br.ReadBytes('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return recvInfo{}, fmt.Errorf("read trailer: %w", err)
	}
	var trailer dropTrailer
	if err := json.Unmarshal([]byte(strings.TrimRight(string(line), "\n")), &trailer); err != nil {
		return recvInfo{}, fmt.Errorf("bad trailer for %q: %w", hdr.Name, err)
	}
	got := hex.EncodeToString(h.Sum(nil))
	if trailer.SHA256 != got {
		return recvInfo{}, fmt.Errorf("hash mismatch for %q: sent %s, received %s", hdr.Name, trailer.SHA256, got)
	}

	dest, err := place(hdr, got)
	if err != nil {
		return recvInfo{}, err
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return recvInfo{}, err
	}
	mode := os.FileMode(hdr.Mode).Perm()
	if mode == 0 {
		mode = 0o644
	}
	if err := os.Chmod(tmpName, mode); err != nil {
		return recvInfo{}, err
	}
	if err := os.Rename(tmpName, dest); err != nil {
		// Cross-device rename (temp dir on another filesystem): fall back to copy.
		if err := copyFile(tmpName, dest, mode); err != nil {
			return recvInfo{}, fmt.Errorf("install %q: %w", hdr.Name, err)
		}
	}
	return recvInfo{Name: hdr.Name, SHA256: got, Bytes: hdr.Size, Path: dest}, nil
}

// copyFile is the cross-filesystem fallback for os.Rename.
func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// sanitizeDest resolves name against dir and rejects any path that is absolute
// or escapes dir via "..". A malicious sender cannot write outside the
// destination directory.
func sanitizeDest(dir, name string) (string, error) {
	if name == "" {
		return "", errors.New("refusing empty file name")
	}
	if filepath.IsAbs(name) || strings.ContainsRune(name, ':') {
		return "", fmt.Errorf("refusing absolute path %q", name)
	}
	clean := filepath.Clean(name)
	if clean == ".." || strings.HasPrefix(clean, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("refusing path %q: escapes destination directory", name)
	}
	dest := filepath.Join(dir, clean)
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	absDest, err := filepath.Abs(dest)
	if err != nil {
		return "", err
	}
	if absDest != absDir && !strings.HasPrefix(absDest, absDir+string(os.PathSeparator)) {
		return "", fmt.Errorf("refusing path %q: escapes destination directory", name)
	}
	return absDest, nil
}

// sendStream is the local end of a send-only session: Read yields the framed
// file stream produced by sendFiles; the receiver returns no application data,
// so Write is discarded.
type sendStream struct {
	r io.Reader
}

func (s sendStream) Read(p []byte) (int, error) { return s.r.Read(p) }
func (sendStream) Write(p []byte) (int, error)  { return len(p), nil }
func (sendStream) Close() error                 { return nil }

// cmdDrop sends files to a peer, or (with --config) runs a drop receiver.
func cmdDrop(args []string) error {
	fs := flag.NewFlagSet("drop", flag.ExitOnError)
	o := meshFlags(fs)
	cfgPath := fs.String("config", "", "run a drop receiver from this config file (instead of sending)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *cfgPath != "" {
		return dropReceive(*cfgPath)
	}
	if fs.NArg() < 2 {
		return errors.New("usage: meshmcp drop [flags] <peer-ip:port> <file...>   (or: meshmcp drop --config drop.yaml)")
	}
	target := fs.Arg(0)
	files := fs.Args()[1:]
	for _, f := range files {
		if _, err := os.Stat(f); err != nil {
			return fmt.Errorf("cannot send %s: %w", f, err)
		}
	}

	o.BlockInbound = true // outbound-only peer
	client, err := startMesh(o, os.Stderr)
	if err != nil {
		return err
	}
	defer stopMesh(client)

	pr, pw := io.Pipe()
	go func() { pw.CloseWithError(sendFiles(pw, files)) }()

	dial := func(ctx context.Context) (net.Conn, error) { return client.Dial(ctx, "tcp", target) }
	sc := session.NewClient(dial, log.Printf)
	log.Printf("dropping %d file(s) to %s", len(files), target)
	if err := sc.Run(context.Background(), sendStream{r: pr}); err != nil {
		return fmt.Errorf("drop to %s: %w", target, err)
	}
	log.Printf("drop complete")
	return nil
}

// dropReceive runs the receiver daemon: it listens on the mesh, gates each
// sender by the ACL, receives their files into Dir, and audits every one.
func dropReceive(cfgPath string) error {
	cfg, err := loadDropConfig(cfgPath)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(cfg.Dir, 0o755); err != nil {
		return fmt.Errorf("create dir %s: %w", cfg.Dir, err)
	}

	client, err := startMesh(cfg.Mesh.options(), os.Stderr)
	if err != nil {
		return err
	}
	defer stopMesh(client)
	if st, err := client.Status(); err == nil {
		log.Printf("drop receiver up: %s (%s), dir %s, port %d",
			strings.SplitN(st.LocalPeerState.IP, "/", 2)[0], st.LocalPeerState.FQDN, cfg.Dir, cfg.ListenPort)
	}

	var audit *policy.AuditLog
	if cfg.AuditLog != "" {
		f, err := os.OpenFile(cfg.AuditLog, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return fmt.Errorf("open audit log %s: %w", cfg.AuditLog, err)
		}
		defer f.Close()
		audit = policy.NewAuditLog(f, func() string { return time.Now().UTC().Format(time.RFC3339) })
	}

	ln, err := client.ListenTCP(fmt.Sprintf(":%d", cfg.ListenPort))
	if err != nil {
		return fmt.Errorf("listen on mesh port %d: %w", cfg.ListenPort, err)
	}
	checker := newACL(cfg.Allow)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	go func() { <-sig; ln.Close() }()

	place := dirPlacer(cfg.Dir)
	if cfg.CAS {
		place = casPlacer(cfg.Dir)
		log.Printf("content-addressed store enabled (files stored by hash)")
		if cfg.FetchPort > 0 {
			if err := serveFetchListener(client, cfg.FetchPort, casStore{dir: cfg.Dir}, newACL(cfg.Allow)); err != nil {
				return err
			}
		}
	}
	srv := session.NewServer(newDropFactory(place, cfg.MaxBytes, audit), 2*time.Minute, log.Printf)
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println("drop receiver shutting down")
			return nil
		}
		pubKey, fqdn := peerIdentity(client, conn.RemoteAddr())
		if !checker.allows(pubKey, fqdn) {
			log.Printf("drop DENIED from %s (%s): not in allow list", fqdn, shortKey(pubKey))
			conn.Close()
			continue
		}
		go srv.Handle(conn, session.Meta{PeerFQDN: fqdn, PeerAddr: conn.RemoteAddr().String(), PeerKey: pubKey})
	}
}

// newDropFactory returns a session backend factory whose backends receive a
// dropped file stream, verify each hash, place each file via place, and audit.
func newDropFactory(place placer, maxBytes int64, audit *policy.AuditLog) session.BackendFactory {
	return func(meta session.Meta) (session.Backend, error) {
		pr, pw := io.Pipe()
		d := &dropSink{pw: pw, done: make(chan struct{})}
		go func() {
			err := recvFiles(pr, place, maxBytes, func(fi recvInfo) {
				log.Printf("received %q (%d bytes, sha256 %s) from %s", fi.Name, fi.Bytes, fi.SHA256, meta.PeerFQDN)
				if audit != nil {
					audit.Append(policy.AuditRecord{
						Backend:  "drop",
						Peer:     meta.PeerFQDN,
						PeerKey:  meta.PeerKey,
						PeerAddr: meta.PeerAddr,
						Method:   "drop/recv",
						Tool:     fi.SHA256,
						Decision: "allow",
						Reason:   fmt.Sprintf("received %q (%d bytes)", fi.Name, fi.Bytes),
						Rule:     -1,
					})
				}
			})
			pr.CloseWithError(err)
			d.finish(err)
		}()
		return d, nil
	}
}

// dropSink is a session backend for a send-only transfer: bytes the peer
// sends arrive via Write and are parsed into files; Read blocks until the
// transfer ends (the receiver produces no reverse data).
type dropSink struct {
	pw   *io.PipeWriter
	done chan struct{}
	err  error
}

func (d *dropSink) Write(p []byte) (int, error) { return d.pw.Write(p) }

func (d *dropSink) Read(p []byte) (int, error) {
	<-d.done
	if d.err != nil {
		return 0, d.err
	}
	return 0, io.EOF
}

func (d *dropSink) Close() error {
	d.pw.Close()
	<-d.done
	return d.err
}

func (d *dropSink) finish(err error) {
	d.err = err
	select {
	case <-d.done:
	default:
		close(d.done)
	}
}

func shortKey(k string) string {
	if len(k) > 12 {
		return k[:12] + "…"
	}
	return k
}

// DropConfig configures a drop receiver: it joins the mesh, listens on a mesh
// port, admits only senders matching Allow, and writes received files to Dir.
type DropConfig struct {
	Mesh       MeshConfig `yaml:"mesh"`
	ListenPort int        `yaml:"listen_port"`
	Dir        string     `yaml:"dir"`       // destination directory for received files
	Allow      []string   `yaml:"allow"`     // sender ACL: FQDN globs or "pubkey:<key>"; empty = any mesh peer
	AuditLog   string     `yaml:"audit_log"` // JSONL hash-chained log; one record per received file
	MaxBytes   int64      `yaml:"max_bytes"` // per-file size cap (0 = unlimited)
	CAS        bool       `yaml:"cas"`       // store received files by content hash (dedup) and serve `fetch`
	FetchPort  int        `yaml:"fetch_port"` // if >0 and cas, serve fetch-by-hash on this mesh port
}

func loadDropConfig(path string) (*DropConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var cfg DropConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	if cfg.ListenPort <= 0 || cfg.ListenPort > 65535 {
		return nil, errors.New("listen_port must be 1-65535")
	}
	if cfg.Dir == "" {
		return nil, errors.New("dir is required (destination for received files)")
	}
	return &cfg, nil
}
