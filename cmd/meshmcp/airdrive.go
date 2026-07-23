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
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/xrey167/meshmcp/air"
	"github.com/xrey167/meshmcp/policy"
	"github.com/xrey167/meshmcp/session"
)

// Air · Drive — a governed shared drive over the mesh.
//
// A folder is exposed to named mesh identities: a read ACL may list/get, a
// write ACL may put/rm. Every accepted conn is resolved to its WireGuard
// identity before a byte is read; both ACLs are deny-by-default (empty = nobody,
// never any-mesh-peer), and the daemon refuses to start without at least one.
// Every op that reaches the daemon is audited into the hash-chained ledger, so
// drive activity shows up in `air stream` / `air bind` / the Receipts view for
// free. Path safety is two independent gates (air.CleanRelPath, then the
// existing sanitizeDest), put is bounded by a per-file cap, and the check→write
// commit for a path is serialized by a per-path keyed mutex.
//
//	SERVE:  meshmcp air drive serve --dir ~/Share --reader 'ana-*' --writer 'ana-phone.netbird.cloud' [--audit f] [--port 9160] [--max-bytes N] [--allow-ext .pdf,.png]
//	CLIENT: meshmcp air drive ls  <host:port> [path]
//	        meshmcp air drive get <host:port> <path> [--out f]
//	        meshmcp air drive put <host:port> <path> [localfile]   (stdin if no localfile)
//	        meshmcp air drive rm  <host:port> <path>
//
// Wire: one JSON request line, one JSON response line, then op-specific bytes,
// over a raw client.Dial conn (drive ops are short and idempotent-retryable, so
// — like fetch — they skip the resumable session layer). The put body is a
// SINGLE self-delimiting drop record (header declares the byte count, a one-line
// trailer carries the content hash): that framing is the explicit put
// terminator, so the daemon reads exactly one record with recvDriveRecord (NOT
// recvFiles-until-EOF) and can write the DriveResp on the same conn afterward.
// The client additionally half-closes its write side after the record as a
// defensive signal; correctness does not depend on it.
//
// DEFERRED (out of scope for v1, stated plainly): file versioning and restore,
// a whole-share quota with a cached usage counter, optimistic-concurrency
// (base-hash) conflict detection, and any `air serve --drive` browser surface.
// If a browser read surface is later added it MUST be deny-by-default (require
// --allow) to match this daemon — it must not inherit empty-allow=any.

const (
	defaultDrivePort     = 9160
	defaultDriveMaxBytes = 256 << 20 // 256 MiB per-file cap by default
)

// cmdAirDrive dispatches the drive sub-ops, mirroring cmdAirFilm's record|play.
func cmdAirDrive(args []string) error {
	if len(args) == 0 {
		return driveUsage()
	}
	switch args[0] {
	case "serve":
		return cmdAirDriveServe(args[1:])
	case "ls", "list":
		return cmdAirDriveLs(args[1:])
	case "get":
		return cmdAirDriveGet(args[1:])
	case "put":
		return cmdAirDrivePut(args[1:])
	case "rm":
		return cmdAirDriveRm(args[1:])
	case "-h", "--help", "help":
		return driveUsage()
	default:
		return fmt.Errorf("meshmcp air drive: unknown subcommand %q (want serve | ls | get | put | rm)", args[0])
	}
}

func driveUsage() error {
	fmt.Fprintln(os.Stderr, bold("meshmcp air drive")+dim(" — a governed shared drive over the mesh"))
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "  "+bold("air drive serve")+dim("  --dir <dir> --reader <id> --writer <id> [--audit f] [--port N] [--max-bytes N] [--allow-ext .pdf,.png]"))
	fmt.Fprintln(os.Stderr, "                   "+dim("expose a folder; read ACL may ls/get, write ACL may put/rm; deny-by-default, audited"))
	fmt.Fprintln(os.Stderr, "  "+bold("air drive ls")+dim("     <host:port> [path]        list a folder"))
	fmt.Fprintln(os.Stderr, "  "+bold("air drive get")+dim("    <host:port> <path> [--out f]  pull one file (hash-verified)"))
	fmt.Fprintln(os.Stderr, "  "+bold("air drive put")+dim("    <host:port> <path> [localfile]  push/overwrite one file (stdin if no file)"))
	fmt.Fprintln(os.Stderr, "  "+bold("air drive rm")+dim("     <host:port> <path>        delete one file"))
	return nil
}

// -------- server (daemon) --------

// driveServer holds a live drive's policy and state. The two ACLs are strict
// deny-by-default (an empty ACL admits nobody — see aclAllowsStrict), unlike a
// bare acl whose empty case means any-mesh-peer.
type driveServer struct {
	dir      string
	readACL  acl
	writeACL acl
	maxBytes int64
	allowExt map[string]bool // lowercased ".ext" set; empty = any extension
	audit    *policy.AuditLog
	locks    driveKeyedLocks
}

// aclAllowsStrict evaluates an ACL with empty-means-deny semantics, the
// deny-by-default rule a drive requires: an unconfigured (empty) tier admits
// nobody, and an unattributable peer is refused by acl.allows itself.
func aclAllowsStrict(a acl, pubKey, fqdn string) bool {
	if a.empty() {
		return false
	}
	return a.allows(pubKey, fqdn)
}

// canRead reports whether a peer may list/get: it is in the read ACL, or in the
// write ACL (write access implies read access).
func (s *driveServer) canRead(pubKey, fqdn string) bool {
	return aclAllowsStrict(s.readACL, pubKey, fqdn) || aclAllowsStrict(s.writeACL, pubKey, fqdn)
}

// canWrite reports whether a peer may put/rm: it is in the write ACL.
func (s *driveServer) canWrite(pubKey, fqdn string) bool {
	return aclAllowsStrict(s.writeACL, pubKey, fqdn)
}

// extAllowed reports whether rel's extension is permitted (empty allow-list =
// any extension).
func (s *driveServer) extAllowed(rel string) bool {
	if len(s.allowExt) == 0 {
		return true
	}
	return s.allowExt[strings.ToLower(path.Ext(rel))]
}

// driveOptions configures a drive daemon from the CLI flags.
type driveOptions struct {
	dir       string
	port      int
	readers   []string
	writers   []string
	auditPath string
	maxBytes  int64
	allowExt  []string
}

func cmdAirDriveServe(args []string) error {
	fs := flag.NewFlagSet("air drive serve", flag.ExitOnError)
	o := meshFlags(fs)
	dir := fs.String("dir", "", "folder to expose as the drive (REQUIRED)")
	port := fs.Int("port", defaultDrivePort, "mesh port to serve the drive on")
	readers := multiFlag{}
	writers := multiFlag{}
	fs.Var(&readers, "reader", "identity permitted to list/get (FQDN glob or pubkey:<key>); repeatable")
	fs.Var(&writers, "writer", "identity permitted to put/rm (FQDN glob or pubkey:<key>); repeatable")
	auditPath := fs.String("audit", "", "append every drive op (allow or deny) to this JSONL ledger")
	maxBytes := fs.Int64("max-bytes", defaultDriveMaxBytes, "per-file byte cap on put (0 = unlimited)")
	allowExt := fs.String("allow-ext", "", "comma-separated list of permitted put extensions, e.g. .pdf,.png (empty = any)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dir == "" {
		return errors.New("air drive serve: --dir <dir> is required")
	}
	return driveServe(o, driveOptions{
		dir: *dir, port: *port, readers: readers, writers: writers,
		auditPath: *auditPath, maxBytes: *maxBytes, allowExt: splitExt(*allowExt),
	})
}

// splitExt turns "--allow-ext .pdf,.PNG, .md" into a normalized lowercase set.
func splitExt(csv string) []string {
	var out []string
	for _, e := range strings.Split(csv, ",") {
		e = strings.ToLower(strings.TrimSpace(e))
		if e == "" {
			continue
		}
		if !strings.HasPrefix(e, ".") {
			e = "." + e
		}
		out = append(out, e)
	}
	return out
}

// driveServe runs the daemon: join the mesh, listen on a mesh port, gate each
// accepted conn by identity (deny-by-default), and serve drive ops on each.
func driveServe(o *meshOptions, d driveOptions) error {
	// Exposing a folder is privileged: refuse to serve to nobody. Deny-by-default
	// mirrors the drop receiver and `air listen`/`air serve --control` requiring
	// an allow list before they run.
	if len(d.readers) == 0 && len(d.writers) == 0 {
		return errors.New("air drive serve: at least one --reader or --writer is required (deny-by-default)")
	}
	if err := os.MkdirAll(d.dir, 0o755); err != nil {
		return fmt.Errorf("air drive serve: create dir %s: %w", d.dir, err)
	}

	o.BlockInbound = false // we listen for clients on the mesh
	client, err := startMesh(o, os.Stderr)
	if err != nil {
		return err
	}
	defer stopMesh(client)

	var audit *policy.AuditLog
	if d.auditPath != "" {
		f, err := os.OpenFile(d.auditPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return fmt.Errorf("air drive serve: open audit log: %w", err)
		}
		defer f.Close()
		audit = policy.NewAuditLog(f, func() string { return time.Now().UTC().Format(time.RFC3339) })
	}

	srv := &driveServer{
		dir:      d.dir,
		readACL:  newACL(d.readers),
		writeACL: newACL(d.writers),
		maxBytes: d.maxBytes,
		allowExt: extSet(d.allowExt),
		audit:    audit,
	}

	ln, err := client.ListenTCP(fmt.Sprintf(":%d", d.port))
	if err != nil {
		return fmt.Errorf("air drive serve: listen on mesh port %d: %w", d.port, err)
	}
	defer ln.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	go func() { <-ctx.Done(); ln.Close() }()

	if st, err := client.Status(); err == nil {
		log.Printf("drive up: %s (%s), dir %s, port %d · readers[%d] writers[%d]",
			strings.SplitN(st.LocalPeerState.IP, "/", 2)[0], st.LocalPeerState.FQDN,
			d.dir, d.port, len(d.readers), len(d.writers))
	}

	for {
		conn, err := ln.Accept()
		if err != nil {
			return nil // listener closed (Ctrl-C)
		}
		pubKey, fqdn := peerIdentity(client, conn.RemoteAddr())
		// Accept gate (BEFORE any request is read): a peer in neither ACL — and
		// an unattributable peer (canRead handles both) — is refused here. Such a
		// refusal is NOT audited and cannot be: no op or path has been read, so
		// there is nothing to attribute a record to. Only ops that pass this gate
		// reach serveConn, where every outcome IS audited.
		if !srv.canRead(pubKey, fqdn) {
			log.Printf("drive DENIED from %s (%s): not in any allow list", fqdn, shortKey(pubKey))
			conn.Close()
			continue
		}
		go func(c net.Conn) {
			meta := session.Meta{PeerFQDN: fqdn, PeerKey: pubKey, PeerAddr: c.RemoteAddr().String()}
			srv.serveConn(c, meta)
		}(conn)
	}
}

// serveConn handles one drive request on a raw conn: read the request line with
// a bufio.Reader, then dispatch. The SAME reader is threaded into the put path
// so the put body is read from exactly where the request line ended.
func (s *driveServer) serveConn(conn net.Conn, meta session.Meta) {
	defer conn.Close()
	br := bufio.NewReader(conn)
	req, err := air.ReadDriveReq(br)
	if err != nil {
		_ = air.WriteDriveResp(conn, air.DriveResp{Code: air.CodeBadReq, Error: "bad request"})
		return
	}
	switch req.Op {
	case air.OpList:
		s.doList(conn, req, meta)
	case air.OpGet:
		s.doGet(conn, req, meta)
	case air.OpPut:
		s.doPut(conn, br, req, meta)
	case air.OpRm:
		s.doRm(conn, req, meta)
	default:
		s.auditDrive(meta, string(req.Op), req.Path, "deny", "unknown op", 0)
		_ = air.WriteDriveResp(conn, air.DriveResp{Code: air.CodeBadReq, Error: "unknown op"})
	}
}

func (s *driveServer) doList(conn net.Conn, req air.DriveReq, meta session.Meta) {
	rel, err := air.CleanDirPath(req.Path)
	if err != nil {
		s.auditDrive(meta, "list", req.Path, "deny", "bad path: "+err.Error(), 0)
		_ = air.WriteDriveResp(conn, air.DriveResp{Code: air.CodeBadPath, Error: err.Error()})
		return
	}
	if !s.canRead(meta.PeerKey, meta.PeerFQDN) {
		s.auditDrive(meta, "list", rel, "deny", "not a reader", 0)
		_ = air.WriteDriveResp(conn, air.DriveResp{Code: air.CodeDenied, Error: "not permitted to list"})
		return
	}
	dir := s.dir
	if rel != "" {
		d, err := sanitizeDest(s.dir, filepath.FromSlash(rel))
		if err != nil {
			s.auditDrive(meta, "list", rel, "deny", "bad path: "+err.Error(), 0)
			_ = air.WriteDriveResp(conn, air.DriveResp{Code: air.CodeBadPath, Error: err.Error()})
			return
		}
		dir = d
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		s.auditDrive(meta, "list", rel, "deny", "not found", 0)
		_ = air.WriteDriveResp(conn, air.DriveResp{Code: air.CodeNotFound, Error: "no such folder"})
		return
	}
	out := make([]air.DriveEntry, 0, len(ents))
	for _, e := range ents {
		info, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, air.DriveEntry{
			Name:    e.Name(),
			Size:    info.Size(),
			Mode:    uint32(info.Mode().Perm()),
			ModTime: info.ModTime().UTC().Format(time.RFC3339),
			Dir:     e.IsDir(),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	s.auditDrive(meta, "list", rel, "allow", fmt.Sprintf("listed %d entries", len(out)), 0)
	_ = air.WriteDriveResp(conn, air.DriveResp{OK: true, Entries: out})
}

func (s *driveServer) doGet(conn net.Conn, req air.DriveReq, meta session.Meta) {
	rel, err := air.CleanRelPath(req.Path)
	if err != nil {
		s.auditDrive(meta, "get", req.Path, "deny", "bad path: "+err.Error(), 0)
		_ = air.WriteDriveResp(conn, air.DriveResp{Code: air.CodeBadPath, Error: err.Error()})
		return
	}
	if !s.canRead(meta.PeerKey, meta.PeerFQDN) {
		s.auditDrive(meta, "get", rel, "deny", "not a reader", 0)
		_ = air.WriteDriveResp(conn, air.DriveResp{Code: air.CodeDenied, Error: "not permitted to get"})
		return
	}
	dest, err := sanitizeDest(s.dir, filepath.FromSlash(rel))
	if err != nil {
		s.auditDrive(meta, "get", rel, "deny", "bad path: "+err.Error(), 0)
		_ = air.WriteDriveResp(conn, air.DriveResp{Code: air.CodeBadPath, Error: err.Error()})
		return
	}
	f, err := os.Open(dest)
	if err != nil {
		s.auditDrive(meta, "get", rel, "deny", "not found", 0)
		_ = air.WriteDriveResp(conn, air.DriveResp{Code: air.CodeNotFound, Error: "no such file"})
		return
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || fi.IsDir() {
		s.auditDrive(meta, "get", rel, "deny", "not a file", 0)
		_ = air.WriteDriveResp(conn, air.DriveResp{Code: air.CodeNotFound, Error: "not a file"})
		return
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		s.auditDrive(meta, "get", rel, "deny", "read error", 0)
		_ = air.WriteDriveResp(conn, air.DriveResp{Code: air.CodeInternal, Error: "read error"})
		return
	}
	sum := hex.EncodeToString(h.Sum(nil))
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		s.auditDrive(meta, "get", rel, "deny", "seek error", 0)
		_ = air.WriteDriveResp(conn, air.DriveResp{Code: air.CodeInternal, Error: "read error"})
		return
	}
	if err := air.WriteDriveResp(conn, air.DriveResp{OK: true, Size: fi.Size(), SHA256: sum}); err != nil {
		return
	}
	// Stream exactly the declared byte count; the client bounds and hash-verifies.
	_, _ = io.CopyN(conn, f, fi.Size())
	s.auditDrive(meta, "get", sum, "allow", fmt.Sprintf("sent %s (%d bytes)", rel, fi.Size()), int(fi.Size()))
}

func (s *driveServer) doPut(conn net.Conn, br *bufio.Reader, req air.DriveReq, meta session.Meta) {
	rel, err := air.CleanRelPath(req.Path)
	if err != nil {
		s.auditDrive(meta, "put", req.Path, "deny", "bad path: "+err.Error(), 0)
		drainPutBody(br) // the client streams the body regardless; drain so it can read our reply
		_ = air.WriteDriveResp(conn, air.DriveResp{Code: air.CodeBadPath, Error: err.Error()})
		return
	}
	// Authorization is known from the request line, before the body: a reader who
	// is not a writer is refused here and audited (identity, op, and path are all
	// known) — the honest post-read deny.
	if !s.canWrite(meta.PeerKey, meta.PeerFQDN) {
		s.auditDrive(meta, "put", rel, "deny", "not a writer", 0)
		drainPutBody(br)
		_ = air.WriteDriveResp(conn, air.DriveResp{Code: air.CodeDenied, Error: "not permitted to write"})
		return
	}
	if !s.extAllowed(rel) {
		s.auditDrive(meta, "put", rel, "deny", "extension not allowed", 0)
		drainPutBody(br)
		_ = air.WriteDriveResp(conn, air.DriveResp{Code: air.CodeBadType, Error: "file type not allowed"})
		return
	}

	rec, err := recvDriveRecord(br, s.maxBytes)
	if err != nil {
		code := air.CodeInternal
		reason := err.Error()
		if errors.Is(err, errDriveTooBig) {
			code, reason = air.CodeTooBig, "file exceeds the per-file size limit"
		}
		s.auditDrive(meta, "put", rel, "deny", reason, 0)
		_ = air.WriteDriveResp(conn, air.DriveResp{Code: code, Error: reason})
		return
	}
	defer os.Remove(rec.tmp) // no-op after a successful rename

	// Commit under a per-path keyed mutex: the check (is the target a directory?
	// re-validate against the real dir) and the write (atomic rename) must be one
	// critical section per path, so two writers to the SAME path cannot interleave
	// and clobber. Distinct paths take distinct keys and never contend.
	unlock := s.locks.lock(rel)
	defer unlock()

	dest, err := sanitizeDest(s.dir, filepath.FromSlash(rel))
	if err != nil {
		s.auditDrive(meta, "put", rel, "deny", "bad path: "+err.Error(), 0)
		_ = air.WriteDriveResp(conn, air.DriveResp{Code: air.CodeBadPath, Error: err.Error()})
		return
	}
	if fi, err := os.Stat(dest); err == nil && fi.IsDir() {
		s.auditDrive(meta, "put", rel, "deny", "target is a directory", 0)
		_ = air.WriteDriveResp(conn, air.DriveResp{Code: air.CodeBadPath, Error: "target is a directory"})
		return
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		s.auditDrive(meta, "put", rel, "deny", "mkdir error", 0)
		_ = air.WriteDriveResp(conn, air.DriveResp{Code: air.CodeInternal, Error: "server error"})
		return
	}
	if err := os.Rename(rec.tmp, dest); err != nil {
		// Cross-filesystem temp dir: fall back to a symlink-safe copy (os.Rename
		// and copyFile both replace a planted symlink atomically, never following
		// it — see drop.go).
		if cerr := copyFile(rec.tmp, dest, 0o644); cerr != nil {
			s.auditDrive(meta, "put", rel, "deny", "install error", 0)
			_ = air.WriteDriveResp(conn, air.DriveResp{Code: air.CodeInternal, Error: "server error"})
			return
		}
	}
	s.auditDrive(meta, "put", rec.sha, "allow", fmt.Sprintf("wrote %s (%d bytes)", rel, rec.size), int(rec.size))
	_ = air.WriteDriveResp(conn, air.DriveResp{OK: true, Size: rec.size, SHA256: rec.sha})
}

func (s *driveServer) doRm(conn net.Conn, req air.DriveReq, meta session.Meta) {
	rel, err := air.CleanRelPath(req.Path)
	if err != nil {
		s.auditDrive(meta, "rm", req.Path, "deny", "bad path: "+err.Error(), 0)
		_ = air.WriteDriveResp(conn, air.DriveResp{Code: air.CodeBadPath, Error: err.Error()})
		return
	}
	if !s.canWrite(meta.PeerKey, meta.PeerFQDN) {
		s.auditDrive(meta, "rm", rel, "deny", "not a writer", 0)
		_ = air.WriteDriveResp(conn, air.DriveResp{Code: air.CodeDenied, Error: "not permitted to delete"})
		return
	}
	unlock := s.locks.lock(rel)
	defer unlock()
	dest, err := sanitizeDest(s.dir, filepath.FromSlash(rel))
	if err != nil {
		s.auditDrive(meta, "rm", rel, "deny", "bad path: "+err.Error(), 0)
		_ = air.WriteDriveResp(conn, air.DriveResp{Code: air.CodeBadPath, Error: err.Error()})
		return
	}
	fi, err := os.Stat(dest)
	if err != nil {
		s.auditDrive(meta, "rm", rel, "deny", "not found", 0)
		_ = air.WriteDriveResp(conn, air.DriveResp{Code: air.CodeNotFound, Error: "no such file"})
		return
	}
	if fi.IsDir() {
		s.auditDrive(meta, "rm", rel, "deny", "is a directory", 0)
		_ = air.WriteDriveResp(conn, air.DriveResp{Code: air.CodeBadPath, Error: "is a directory"})
		return
	}
	if err := os.Remove(dest); err != nil {
		s.auditDrive(meta, "rm", rel, "deny", "remove error", 0)
		_ = air.WriteDriveResp(conn, air.DriveResp{Code: air.CodeInternal, Error: "server error"})
		return
	}
	s.auditDrive(meta, "rm", rel, "allow", "removed "+rel, 0)
	_ = air.WriteDriveResp(conn, air.DriveResp{OK: true})
}

// auditDrive appends one drive decision to the ledger, mirroring the drop
// receiver's record shape so drive ops appear in air stream/bind/Receipts. Tool
// is the content hash for get/put (like drop/recv) and the path for list/rm.
func (s *driveServer) auditDrive(meta session.Meta, op, tool, decision, reason string, cost int) {
	if s.audit == nil {
		return
	}
	s.audit.Append(policy.AuditRecord{
		Backend:  "drive",
		Peer:     meta.PeerFQDN,
		PeerKey:  meta.PeerKey,
		PeerAddr: meta.PeerAddr,
		Method:   "drive/" + op,
		Tool:     tool,
		Decision: decision,
		Reason:   reason,
		Rule:     -1,
		Cost:     cost,
	})
}

// -------- single-record put receive --------

var errDriveTooBig = errors.New("drive put over per-file cap")

// driveRecord is a verified put body staged in a temp file, awaiting commit.
type driveRecord struct {
	tmp  string
	sha  string
	size int64
}

// maxPutDrain bounds how many body bytes the daemon will read and discard on a
// rejected put (bad path / not a writer / over cap), so a rejected client still
// gets a clean DriveResp for a modest overshoot without letting a hostile client
// make the server drain unboundedly.
const maxPutDrain = 8 << 20

// recvDriveRecord reads exactly one drop record from br — the single, explicit
// put terminator — into a temp file, verifying its declared size and content
// hash. It reuses the drop framing (dropHeader/dropTrailer, readDropLine) but is
// a single-record receive, not recvFiles-until-EOF: it returns as soon as the
// trailer line is read, leaving the conn ready for the DriveResp. The file is
// NOT placed; the caller commits it under the per-path lock.
func recvDriveRecord(br *bufio.Reader, perFile int64) (driveRecord, error) {
	line, err := readDropLine(br)
	if err != nil {
		return driveRecord{}, fmt.Errorf("read put header: %w", err)
	}
	var hdr dropHeader
	if err := json.Unmarshal(line[:len(line)-1], &hdr); err != nil {
		return driveRecord{}, fmt.Errorf("bad put header: %w", err)
	}
	if hdr.Size < 0 {
		return driveRecord{}, fmt.Errorf("bad put size %d", hdr.Size)
	}
	if perFile > 0 && hdr.Size > perFile {
		// Drain the WHOLE pending record — body AND trailer — so no unread bytes
		// remain when the caller closes the conn after writing the toobig reply.
		// Leaving the trailer line unread makes the close an RST (Windows:
		// "connection forcibly closed") that races the client's response read;
		// draining it (bounded by maxPutDrain against a hostile huge declaration)
		// lets a modestly-oversized client read the toobig reply cleanly. Mirrors
		// drainPutBody.
		drainN(br, hdr.Size)
		_, _ = readDropLine(br) // trailer, best-effort
		return driveRecord{}, errDriveTooBig
	}

	tmp, err := os.CreateTemp("", ".airdrive-*")
	if err != nil {
		return driveRecord{}, err
	}
	tmpName := tmp.Name()

	h := sha256.New()
	if _, err := io.CopyN(io.MultiWriter(tmp, h), br, hdr.Size); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return driveRecord{}, fmt.Errorf("receive put body: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return driveRecord{}, err
	}

	tline, err := readDropLine(br)
	if err != nil && !errors.Is(err, io.EOF) {
		os.Remove(tmpName)
		return driveRecord{}, fmt.Errorf("read put trailer: %w", err)
	}
	var tr dropTrailer
	if err := json.Unmarshal([]byte(strings.TrimRight(string(tline), "\n")), &tr); err != nil {
		os.Remove(tmpName)
		return driveRecord{}, fmt.Errorf("bad put trailer: %w", err)
	}
	got := hex.EncodeToString(h.Sum(nil))
	if tr.SHA256 != got {
		os.Remove(tmpName)
		return driveRecord{}, fmt.Errorf("put hash mismatch: sent %s, received %s", tr.SHA256, got)
	}
	return driveRecord{tmp: tmpName, sha: got, size: hdr.Size}, nil
}

// drainPutBody consumes a pending put record (header + body + trailer) from br
// without storing it, so a client whose put was rejected before the body was
// read can still read the DriveResp. Bounded by maxPutDrain.
func drainPutBody(br *bufio.Reader) {
	line, err := readDropLine(br)
	if err != nil {
		return
	}
	var hdr dropHeader
	if json.Unmarshal(line[:len(line)-1], &hdr) != nil || hdr.Size < 0 {
		return
	}
	drainN(br, hdr.Size)
	_, _ = readDropLine(br) // trailer, best-effort
}

// drainN discards up to min(n, maxPutDrain) bytes from br.
func drainN(br *bufio.Reader, n int64) {
	if n > maxPutDrain {
		n = maxPutDrain
	}
	_, _ = io.CopyN(io.Discard, br, n)
}

// extSet builds the lowercased extension allow-set for a driveServer.
func extSet(exts []string) map[string]bool {
	if len(exts) == 0 {
		return nil
	}
	m := make(map[string]bool, len(exts))
	for _, e := range exts {
		m[strings.ToLower(e)] = true
	}
	return m
}

// -------- per-path keyed mutex --------

// driveKeyedLocks serializes the check→write commit for a given in-drive path.
// It reproduces federation/dcr.go's keyedLocks idea (that type is unexported):
// distinct paths never block each other, so concurrent puts to distinct files
// run in parallel while concurrent puts to the SAME file are serialized, closing
// the clobber window that per-conn goroutines would otherwise open. The key
// space is the set of live paths, so the map is not pruned.
type driveKeyedLocks struct {
	mu    sync.Mutex
	locks map[string]*sync.Mutex
}

func (k *driveKeyedLocks) lock(key string) func() {
	k.mu.Lock()
	if k.locks == nil {
		k.locks = map[string]*sync.Mutex{}
	}
	m := k.locks[key]
	if m == nil {
		m = &sync.Mutex{}
		k.locks[key] = m
	}
	k.mu.Unlock()
	m.Lock()
	return m.Unlock
}
