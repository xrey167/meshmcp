package air

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"
)

// Air · Drive — the portable wire + path logic for a governed shared drive over
// the mesh (see the main package's airdrive.go for the mesh/filesystem daemon
// and client). A drive is a folder exposed to named identities: a read ACL may
// list and get, a write ACL may put and rm, every touch is identity-gated and
// audited, deny-by-default.
//
// This file is deliberately I/O-free and mesh-independent: it defines the
// request/response envelopes, the one-request-line/one-response-line codecs,
// and CleanRelPath — the pure string pre-check that rejects a traversal, an
// absolute path, or a Windows drive/ADS path before the daemon ever touches
// the filesystem (the daemon re-validates against the real directory with the
// existing sanitizeDest). Keeping it here lets the wire and path rules be
// unit-tested without a mesh or a disk.

// DriveOp is one operation a drive client requests. v1 is the four verbs of an
// ordinary shared folder; versioning/restore are deliberately out of scope.
type DriveOp string

const (
	OpList DriveOp = "list" // list a folder (read ACL)
	OpGet  DriveOp = "get"  // pull one file, hash-verified (read ACL)
	OpPut  DriveOp = "put"  // create/overwrite one file (write ACL)
	OpRm   DriveOp = "rm"   // delete one file (write ACL)
)

// DriveReq is the single request line a drive client sends over a raw mesh
// conn, before any op-specific bytes (the put body, for put).
type DriveReq struct {
	Op   DriveOp `json:"op"`
	Path string  `json:"path"` // slash-relative path within the share ("" = root, for list)
}

// DriveResp is the response header line the daemon returns. Some ops stream
// bytes after it: get streams Size content bytes; every other op is a header
// only.
type DriveResp struct {
	OK      bool         `json:"ok"`
	Error   string       `json:"error,omitempty"` // human reason on !OK
	Code    string       `json:"code,omitempty"`  // machine reason on !OK (see the Code* constants)
	Entries []DriveEntry `json:"entries,omitempty"`
	Size    int64        `json:"size,omitempty"`   // get: this many body bytes follow the line
	SHA256  string       `json:"sha256,omitempty"` // get: content hash; put: hash the daemon stored
}

// DriveEntry is one row in a listing.
type DriveEntry struct {
	Name    string `json:"name"`
	Size    int64  `json:"size"`
	Mode    uint32 `json:"mode"`
	ModTime string `json:"mtime"` // RFC3339 UTC
	Dir     bool   `json:"dir,omitempty"`
}

// Machine-readable DriveResp.Code values, so a client can react to a failure
// without parsing prose.
const (
	CodeDenied   = "denied"   // authorization refused (post-read, audited)
	CodeBadPath  = "badpath"  // path rejected by CleanRelPath / sanitizeDest
	CodeBadReq   = "badreq"   // unparseable or unknown request
	CodeNotFound = "notfound" // no such file/folder
	CodeTooBig   = "toobig"   // put body over the per-file cap
	CodeBadType  = "badtype"  // put extension not on the allow-list
	CodeInternal = "internal" // server-side failure
)

// CleanRelPath validates and canonicalizes a slash-relative in-drive file path.
// It rejects an empty path, a NUL or control character, a ':' (Windows drive
// letter / NTFS alternate data stream), a backslash (a Windows separator that
// slash-cleaning would not normalize), an absolute path, and any path that
// escapes the drive root via "..". It returns the path.Clean'd slash path.
//
// This is a pure string pre-check; the daemon still resolves the result against
// the real directory with sanitizeDest, so a symlink-planted escape is caught
// by the second, filesystem-aware check. Two independent gates, deny-by-default.
func CleanRelPath(p string) (string, error) {
	if p == "" {
		return "", errors.New("empty path")
	}
	for _, r := range p {
		if r == 0 || r < 0x20 || r == 0x7f {
			return "", errors.New("path contains a control character")
		}
	}
	if strings.ContainsRune(p, ':') {
		return "", errors.New("path contains ':' (drive letter or alternate data stream)")
	}
	if strings.ContainsRune(p, '\\') {
		return "", errors.New("path contains a backslash")
	}
	if strings.HasPrefix(p, "/") {
		return "", errors.New("path is absolute")
	}
	clean := path.Clean(p)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") || strings.HasPrefix(clean, "/") {
		return "", errors.New("path escapes the drive root")
	}
	for _, seg := range strings.Split(clean, "/") {
		if seg == ".." {
			return "", errors.New("path escapes the drive root")
		}
	}
	return clean, nil
}

// CleanDirPath is CleanRelPath for a listing target, where the drive root is a
// valid folder: "", ".", and "/" all clean to "" (root); anything else must be
// a contained relative path.
func CleanDirPath(p string) (string, error) {
	if p == "" || p == "." || p == "/" {
		return "", nil
	}
	return CleanRelPath(p)
}

// maxDriveLine bounds one request/response header line so a peer cannot force
// an unbounded line buffer by never sending a newline. Reuses the same order of
// magnitude as maxEnvelopeLine (a header line is small JSON).
const maxDriveLine = maxEnvelopeLine

// WriteDriveReq frames one request as a newline-delimited JSON line.
func WriteDriveReq(w io.Writer, r DriveReq) error {
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	_, err = w.Write(append(b, '\n'))
	return err
}

// ReadDriveReq reads one request line, bounded by maxDriveLine.
func ReadDriveReq(br *bufio.Reader) (DriveReq, error) {
	line, err := readDriveLine(br)
	if err != nil {
		return DriveReq{}, err
	}
	var r DriveReq
	if err := json.Unmarshal(line, &r); err != nil {
		return DriveReq{}, fmt.Errorf("bad drive request: %w", err)
	}
	return r, nil
}

// WriteDriveResp frames one response as a newline-delimited JSON line.
func WriteDriveResp(w io.Writer, r DriveResp) error {
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	_, err = w.Write(append(b, '\n'))
	return err
}

// ReadDriveResp reads one response line, bounded by maxDriveLine. The caller
// keeps reading op-specific bytes (a get body) from the same *bufio.Reader.
func ReadDriveResp(br *bufio.Reader) (DriveResp, error) {
	line, err := readDriveLine(br)
	if err != nil {
		return DriveResp{}, err
	}
	var r DriveResp
	if err := json.Unmarshal(line, &r); err != nil {
		return DriveResp{}, fmt.Errorf("bad drive response: %w", err)
	}
	return r, nil
}

// readDriveLine reads one newline-terminated line (without the newline),
// bounded by maxDriveLine so a missing newline cannot exhaust memory.
func readDriveLine(br *bufio.Reader) ([]byte, error) {
	var buf []byte
	for {
		b, err := br.ReadByte()
		if err != nil {
			return buf, err
		}
		if b == '\n' {
			return buf, nil
		}
		buf = append(buf, b)
		if len(buf) > maxDriveLine {
			return buf, fmt.Errorf("drive line exceeds %d bytes", maxDriveLine)
		}
	}
}
