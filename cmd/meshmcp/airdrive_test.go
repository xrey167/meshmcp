package main

import (
	"bufio"
	"bytes"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/xrey167/meshmcp/air"
	"github.com/xrey167/meshmcp/policy"
	"github.com/xrey167/meshmcp/session"
)

// Identities used throughout the drive tests.
const (
	readerFQDN   = "ana-laptop.netbird.cloud"
	readerKey    = "READERKEY0001"
	writerFQDN   = "ana-phone.netbird.cloud"
	writerKey    = "WRITERKEY0001"
	strangerFQDN = "eve.netbird.cloud"
	strangerKey  = "STRANGERKEY01"
)

// newDriveTestServer builds a driveServer over a temp dir with the reader/writer
// identities above and an optional audit sink.
func newDriveTestServer(t *testing.T, audit *policy.AuditLog) (*driveServer, string) {
	t.Helper()
	dir := t.TempDir()
	return &driveServer{
		dir:      dir,
		readACL:  newACL([]string{readerFQDN}),
		writeACL: newACL([]string{writerFQDN}),
		maxBytes: 1 << 20,
		audit:    audit,
	}, dir
}

// startDriveListener serves s over a real loopback TCP listener, presenting the
// given identity for every accepted conn (this stands in for the mesh
// peerIdentity gate, which the accept loop performs in production). Real TCP —
// not net.Pipe — is used deliberately: the put path relies on TCP's independent
// half-duplex closes and socket buffering, which the real mesh conn (a gonet
// TCP conn) provides and net.Pipe does not model.
func startDriveListener(t *testing.T, s *driveServer, pubKey, fqdn string) func() net.Conn {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serveConn(conn, session.Meta{PeerKey: pubKey, PeerFQDN: fqdn, PeerAddr: conn.RemoteAddr().String()})
		}
	}()
	return func() net.Conn {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		return c
	}
}

func TestDriveRoundTrip_PutListGetRm(t *testing.T) {
	s, _ := newDriveTestServer(t, nil)
	dialWriter := startDriveListener(t, s, writerKey, writerFQDN)

	payload := bytes.Repeat([]byte("mesh-drive-"), 200)

	// put
	c := dialWriter()
	resp, err := driveClientPut(c, "reports/q3.pdf", "q3.pdf", payload)
	c.Close()
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	if !resp.OK {
		t.Fatalf("put not OK: %+v", resp)
	}
	if resp.SHA256 != sha(payload) {
		t.Fatalf("put sha %s, want %s", resp.SHA256, sha(payload))
	}

	// list root and the subfolder
	c = dialWriter()
	ents, err := driveClientList(c, "")
	c.Close()
	if err != nil {
		t.Fatalf("list root: %v", err)
	}
	if len(ents) != 1 || ents[0].Name != "reports" || !ents[0].Dir {
		t.Fatalf("list root = %+v, want one dir 'reports'", ents)
	}
	c = dialWriter()
	ents, err = driveClientList(c, "reports")
	c.Close()
	if err != nil {
		t.Fatalf("list reports: %v", err)
	}
	if len(ents) != 1 || ents[0].Name != "q3.pdf" || ents[0].Size != int64(len(payload)) {
		t.Fatalf("list reports = %+v", ents)
	}

	// get
	c = dialWriter()
	got, sum, err := driveClientGet(c, "reports/q3.pdf", 0)
	c.Close()
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("get content mismatch (%d vs %d bytes)", len(got), len(payload))
	}
	if sum != sha(payload) {
		t.Fatalf("get sha %s, want %s", sum, sha(payload))
	}

	// rm
	c = dialWriter()
	rmResp, err := driveClientRm(c, "reports/q3.pdf")
	c.Close()
	if err != nil || !rmResp.OK {
		t.Fatalf("rm: err=%v resp=%+v", err, rmResp)
	}
	if _, err := os.Stat(filepath.Join(s.dir, "reports", "q3.pdf")); !os.IsNotExist(err) {
		t.Fatalf("file should be gone after rm")
	}
}

func TestDrive_ReaderCannotWrite_WriterCan(t *testing.T) {
	s, dir := newDriveTestServer(t, nil)
	writeTemp(t, dir, "seed.txt", []byte("seed"))

	dialReader := startDriveListener(t, s, readerKey, readerFQDN)

	// A reader can list and get.
	c := dialReader()
	if _, err := driveClientList(c, ""); err != nil {
		t.Fatalf("reader list: %v", err)
	}
	c.Close()
	c = dialReader()
	if _, _, err := driveClientGet(c, "seed.txt", 0); err != nil {
		t.Fatalf("reader get: %v", err)
	}
	c.Close()

	// A reader cannot put.
	c = dialReader()
	resp, err := driveClientPut(c, "hack.txt", "hack.txt", []byte("nope"))
	c.Close()
	if err != nil {
		t.Fatalf("reader put transport: %v", err)
	}
	if resp.OK || resp.Code != air.CodeDenied {
		t.Fatalf("reader put should be denied, got %+v", resp)
	}
	if _, err := os.Stat(filepath.Join(dir, "hack.txt")); !os.IsNotExist(err) {
		t.Fatalf("denied put must not write a file")
	}

	// A reader cannot rm.
	c = dialReader()
	rmResp, err := driveClientRm(c, "seed.txt")
	c.Close()
	if err != nil {
		t.Fatalf("reader rm transport: %v", err)
	}
	if rmResp.OK || rmResp.Code != air.CodeDenied {
		t.Fatalf("reader rm should be denied, got %+v", rmResp)
	}

	// A writer can put and rm.
	dialWriter := startDriveListener(t, s, writerKey, writerFQDN)
	c = dialWriter()
	resp, err = driveClientPut(c, "ok.txt", "ok.txt", []byte("hello"))
	c.Close()
	if err != nil || !resp.OK {
		t.Fatalf("writer put: err=%v resp=%+v", err, resp)
	}
	c = dialWriter()
	rmResp, err = driveClientRm(c, "ok.txt")
	c.Close()
	if err != nil || !rmResp.OK {
		t.Fatalf("writer rm: err=%v resp=%+v", err, rmResp)
	}
}

func TestServeDriveConn_DeniesUnlistedIdentity(t *testing.T) {
	// A stranger is in neither ACL. The production accept gate would refuse them
	// before serveConn is ever called (see TestDrive_AcceptGateNotAudited); if
	// one somehow reaches serveConn, defense-in-depth denies every op.
	s, _ := newDriveTestServer(t, nil)
	dialStranger := startDriveListener(t, s, strangerKey, strangerFQDN)

	c := dialStranger()
	_, err := driveClientList(c, "")
	c.Close()
	if err == nil {
		t.Fatalf("stranger list should be denied")
	}

	// An unattributable peer (no key, no FQDN) is denied by canRead itself.
	if s.canRead("", "") {
		t.Fatalf("unattributable peer must not pass canRead")
	}
	// Both empty ACLs => nobody, even for an otherwise-valid identity.
	empty := &driveServer{dir: t.TempDir(), readACL: newACL(nil), writeACL: newACL(nil)}
	if empty.canRead(writerKey, writerFQDN) {
		t.Fatalf("empty ACLs must deny everyone (deny-by-default)")
	}
}

func TestDrivePut_HashVerifiedAndSizeCapped(t *testing.T) {
	s, dir := newDriveTestServer(t, nil)
	s.maxBytes = 16 // tiny cap
	dialWriter := startDriveListener(t, s, writerKey, writerFQDN)

	// A small file lands.
	small := []byte("under-cap")[:9]
	if len(small) > int(s.maxBytes) {
		t.Fatalf("test setup: small must fit under cap")
	}
	c := dialWriter()
	resp, err := driveClientPut(c, "small.txt", "small.txt", small)
	c.Close()
	if err != nil || !resp.OK {
		t.Fatalf("small put: err=%v resp=%+v", err, resp)
	}

	// An oversized file is rejected with code toobig and not written.
	big := bytes.Repeat([]byte{7}, 100)
	c = dialWriter()
	resp, err = driveClientPut(c, "big.dat", "big.dat", big)
	c.Close()
	if err != nil {
		t.Fatalf("big put transport: %v", err)
	}
	if resp.OK || resp.Code != air.CodeTooBig {
		t.Fatalf("oversized put should be toobig, got %+v", resp)
	}
	if _, err := os.Stat(filepath.Join(dir, "big.dat")); !os.IsNotExist(err) {
		t.Fatalf("oversized put must not write a file")
	}
}

// TestDrivePut_CorruptTrailerRejected hand-crafts a put whose trailer hash does
// not match the body, exercising recvDriveRecord's hash check.
func TestDrivePut_CorruptTrailerRejected(t *testing.T) {
	s, dir := newDriveTestServer(t, nil)
	dialWriter := startDriveListener(t, s, writerKey, writerFQDN)

	c := dialWriter()
	// request line
	if err := air.WriteDriveReq(c, air.DriveReq{Op: air.OpPut, Path: "x.txt"}); err != nil {
		t.Fatal(err)
	}
	// a record with a wrong trailer hash
	c.Write([]byte(`{"name":"x.txt","size":3,"mode":420}` + "\n"))
	c.Write([]byte("abc"))
	c.Write([]byte(`{"sha256":"deadbeef"}` + "\n"))
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		cw.CloseWrite()
	}
	resp, err := air.ReadDriveResp(bufio.NewReader(c))
	c.Close()
	if err != nil {
		t.Fatalf("read resp: %v", err)
	}
	if resp.OK {
		t.Fatalf("corrupt put should be rejected, got %+v", resp)
	}
	if _, err := os.Stat(filepath.Join(dir, "x.txt")); !os.IsNotExist(err) {
		t.Fatalf("corrupt put must not write a file")
	}
}

func TestDrive_PathSafety(t *testing.T) {
	s, dir := newDriveTestServer(t, nil)
	// Plant a file OUTSIDE the drive to prove traversal cannot read it.
	outside := filepath.Join(filepath.Dir(dir), "secret.txt")
	if err := os.WriteFile(outside, []byte("top secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(outside) })

	dialWriter := startDriveListener(t, s, writerKey, writerFQDN)
	for _, bad := range []string{"../secret.txt", "../../etc/passwd", "/etc/passwd", "a/../../b", "a:b"} {
		// get is refused
		c := dialWriter()
		if _, _, err := driveClientGet(c, bad, 0); err == nil {
			t.Errorf("get(%q) should be refused", bad)
		}
		c.Close()
		// put is refused and writes nothing outside
		c = dialWriter()
		resp, err := driveClientPut(c, bad, "x", []byte("escape"))
		c.Close()
		if err == nil && resp.OK {
			t.Errorf("put(%q) should be refused, got %+v", bad, resp)
		}
	}
	if b, _ := os.ReadFile(outside); string(b) != "top secret" {
		t.Fatalf("a traversal put overwrote the outside file")
	}
}

// TestDrivePut_ConcurrentSamePath verifies the keyed mutex + atomic rename leave
// the file as exactly one writer's complete content (never a torn mix), and
// concurrent puts to DISTINCT paths both land.
func TestDrivePut_ConcurrentSamePath(t *testing.T) {
	s, dir := newDriveTestServer(t, nil)
	s.maxBytes = 1 << 20
	dialWriter := startDriveListener(t, s, writerKey, writerFQDN)

	a := bytes.Repeat([]byte("A"), 4096)
	b := bytes.Repeat([]byte("B"), 4096)

	var wg sync.WaitGroup
	for _, payload := range [][]byte{a, b} {
		wg.Add(1)
		go func(p []byte) {
			defer wg.Done()
			c := dialWriter()
			defer c.Close()
			if _, err := driveClientPut(c, "same.dat", "same.dat", p); err != nil {
				t.Errorf("concurrent same-path put: %v", err)
			}
		}(payload)
	}
	wg.Wait()

	final, err := os.ReadFile(filepath.Join(dir, "same.dat"))
	if err != nil {
		t.Fatalf("read final: %v", err)
	}
	if !bytes.Equal(final, a) && !bytes.Equal(final, b) {
		t.Fatalf("same-path file is torn/clobbered: %d bytes, first=%q", len(final), string(final[:1]))
	}

	// Distinct paths both succeed.
	var wg2 sync.WaitGroup
	for _, name := range []string{"one.txt", "two.txt", "three.txt"} {
		wg2.Add(1)
		go func(n string) {
			defer wg2.Done()
			c := dialWriter()
			defer c.Close()
			resp, err := driveClientPut(c, n, n, []byte(n))
			if err != nil || !resp.OK {
				t.Errorf("distinct-path put %s: err=%v resp=%+v", n, err, resp)
			}
		}(name)
	}
	wg2.Wait()
	for _, name := range []string{"one.txt", "two.txt", "three.txt"} {
		if b, err := os.ReadFile(filepath.Join(dir, name)); err != nil || string(b) != name {
			t.Errorf("distinct-path file %s = %q, err=%v", name, string(b), err)
		}
	}
}

func TestDrive_AuditRecordsEveryOpAndVerifies(t *testing.T) {
	auditBuf := &syncBuffer{}
	audit := policy.NewAuditLog(auditBuf, func() string { return "t" })
	s, _ := newDriveTestServer(t, audit)
	dialWriter := startDriveListener(t, s, writerKey, writerFQDN)
	dialReader := startDriveListener(t, s, readerKey, readerFQDN)

	// A full lifecycle plus one denied op (reader tries to put).
	c := dialWriter()
	driveClientPut(c, "a.txt", "a.txt", []byte("hello"))
	c.Close()
	c = dialWriter()
	driveClientList(c, "")
	c.Close()
	c = dialWriter()
	driveClientGet(c, "a.txt", 0)
	c.Close()
	c = dialReader()
	driveClientPut(c, "a.txt", "a.txt", []byte("overwrite")) // denied: reader
	c.Close()
	c = dialWriter()
	driveClientRm(c, "a.txt")
	c.Close()

	log := auditBuf.String()
	for _, want := range []string{
		`"method":"drive/put"`,
		`"method":"drive/list"`,
		`"method":"drive/get"`,
		`"method":"drive/rm"`,
		`"decision":"deny"`,
		`"decision":"allow"`,
		`"backend":"drive"`,
		`"reason":"not a writer"`,
	} {
		if !strings.Contains(log, want) {
			t.Errorf("audit log missing %s\n---\n%s", want, log)
		}
	}
	// The hash chain must verify end to end.
	res, err := policy.VerifyChain(strings.NewReader(log))
	if err != nil {
		t.Fatalf("VerifyChain error: %v", err)
	}
	if !res.OK {
		t.Fatalf("audit chain broken at seq %d: %s", res.BreakSeq, res.Reason)
	}
}

// TestDrive_AcceptGateNotAudited asserts the honest-audit boundary: a peer in
// neither ACL is refused at the accept gate BEFORE any request is read, so
// there is no op/path to attribute and NOTHING is audited. Only ops that pass
// the gate reach serveConn, where every outcome is audited (see the audit test).
func TestDrive_AcceptGateNotAudited(t *testing.T) {
	auditBuf := &syncBuffer{}
	audit := policy.NewAuditLog(auditBuf, func() string { return "t" })
	s, _ := newDriveTestServer(t, audit)

	// Mimic the daemon accept-loop decision for a stranger.
	if s.canRead(strangerKey, strangerFQDN) {
		t.Fatalf("stranger must not pass the accept gate")
	}
	// Because the gate refuses before serveConn, no record is written.
	if auditBuf.Len() != 0 {
		t.Fatalf("accept-gate refusal must not be audited, got: %s", auditBuf.String())
	}
}

func TestDriveServe_RequiresAnACL(t *testing.T) {
	err := driveServe(&meshOptions{}, driveOptions{dir: t.TempDir()})
	if err == nil || !strings.Contains(err.Error(), "reader") {
		t.Fatalf("driveServe with no ACL should error, got %v", err)
	}
}
