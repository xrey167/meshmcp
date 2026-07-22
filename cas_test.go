package main

import (
	"bytes"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
)

// TestCASPlacerDedup verifies content-addressed placement stores identical
// bytes at the same path (dedup) regardless of the sender's file name.
func TestCASPlacerDedup(t *testing.T) {
	dir := t.TempDir()
	place := casPlacer(dir)
	data := []byte("content addressed")
	hash := sha(data)

	p1, err := place(dropHeader{Name: "a.txt"}, hash)
	if err != nil {
		t.Fatal(err)
	}
	p2, err := place(dropHeader{Name: "totally-different-name.bin"}, hash)
	if err != nil {
		t.Fatal(err)
	}
	if p1 != p2 {
		t.Fatalf("same content placed at different paths: %s vs %s", p1, p2)
	}
	if filepath.Base(p1) != hash {
		t.Errorf("blob not named by hash: %s", p1)
	}
	if !bytes.Contains([]byte(p1), []byte(hash[:2])) {
		t.Errorf("blob not sharded by hash prefix: %s", p1)
	}
}

// TestFetchRoundTrip stores a blob in a CAS and fetches it by hash over a
// loopback listener, verifying integrity and a miss for an unknown hash.
func TestFetchRoundTrip(t *testing.T) {
	storeDir := t.TempDir()
	store := casStore{dir: storeDir}
	data := bytes.Repeat([]byte("artifact"), 1000) // 8000 bytes
	hash := sha(data)

	// Place the blob as a CAS receiver would.
	p, err := casPlacer(storeDir)(dropHeader{Name: "x"}, hash)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if !store.has(hash) {
		t.Fatal("store should have the blob")
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serveFetch(conn, store)
		}
	}()

	// Successful fetch.
	out := filepath.Join(t.TempDir(), "fetched.bin")
	if err := clientFetch(t, ln.Addr().String(), hash, out); err != nil {
		t.Fatalf("fetch: %v", err)
	}
	gotBytes, _ := os.ReadFile(out)
	if !bytes.Equal(gotBytes, data) {
		t.Fatalf("fetched content mismatch (%d vs %d)", len(gotBytes), len(data))
	}

	// Missing blob -> error.
	missing := sha([]byte("nope"))
	if err := clientFetch(t, ln.Addr().String(), missing, filepath.Join(t.TempDir(), "x")); err == nil {
		t.Fatal("expected error fetching a missing blob")
	}
}

// clientFetch dials the fetch server directly (bypassing the mesh) and runs
// the fetch protocol.
func clientFetch(t *testing.T, addr, hash, dest string) error {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := json.NewEncoder(conn).Encode(fetchReq{Hash: hash}); err != nil {
		return err
	}
	_, err = fetchBlob(conn, hash, dest, defaultFetchMaxBytes)
	return err
}

// TestFetchBlobRejectsOversizedDeclaredSize proves the fetcher refuses a
// peer-declared blob size larger than the cap before streaming any bytes, so a
// malicious holder cannot fill the requester's disk ahead of the hash check.
func TestFetchBlobRejectsOversizedDeclaredSize(t *testing.T) {
	// A response claiming a huge size, followed by no payload.
	resp, _ := json.Marshal(fetchResp{Found: true, Size: 1 << 40}) // 1 TiB
	r := bytes.NewReader(append(resp, '\n'))
	dest := filepath.Join(t.TempDir(), "out.bin")
	_, err := fetchBlob(r, "deadbeef", dest, 256<<20)
	if err == nil {
		t.Fatal("fetchBlob must reject an over-cap declared size")
	}
	if _, statErr := os.Stat(dest); statErr == nil {
		t.Fatal("no destination file should be written when the size is rejected")
	}
	// A negative size is also rejected.
	respNeg, _ := json.Marshal(fetchResp{Found: true, Size: -1})
	if _, err := fetchBlob(bytes.NewReader(append(respNeg, '\n')), "deadbeef", dest, 256<<20); err == nil {
		t.Fatal("fetchBlob must reject a negative declared size")
	}
}
