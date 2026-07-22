package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScreenSubdir(t *testing.T) {
	cases := map[string]string{
		"laptop.mesh": "laptop.mesh",
		"":            "peer",
		"a/b":         "a_b",
		"host:9121":   "host_9121",
		"..":          "_",
		"a\\b":        "a_b",
	}
	for in, want := range cases {
		if got := screenSubdir(in); got != want {
			t.Errorf("screenSubdir(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestScreenPlacerRollsOneFrame(t *testing.T) {
	dir := t.TempDir()
	place := screenPlacer(dir, "laptop.mesh")

	// First frame.
	p1, err := place(dropHeader{Name: "frame-000000.png"}, "hash1")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(filepath.ToSlash(p1), "laptop.mesh/current.png") {
		t.Fatalf("frame path = %q, want …/laptop.mesh/current.png", p1)
	}
	// A later frame rolls to the SAME file (bounded to one live frame per sender).
	p2, err := place(dropHeader{Name: "frame-000009.png"}, "hash2")
	if err != nil {
		t.Fatal(err)
	}
	if p1 != p2 {
		t.Fatalf("frames should roll to one file: %q vs %q", p1, p2)
	}
	// A non-image frame is refused.
	if _, err := place(dropHeader{Name: "evil.txt"}, "h"); err == nil {
		t.Fatal("non-image frame should be refused")
	}
}

// TestScreenReceiveWritesRollingFrame drives recvFiles with the screen placer
// (the receiver's core) and asserts the rolling frame lands and overwrites.
func TestScreenReceiveWritesRollingFrame(t *testing.T) {
	dir := t.TempDir()
	place := screenPlacer(dir, "laptop.mesh")

	// Stream two frames through the real drop wire (sendData -> recvFiles).
	pr, pw := io.Pipe()
	go func() {
		_ = sendData(pw, "frame-000000.png", []byte("\x89PNG-frame-A"))
		_ = sendData(pw, "frame-000001.png", []byte("\x89PNG-frame-B-longer"))
		pw.Close()
	}()
	var count int
	if err := recvFiles(pr, place, dropLimits{PerFile: maxAirImage, MaxFiles: 100, MaxTotal: 1 << 30}, func(recvInfo) { count++ }); err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("received %d frames, want 2", count)
	}
	// Exactly one rolling file, holding the LATEST frame.
	got, err := os.ReadFile(filepath.Join(dir, "laptop.mesh", "current.png"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "\x89PNG-frame-B-longer" {
		t.Fatalf("rolling frame = %q, want the latest frame", got)
	}
}
