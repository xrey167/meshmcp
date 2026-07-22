package air

import (
	"bufio"
	"bytes"
	"strings"
	"testing"
)

func TestCleanRelPath_RejectsTraversalAbsoluteAndReserved(t *testing.T) {
	bad := []string{
		"",              // empty
		"../x",          // traversal
		"../../etc/pwd", // traversal
		"a/../../b",     // traversal after a segment
		"/etc/passwd",   // absolute
		"a:b",           // Windows drive / ADS
		"a\\b",          // backslash separator
		"x\x00y",        // NUL
		"x\ty",          // control character
		".",             // the root is not a file
		"..",            // parent
	}
	for _, p := range bad {
		if got, err := CleanRelPath(p); err == nil {
			t.Errorf("CleanRelPath(%q) = %q, want error", p, got)
		}
	}

	good := map[string]string{
		"reports/q3.pdf": "reports/q3.pdf",
		"a/./b.txt":      "a/b.txt",
		"notes.md":       "notes.md",
		"a//b":           "a/b",
	}
	for in, want := range good {
		got, err := CleanRelPath(in)
		if err != nil {
			t.Errorf("CleanRelPath(%q) unexpected error: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("CleanRelPath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCleanDirPath_RootIsValid(t *testing.T) {
	for _, root := range []string{"", ".", "/"} {
		got, err := CleanDirPath(root)
		if err != nil || got != "" {
			t.Errorf("CleanDirPath(%q) = (%q, %v), want (\"\", nil)", root, got, err)
		}
	}
	if got, err := CleanDirPath("../escape"); err == nil {
		t.Errorf("CleanDirPath(../escape) = %q, want error", got)
	}
	if got, err := CleanDirPath("sub/dir"); err != nil || got != "sub/dir" {
		t.Errorf("CleanDirPath(sub/dir) = (%q, %v), want (sub/dir, nil)", got, err)
	}
}

func TestDriveReqRespRoundTrip(t *testing.T) {
	reqs := []DriveReq{
		{Op: OpList, Path: ""},
		{Op: OpGet, Path: "reports/q3.pdf"},
		{Op: OpPut, Path: "a/b.txt"},
		{Op: OpRm, Path: "old.log"},
	}
	for _, in := range reqs {
		var buf bytes.Buffer
		if err := WriteDriveReq(&buf, in); err != nil {
			t.Fatalf("WriteDriveReq: %v", err)
		}
		got, err := ReadDriveReq(bufio.NewReader(&buf))
		if err != nil {
			t.Fatalf("ReadDriveReq: %v", err)
		}
		if got != in {
			t.Errorf("req round-trip: got %+v, want %+v", got, in)
		}
	}

	resp := DriveResp{
		OK:     true,
		Size:   1234,
		SHA256: "9f2a1c",
		Entries: []DriveEntry{
			{Name: "q3.pdf", Size: 2100, Mode: 0o644, ModTime: "2026-07-22T14:03:01Z"},
			{Name: "sub", Dir: true, ModTime: "2026-07-22T14:03:01Z"},
		},
	}
	var buf bytes.Buffer
	if err := WriteDriveResp(&buf, resp); err != nil {
		t.Fatalf("WriteDriveResp: %v", err)
	}
	got, err := ReadDriveResp(bufio.NewReader(&buf))
	if err != nil {
		t.Fatalf("ReadDriveResp: %v", err)
	}
	if !got.OK || got.Size != 1234 || got.SHA256 != "9f2a1c" || len(got.Entries) != 2 || got.Entries[1].Name != "sub" || !got.Entries[1].Dir {
		t.Errorf("resp round-trip mismatch: %+v", got)
	}
}

func TestReadDriveReq_RejectsGarbageAndOversize(t *testing.T) {
	if _, err := ReadDriveReq(bufio.NewReader(strings.NewReader("not json\n"))); err == nil {
		t.Error("ReadDriveReq accepted non-JSON")
	}
	// A line with no newline that exceeds the bound must error, not buffer forever.
	huge := strings.Repeat("A", maxDriveLine+16)
	if _, err := ReadDriveReq(bufio.NewReader(strings.NewReader(huge))); err == nil {
		t.Error("ReadDriveReq accepted an unbounded line")
	}
}
