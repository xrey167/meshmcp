package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeImage drops a fake image file into dir with the given mtime offset.
func writeImage(t *testing.T, dir, name string, ageSec int) {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("\x89PNG\r\n\x1a\n"+name), 0o644); err != nil {
		t.Fatal(err)
	}
	mt := time.Now().Add(-time.Duration(ageSec) * time.Second)
	if err := os.Chtimes(p, mt, mt); err != nil {
		t.Fatal(err)
	}
}

func TestListGalleryImagesFiltersAndOrders(t *testing.T) {
	dir := t.TempDir()
	writeImage(t, dir, "old.png", 300)
	writeImage(t, dir, "new.jpg", 10)
	writeImage(t, dir, filepath.Join("photos", "nested.webp"), 100)
	// Non-images must be ignored.
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("hi"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "secret.pem"), []byte("key"), 0o644); err != nil {
		t.Fatal(err)
	}

	imgs, err := listGalleryImages(dir, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(imgs) != 3 {
		t.Fatalf("want 3 images, got %d: %+v", len(imgs), imgs)
	}
	// Newest first.
	if imgs[0].Name != "new.jpg" {
		t.Errorf("newest first: want new.jpg, got %q", imgs[0].Name)
	}
	if imgs[0].Type != "image/jpeg" {
		t.Errorf("want image/jpeg, got %q", imgs[0].Type)
	}
	// Nested drop is addressable by slash-separated relative name.
	var foundNested bool
	for _, im := range imgs {
		if im.Name == "photos/nested.webp" {
			foundNested = true
			if im.Type != "image/webp" {
				t.Errorf("nested type: want image/webp, got %q", im.Type)
			}
		}
	}
	if !foundNested {
		t.Error("nested image photos/nested.webp not listed")
	}
}

func TestListGalleryImagesLimit(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 5; i++ {
		writeImage(t, dir, filepath.Join("g", "img"+string(rune('a'+i))+".png"), i)
	}
	imgs, err := listGalleryImages(dir, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(imgs) != 2 {
		t.Fatalf("limit not applied: got %d", len(imgs))
	}
}

func TestListGalleryImagesMissingDir(t *testing.T) {
	if _, err := listGalleryImages(filepath.Join(t.TempDir(), "nope"), 0); err == nil {
		t.Fatal("want error for missing dir")
	}
}

func TestReadGalleryImageServesImage(t *testing.T) {
	dir := t.TempDir()
	writeImage(t, dir, "pic.png", 5)
	data, ct, err := readGalleryImage(dir, "pic.png")
	if err != nil {
		t.Fatal(err)
	}
	if ct != "image/png" {
		t.Errorf("content type: want image/png, got %q", ct)
	}
	if len(data) == 0 {
		t.Error("empty image data")
	}
}

func TestReadGalleryImageRejectsTraversal(t *testing.T) {
	dir := t.TempDir()
	// A secret sits OUTSIDE the inbox; the endpoint must never reach it.
	secret := filepath.Join(filepath.Dir(dir), "secret.png")
	if err := os.WriteFile(secret, []byte("\x89PNGsecret"), 0o644); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(secret)

	for _, name := range []string{
		"../secret.png",
		filepath.Join("..", "secret.png"),
		"/etc/passwd",
	} {
		if _, _, err := readGalleryImage(dir, name); err == nil {
			t.Errorf("traversal %q was not rejected", name)
		}
	}
}

func TestReadGalleryImageRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	// A secret outside the inbox; a symlink inside points at it with an image name.
	secret := filepath.Join(filepath.Dir(dir), "secret.txt")
	if err := os.WriteFile(secret, []byte("PRIVATE KEY"), 0o644); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(secret)
	link := filepath.Join(dir, "innocent.png")
	if err := os.Symlink(secret, link); err != nil {
		t.Skipf("symlinks unavailable on this platform: %v", err) // Windows without privilege
	}
	// The listing already skips it (lstat semantics)...
	imgs, err := listGalleryImages(dir, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(imgs) != 0 {
		t.Errorf("symlink should not be listed, got %+v", imgs)
	}
	// ...and the read path must refuse to follow it out of the inbox.
	if _, _, err := readGalleryImage(dir, "innocent.png"); err == nil {
		t.Fatal("readGalleryImage followed a symlink out of the inbox")
	}
}

func TestReadGalleryImageRejectsNonImage(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "key.pem"), []byte("private"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readGalleryImage(dir, "key.pem"); err == nil {
		t.Fatal("non-image extension was not rejected")
	}
	// SVG is deliberately excluded (can carry script).
	if err := os.WriteFile(filepath.Join(dir, "x.svg"), []byte("<svg/>"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readGalleryImage(dir, "x.svg"); err == nil {
		t.Fatal("svg was not rejected")
	}
}

func TestReadGalleryImageTooLarge(t *testing.T) {
	dir := t.TempDir()
	big := filepath.Join(dir, "big.png")
	if err := os.WriteFile(big, make([]byte, maxAirImage+1), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readGalleryImage(dir, "big.png"); err == nil {
		t.Fatal("oversize image was not rejected")
	}
}

func TestImageType(t *testing.T) {
	cases := map[string]string{
		"a.png": "image/png", "b.JPG": "image/jpeg", "c.jpeg": "image/jpeg",
		"d.gif": "image/gif", "e.webp": "image/webp",
	}
	for name, want := range cases {
		if got, ok := imageType(name); !ok || got != want {
			t.Errorf("imageType(%q)=%q,%v; want %q", name, got, ok, want)
		}
	}
	for _, name := range []string{"x.txt", "y.svg", "z", "w.pem"} {
		if _, ok := imageType(name); ok {
			t.Errorf("imageType(%q) should not be an image", name)
		}
	}
}

func TestHumanBytes(t *testing.T) {
	cases := map[int64]string{0: "0 B", 512: "512 B", 1500: "1.5 kB", 2_000_000: "2.0 MB"}
	for n, want := range cases {
		if got := humanBytes(n); got != want {
			t.Errorf("humanBytes(%d)=%q; want %q", n, got, want)
		}
	}
}
