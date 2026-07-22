package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Air · Vision — seeing over the mesh.
//
// Air already moves bytes; Vision moves and VIEWS visual context — a screenshot,
// an image, a photo — with the same identity, ACL, and receipt as any drop. The
// concrete, shipped-primitive form: a `drop` receiver's inbox is a directory of
// files that landed by cryptographic identity, each audited by content hash. Air
// Vision renders the IMAGES in that inbox — in the terminal (`air vision <dir>`)
// and, the point of it, inline on the served phone-first page (`air serve
// --gallery <dir>`), so a phone SEES what a laptop dropped, gated by the viewer
// ACL and served path-safely. See docs/AIR-VISION.md.

// maxAirImage bounds a single image the gallery will read and serve, so a huge
// file dropped into the inbox can't wedge the page or exhaust memory.
const maxAirImage = 16 << 20

// maxGalleryImages caps how many images a single listing returns, newest first —
// a busy inbox stays a scannable gallery, not an unbounded scroll.
const maxGalleryImages = 200

// imageContentTypes maps a lower-cased file extension to the exact Content-Type
// the gallery serves it as. It is an allow-list: a file whose extension is not
// here is not an image the gallery will list or serve. SVG is deliberately
// excluded — it can carry script, and "an image" should never be able to.
var imageContentTypes = map[string]string{
	".png":  "image/png",
	".jpg":  "image/jpeg",
	".jpeg": "image/jpeg",
	".gif":  "image/gif",
	".webp": "image/webp",
	".bmp":  "image/bmp",
	".avif": "image/avif",
	".heic": "image/heic",
}

// imageType returns the Content-Type for name's extension and whether it is a
// recognised, servable image at all.
func imageType(name string) (string, bool) {
	ct, ok := imageContentTypes[strings.ToLower(filepath.Ext(name))]
	return ct, ok
}

// galleryImage describes one image that landed in a Vision inbox. Name is the
// path relative to the inbox root (slash-separated, so a drop that reproduced a
// tree — "photos/a.jpg" — is addressable); it is the exact value handed back to
// readGalleryImage, which re-validates it against the root.
type galleryImage struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	Size    int64  `json:"size"`
	ModUnix int64  `json:"mod"` // last-modified, unix seconds (freshness / ordering)
}

// listGalleryImages walks dir and returns the image files under it, newest
// first, capped at limit. Non-image files, directories, and non-regular entries
// (symlinks, devices) are skipped, so the gallery never follows a link out of
// the inbox. A missing dir is reported as an error; an empty one as no images.
func listGalleryImages(dir string, limit int) ([]galleryImage, error) {
	if limit <= 0 || limit > maxGalleryImages {
		limit = maxGalleryImages
	}
	var imgs []galleryImage
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !d.Type().IsRegular() {
			return nil
		}
		ct, ok := imageType(d.Name())
		if !ok {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		imgs = append(imgs, galleryImage{
			Name:    filepath.ToSlash(rel),
			Type:    ct,
			Size:    info.Size(),
			ModUnix: info.ModTime().Unix(),
		})
		return nil
	})
	if err != nil {
		return nil, err
	}
	// Newest first; a stable name tiebreak keeps identical mtimes deterministic.
	sort.Slice(imgs, func(i, j int) bool {
		if imgs[i].ModUnix != imgs[j].ModUnix {
			return imgs[i].ModUnix > imgs[j].ModUnix
		}
		return imgs[i].Name < imgs[j].Name
	})
	if len(imgs) > limit {
		imgs = imgs[:limit]
	}
	return imgs, nil
}

// readGalleryImage reads one image by its listing name, safely. name is resolved
// against dir with the same traversal defence as a received drop (sanitizeDest
// rejects absolute paths and any ".." escape), and its extension must be a
// recognised image type — so a viewer cannot coax the page into serving an
// arbitrary file (a private key, /etc/passwd) through the image endpoint. The
// returned Content-Type is derived from the extension, never sniffed.
func readGalleryImage(dir, name string) (data []byte, contentType string, err error) {
	ct, ok := imageType(name)
	if !ok {
		return nil, "", fmt.Errorf("not an image: %q", name)
	}
	dest, err := sanitizeDest(dir, name)
	if err != nil {
		return nil, "", err
	}
	// Lstat, not Stat: sanitizeDest is purely lexical (it never resolves
	// symlinks), so a symlink named e.g. "x.png" inside the inbox pointing at a
	// secret outside it would pass the lexical check and, if we followed it, be
	// served as an image. Lstat sees the link itself; requiring a regular file
	// rejects it — matching the listing path (WalkDir's lstat-based
	// DirEntry.Type), which already skips symlinks. So /api/image can never serve
	// what /api/gallery would not list.
	fi, err := os.Lstat(dest)
	if err != nil {
		return nil, "", err
	}
	if !fi.Mode().IsRegular() {
		return nil, "", fmt.Errorf("not a regular file: %q", name)
	}
	if fi.Size() > maxAirImage {
		return nil, "", fmt.Errorf("image %q is %s, over the %s limit", name, humanBytes(fi.Size()), humanBytes(maxAirImage))
	}
	f, err := os.Open(dest)
	if err != nil {
		return nil, "", err
	}
	defer f.Close()
	data, err = io.ReadAll(io.LimitReader(f, maxAirImage))
	if err != nil {
		return nil, "", err
	}
	return data, ct, nil
}

// cmdAirVision lists the images that have landed in a drop inbox — a terminal
// inventory of the visual context sent to this node — and points at `air serve
// --gallery` to actually view them. It is the CLI face of Air · Vision; the page
// gallery is where the pixels show.
func cmdAirVision(args []string) error {
	fs := flag.NewFlagSet("air vision", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "print the image inventory as JSON")
	limit := fs.Int("limit", maxGalleryImages, "maximum images to list (newest first)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: meshmcp air vision [flags] <inbox-dir>")
	}
	dir := fs.Arg(0)

	imgs, err := listGalleryImages(dir, *limit)
	if err != nil {
		return fmt.Errorf("air vision: %w", err)
	}
	if *asJSON {
		b, err := json.MarshalIndent(map[string]any{"dir": dir, "images": imgs}, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(b))
		return nil
	}
	if len(imgs) == 0 {
		fmt.Fprintln(os.Stderr, dim("no images in ")+bold(dir))
		return nil
	}
	now := time.Now().Unix()
	var rows [][]cell
	for _, im := range imgs {
		rows = append(rows, []cell{
			styled(im.Name, bold),
			plain(humanBytes(im.Size)),
			styled(humanAge(int(now-im.ModUnix)), dim),
			styled(strings.TrimPrefix(im.Type, "image/"), cyan),
		})
	}
	renderTable(os.Stdout, []string{"image", "size", "age", "type"}, rows)
	fmt.Fprintln(os.Stderr, dim(fmt.Sprintf("%d image(s) · view them on a phone: ", len(rows)))+
		bold("meshmcp air serve --gallery "+dir))
	return nil
}

// humanBytes renders a byte count compactly (e.g. "1.4 MB"), for the Vision
// inventory. Decimal units keep it legible next to file sizes users recognise.
func humanBytes(n int64) string {
	const unit = 1000
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for x := n / unit; x >= unit; x /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "kMGTPE"[exp])
}
