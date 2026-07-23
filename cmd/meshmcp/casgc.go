package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// CAS garbage collection (`meshmcp fetch --gc`).
//
// The content-addressed store has NO reference model: nothing in meshmcp
// records which blobs are still wanted, so a "safe to delete" verdict cannot
// be computed. GC is therefore explicit and policy-free: blobs are candidates
// only under the operator-supplied --max-age and/or --max-total-bytes bounds,
// and the default run is a dry run — nothing is deleted until --apply is
// passed. Only well-formed blob entries (<dir>/<aa>/<64-hex> whose parent
// shard matches the hash prefix) are considered; foreign files are never
// touched.

// gcBlob is one blob considered by the collector.
type gcBlob struct {
	Path    string    `json:"path"`
	Hash    string    `json:"hash"`
	Size    int64     `json:"size"`
	ModTime time.Time `json:"mod_time"`
}

// gcPlan is the collector's verdict: which blobs to delete and why-sized totals.
type gcPlan struct {
	Scanned      int
	ScannedBytes int64
	Delete       []gcBlob
	DeleteBytes  int64
}

// scanCASBlobs lists well-formed blobs under dir, skipping anything that is
// not a <aa>/<64-hex> entry in its matching shard.
func scanCASBlobs(dir string) ([]gcBlob, error) {
	shards, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read cas dir %s: %w", dir, err)
	}
	var blobs []gcBlob
	for _, sh := range shards {
		if !sh.IsDir() || len(sh.Name()) != 2 || !isHex(sh.Name()) {
			continue
		}
		entries, err := os.ReadDir(filepath.Join(dir, sh.Name()))
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			name := e.Name()
			if e.IsDir() || len(name) != 64 || !isHex(name) || name[:2] != sh.Name() {
				continue
			}
			info, err := e.Info()
			if err != nil {
				if errors.Is(err, os.ErrNotExist) {
					continue // raced with a concurrent delete
				}
				return nil, err
			}
			blobs = append(blobs, gcBlob{
				Path:    filepath.Join(dir, sh.Name(), name),
				Hash:    name,
				Size:    info.Size(),
				ModTime: info.ModTime(),
			})
		}
	}
	return blobs, nil
}

// planCASGC selects deletion candidates: first every blob older than maxAge
// (if maxAge > 0), then — if the survivors still exceed maxTotal (> 0) —
// oldest-first until the store fits. At least one bound must be positive.
func planCASGC(blobs []gcBlob, now time.Time, maxAge time.Duration, maxTotal int64) gcPlan {
	sorted := append([]gcBlob(nil), blobs...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].ModTime.Before(sorted[j].ModTime) })

	plan := gcPlan{Scanned: len(sorted)}
	var kept []gcBlob
	var keptBytes int64
	for _, b := range sorted {
		plan.ScannedBytes += b.Size
		if maxAge > 0 && now.Sub(b.ModTime) > maxAge {
			plan.Delete = append(plan.Delete, b)
			plan.DeleteBytes += b.Size
			continue
		}
		kept = append(kept, b)
		keptBytes += b.Size
	}
	if maxTotal > 0 {
		for _, b := range kept { // oldest first (kept preserves sort order)
			if keptBytes <= maxTotal {
				break
			}
			plan.Delete = append(plan.Delete, b)
			plan.DeleteBytes += b.Size
			keptBytes -= b.Size
		}
	}
	return plan
}

// runCASGC scans, plans, and (with apply) deletes. It returns the plan so the
// caller can report what happened (or would happen on a dry run); on apply the
// returned plan is narrowed to what was actually deleted.
func runCASGC(dir string, now time.Time, maxAge time.Duration, maxTotal int64, apply bool) (gcPlan, error) {
	if maxAge <= 0 && maxTotal <= 0 {
		return gcPlan{}, errors.New("gc needs at least one bound: --max-age and/or --max-total-bytes")
	}
	blobs, err := scanCASBlobs(dir)
	if err != nil {
		return gcPlan{}, err
	}
	plan := planCASGC(blobs, now, maxAge, maxTotal)
	if !apply {
		return plan, nil
	}
	return deleteCASBlobs(plan)
}

// deleteCASBlobs removes the planned blobs, re-checking each path immediately
// before deletion: a blob whose mtime advanced since the scan was re-dropped
// concurrently (recvOne renames a fresh temp file over the path, refreshing
// its mtime), so deleting it on the stale scan verdict would discard content
// the receiver just audited as stored. Refreshed or vanished entries are
// skipped; the returned plan reports only what was actually deleted.
func deleteCASBlobs(plan gcPlan) (gcPlan, error) {
	deleted := gcPlan{Scanned: plan.Scanned, ScannedBytes: plan.ScannedBytes}
	for _, b := range plan.Delete {
		info, err := os.Lstat(b.Path)
		if errors.Is(err, os.ErrNotExist) {
			continue // already gone (raced with a concurrent delete)
		}
		if err != nil {
			return deleted, fmt.Errorf("stat %s: %w", b.Path, err)
		}
		if info.ModTime().After(b.ModTime) {
			continue // re-dropped since the scan: keep the fresh copy
		}
		if err := os.Remove(b.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return deleted, fmt.Errorf("delete %s: %w", b.Path, err)
		}
		deleted.Delete = append(deleted.Delete, b)
		deleted.DeleteBytes += b.Size
	}
	return deleted, nil
}

// cmdFetchGC is the local `fetch --gc` mode: no mesh, no network — it prunes
// the local CAS directory under explicit bounds, dry-run by default.
func cmdFetchGC(dir string, maxAge time.Duration, maxTotal int64, apply bool) error {
	if dir == "" {
		return errors.New("usage: meshmcp fetch --gc --dir <cas-dir> [--max-age 720h] [--max-total-bytes N] [--apply]")
	}
	plan, err := runCASGC(dir, time.Now(), maxAge, maxTotal, apply)
	if err != nil {
		return err
	}
	verb := "would delete"
	if apply {
		verb = "deleted"
	}
	for _, b := range plan.Delete {
		fmt.Printf("%s %s (%d bytes, modified %s)\n", verb, b.Hash, b.Size, b.ModTime.UTC().Format(time.RFC3339))
	}
	fmt.Printf("gc: scanned %d blob(s) / %d bytes; %s %d blob(s) / %d bytes\n",
		plan.Scanned, plan.ScannedBytes, verb, len(plan.Delete), plan.DeleteBytes)
	if !apply && len(plan.Delete) > 0 {
		fmt.Println("dry run: re-run with --apply to delete")
	}
	return nil
}
