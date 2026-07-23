package checkpoint

import "os"

// writeFileAtomic writes data to path all-or-nothing: it writes to a sibling
// temp file, fsyncs it so the bytes are durably on disk, then renames it into
// place. os.Rename is atomic on a single filesystem, so a concurrent reader of
// path observes either the complete old file or the complete new one — never a
// half-written checkpoint. On any failure the temp file is removed and path is
// left untouched.
//
// This is a small, self-contained re-implementation of the repo's temp+fsync+
// rename idiom (session.FileStore.writeLocked, federation.DCRStore.writeAtomic,
// policy's approval-token store). Those helpers are unexported methods bound to
// their own store/record types and are not importable without refactoring the
// packages that own them, so — per the S5 constraint against extracting a
// package just to reuse a ~20-line helper — this package carries its own.
//
// The temp path is derived from path (which is unique per RunID) and callers
// serialize writes per RunID, so the fixed ".tmp" suffix cannot collide across
// concurrent writers. O_TRUNC clears any temp left by an earlier crash.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, perm)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil { // durable: bytes on disk before the rename
		f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil { // atomic replace
		_ = os.Remove(tmp)
		return err
	}
	return nil
}
