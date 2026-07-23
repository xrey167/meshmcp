package session

import (
	"encoding/json"
	"os"
	"testing"
)

// TestSessionFileStoreStampsVersion proves a persisted session self-describes
// its format and round-trips through Load unchanged.
func TestSessionFileStoreStampsVersion(t *testing.T) {
	dir := t.TempDir()
	s, err := NewFileStore(dir)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if err := s.Save(PersistedSession{ID: "sess-1", Owner: "gw-a"}); err != nil {
		t.Fatalf("save: %v", err)
	}
	b, err := os.ReadFile(s.path("sess-1"))
	if err != nil {
		t.Fatal(err)
	}
	var onDisk struct {
		SchemaVersion int `json:"schema_version"`
	}
	if err := json.Unmarshal(b, &onDisk); err != nil {
		t.Fatal(err)
	}
	if onDisk.SchemaVersion != sessionSchemaVersion {
		t.Errorf("stamped version = %d, want %d", onDisk.SchemaVersion, sessionSchemaVersion)
	}
	ps, found, err := s.Load("sess-1")
	if err != nil || !found {
		t.Fatalf("load: found=%v err=%v", found, err)
	}
	if ps.ID != "sess-1" || ps.Owner != "gw-a" {
		t.Errorf("round-trip mismatch: %+v", ps)
	}
}

// TestSessionFileStoreSkipsNewerVersion proves a session written by a newer
// build is treated as no resumable session (Load → not found) and skipped by
// List — the tolerant posture for resumption state — rather than being
// misread or resumed against a format this build may not understand.
func TestSessionFileStoreSkipsNewerVersion(t *testing.T) {
	dir := t.TempDir()
	s, err := NewFileStore(dir)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	newer := `{"id": "sess-future", "owner": "gw-b", "schema_version": 2}`
	if err := os.WriteFile(s.path("sess-future"), []byte(newer), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, found, err := s.Load("sess-future"); err != nil || found {
		t.Errorf("Load of a newer-version session: found=%v err=%v, want found=false", found, err)
	}
	list, err := s.List()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	for _, ps := range list {
		if ps.ID == "sess-future" {
			t.Errorf("List returned a newer-version session it should have skipped")
		}
	}
}

// TestSessionFileStoreLegacyLoads proves a pre-versioning session file (no
// schema_version key) still resumes.
func TestSessionFileStoreLegacyLoads(t *testing.T) {
	dir := t.TempDir()
	s, err := NewFileStore(dir)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	legacy := `{"id": "sess-old", "owner": "gw-c", "send_seq": 3}`
	if err := os.WriteFile(s.path("sess-old"), []byte(legacy), 0o644); err != nil {
		t.Fatal(err)
	}
	ps, found, err := s.Load("sess-old")
	if err != nil || !found {
		t.Fatalf("legacy load: found=%v err=%v", found, err)
	}
	if ps.ID != "sess-old" || ps.SendSeq != 3 {
		t.Errorf("legacy session decoded wrong: %+v", ps)
	}
}
