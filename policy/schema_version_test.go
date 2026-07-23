package policy

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// TestAuditWrittenRecordsCarrySchemaVersion proves every written record
// self-describes its format: schema_version is present and equals the current
// version, and the chain (which covers the field) still verifies.
func TestAuditWrittenRecordsCarrySchemaVersion(t *testing.T) {
	var buf bytes.Buffer
	a := NewAuditLog(&buf, func() string { return "T" })
	for i := 0; i < 3; i++ {
		if err := a.write(AuditRecord{Backend: "kg", Peer: "p", Method: "tools/call", Decision: "allow", Rule: 0}); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	for _, line := range strings.Split(strings.TrimRight(buf.String(), "\n"), "\n") {
		var m map[string]json.RawMessage
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatal(err)
		}
		v, ok := m["schema_version"]
		if !ok {
			t.Fatalf("written record has no schema_version: %s", line)
		}
		if strings.TrimSpace(string(v)) != "1" {
			t.Errorf("schema_version = %s, want 1", v)
		}
	}
	if res, err := VerifyChain(bytes.NewReader(buf.Bytes())); err != nil || !res.OK {
		t.Fatalf("chain with schema_version did not verify: ok=%v reason=%q err=%v", res.OK, res.Reason, err)
	}
}

// TestAuditRejectsNewerSchemaVersion proves a record from a newer build (a
// higher schema_version) is refused — fail closed — by both verifiers, and is
// NEVER treated as a torn tail even when it is the final line.
func TestAuditRejectsNewerSchemaVersion(t *testing.T) {
	// A single, otherwise well-formed record whose schema_version is one beyond
	// what this build supports. Hash/prev_hash are irrelevant: the version gate
	// fires before the chain checks.
	rec := AuditRecord{
		Time: "T", Backend: "kg", Peer: "p", Method: "tools/call",
		Decision: "allow", Rule: 0, Seq: 1, PrevHash: "",
		SchemaVersion: auditSchemaVersion + 1,
	}
	line, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	data := append(line, '\n')

	res, err := VerifyChain(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("VerifyChain err: %v", err)
	}
	if res.OK {
		t.Fatalf("VerifyChain accepted a newer schema version (should fail closed)")
	}
	if !strings.Contains(res.Reason, "schema version") {
		t.Errorf("reason %q does not mention the schema version", res.Reason)
	}

	// The same record as the final line must NOT be repaired as a torn tail — a
	// complete future-format record is refused, not truncated away.
	repairRes, truncateTo, torn := VerifyForRepair(data)
	if torn {
		t.Fatalf("VerifyForRepair treated a newer-version record as a torn tail (would silently drop a valid future record)")
	}
	if repairRes.OK {
		t.Fatalf("VerifyForRepair accepted a newer schema version")
	}
	if truncateTo != 0 {
		t.Errorf("truncateTo = %d, want 0 (no truncation for a version mismatch)", truncateTo)
	}
}

// TestAuditLegacyRecordWithoutVersionVerifies proves a record written before the
// schema_version field existed (field absent → decodes as 0) still verifies, so
// existing chains keep working across the upgrade that introduced the field.
func TestAuditLegacyRecordWithoutVersionVerifies(t *testing.T) {
	// Build a record, hash it as if schema_version had never been part of the
	// struct by clearing it before hashing — this reproduces a pre-upgrade line.
	rec := AuditRecord{
		Time: "T", Backend: "kg", Peer: "p", Method: "tools/call",
		Decision: "allow", Rule: 0, Seq: 1, PrevHash: "",
	}
	h, _, err := chainHash(rec)
	if err != nil {
		t.Fatal(err)
	}
	rec.Hash = h
	line, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(line, []byte("schema_version")) {
		t.Fatalf("legacy fixture unexpectedly emitted schema_version: %s", line)
	}
	res, err := VerifyChain(bytes.NewReader(append(line, '\n')))
	if err != nil || !res.OK {
		t.Fatalf("legacy record did not verify: ok=%v reason=%q err=%v", res.OK, res.Reason, err)
	}
}
