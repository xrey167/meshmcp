package policy

import (
	"errors"
	"io"
	"strings"
	"testing"
)

// failWriter fails every write after the first N succeed, simulating a full
// disk / broken audit sink.
type failWriter struct {
	ok  int
	buf strings.Builder
}

func (w *failWriter) Write(p []byte) (int, error) {
	if w.ok <= 0 {
		return 0, errors.New("disk full")
	}
	w.ok--
	return w.buf.Write(p)
}

// TestAuditWriteReservesSeqOnlyOnSuccess proves the chain cursor does not
// advance when a record cannot be written, so no gap appears in the sequence
// that verification would later flag as tamper (S11).
func TestAuditWriteReservesSeqOnlyOnSuccess(t *testing.T) {
	w := &failWriter{ok: 1}
	a := NewAuditLog(w, func() string { return "" })

	if err := a.write(AuditRecord{Backend: "b", Tool: "t1", Decision: "allow"}); err != nil {
		t.Fatalf("first write should succeed: %v", err)
	}
	// Second write fails (writer exhausted); seq must NOT advance.
	if err := a.write(AuditRecord{Backend: "b", Tool: "t2", Decision: "allow"}); err == nil {
		t.Fatal("second write should fail")
	}
	// A subsequent successful write must reuse seq 2 (no gap), linking to
	// record 1's hash.
	w.ok = 1
	if err := a.write(AuditRecord{Backend: "b", Tool: "t3", Decision: "allow"}); err != nil {
		t.Fatalf("third write should succeed: %v", err)
	}
	if a.seq != 2 {
		t.Fatalf("seq advanced past a failed write: want 2, got %d", a.seq)
	}
}

// recordRWC is a minimal backend that records everything written to it.
type recordRWC struct {
	written strings.Builder
	r       *io.PipeReader
	w       *io.PipeWriter
}

func newRecordRWC() *recordRWC {
	r, w := io.Pipe()
	return &recordRWC{r: r, w: w}
}
func (b *recordRWC) Read(p []byte) (int, error)  { return b.r.Read(p) }
func (b *recordRWC) Write(p []byte) (int, error) { return b.written.Write(p) }
func (b *recordRWC) Close() error                { b.w.Close(); return b.r.Close() }

// TestFailClosedAuditDeniesCall proves that when the audit sink cannot record a
// tools/call and the log is fail-closed, the call is denied and never reaches
// the backend (P0-3 / F22).
func TestFailClosedAuditDeniesCall(t *testing.T) {
	backend := newRecordRWC()
	audit := NewAuditLog(&failWriter{ok: 0}, func() string { return "" }).WithFailClosed(true)
	pol := &Policy{DefaultAllow: true} // policy would allow; audit must still gate
	f := NewFilter(backend, Caller{Peer: "alice", PeerKey: "alice-key", Backend: "b"}, pol, audit, nil)

	call := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"do_it"}}` + "\n"
	// The denial is written to the read side (a pipe), so drive Write on its own
	// goroutine and read the response here.
	go func() { _, _ = f.Write([]byte(call)) }()
	buf := make([]byte, 4096)
	n, _ := f.Read(buf)
	got := string(buf[:n])
	if !strings.Contains(got, "audit sink unavailable") {
		t.Fatalf("expected fail-closed denial, got: %s", got)
	}
	if backend.written.Len() != 0 {
		t.Fatalf("call reached the backend despite audit failure: %q", backend.written.String())
	}
}
