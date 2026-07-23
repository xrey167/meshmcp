package session

import (
	"testing"
)

// BenchmarkFileStoreSaveLoad pins the per-checkpoint cost of session
// persistence (Save is called on ack-driven checkpoints; Load on resume).
// Run with: go test ./session/ -bench . -benchmem -run '^$'
func BenchmarkFileStoreSaveLoad(b *testing.B) {
	s, err := NewFileStore(b.TempDir())
	if err != nil {
		b.Fatal(err)
	}
	ps := PersistedSession{
		ID: "bench-session", Owner: "gw-1", CreatorKey: "peer-key",
		SendSeq: 42, Acked: 40, RecvSeq: 17,
		SendBuf: []PersistedFrame{{Seq: 41, Payload: make([]byte, 512)}, {Seq: 42, Payload: make([]byte, 512)}},
		Replay:  make([]byte, 4096),
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if err := s.Save(ps); err != nil {
			b.Fatal(err)
		}
		if _, ok, err := s.Load(ps.ID); err != nil || !ok {
			b.Fatalf("load: ok=%v err=%v", ok, err)
		}
	}
}
