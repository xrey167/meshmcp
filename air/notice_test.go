package air

import (
	"bytes"
	"strings"
	"testing"
)

func TestNoticeValidate(t *testing.T) {
	if err := Ring("build is red").Validate(); err != nil {
		t.Errorf("valid ring rejected: %v", err)
	}
	if err := (Notice{Priority: PriorityUrgent, Message: "eyes now"}).Validate(); err != nil {
		t.Errorf("urgent ring rejected: %v", err)
	}
	// Empty message.
	if err := (Notice{}).Validate(); err == nil {
		t.Error("empty message should be rejected")
	}
	// Over length.
	if err := Ring(strings.Repeat("x", maxNoticeMessage+1)).Validate(); err == nil {
		t.Error("over-length message should be rejected")
	}
	// Control characters (terminal-escape injection).
	if err := Ring("evil\x1b[31m").Validate(); err == nil {
		t.Error("control chars should be rejected")
	}
	// Bad priority / kind.
	if err := (Notice{Message: "x", Priority: "loud"}).Validate(); err == nil {
		t.Error("bad priority should be rejected")
	}
	if err := (Notice{Message: "x", Kind: "cast"}).Validate(); err == nil {
		t.Error("unknown kind should be rejected")
	}
}

func TestNoticeNormalized(t *testing.T) {
	n := Notice{Message: "hi"}.Normalized()
	if n.Kind != NoticeRing || n.Priority != PriorityNormal {
		t.Fatalf("defaults not applied: %+v", n)
	}
	if !(Notice{Message: "x", Priority: PriorityUrgent}).Urgent() {
		t.Error("urgent not reported")
	}
}

func TestWriteParseNoticesRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	sent := []Notice{Ring("one"), {Message: "two", Priority: PriorityUrgent, From: "laptop"}}
	for _, n := range sent {
		if err := WriteNotice(&buf, n); err != nil {
			t.Fatal(err)
		}
	}
	var got []Notice
	if err := ParseNotices(&buf, func(n Notice) { got = append(got, n) }); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Message != "one" || got[1].Priority != PriorityUrgent {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
}

func TestParseNoticesRejectsBadLine(t *testing.T) {
	r := strings.NewReader("{not json}\n")
	if err := ParseNotices(r, func(Notice) {}); err == nil {
		t.Fatal("malformed line should error")
	}
}
