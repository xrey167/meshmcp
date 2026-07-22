package air

import (
	"bytes"
	"testing"
)

// TestParseTarget covers the "<kind>:<value>" grammar: valid kinds parse, empty
// is the zero target, and malformed / unknown-kind targets error.
func TestParseTarget(t *testing.T) {
	cases := map[string]struct {
		kind  TargetKind
		value string
	}{
		"task:9f2a":       {TargetTask, "9f2a"},
		"agent:analyst.m": {TargetAgent, "analyst.m"},
		"session:1a2b":    {TargetSession, "1a2b"},
		"group:readers":   {TargetGroup, "readers"},
	}
	for in, want := range cases {
		got, err := ParseTarget(in)
		if err != nil || got.Kind != want.kind || got.Value != want.value {
			t.Fatalf("ParseTarget(%q) = %+v err=%v", in, got, err)
		}
		if got.String() != in {
			t.Fatalf("round-trip: %q -> %+v -> %q", in, got, got.String())
		}
	}
	if z, err := ParseTarget(""); err != nil || !z.Empty() || z.String() != "" {
		t.Fatalf("empty target: %+v err=%v", z, err)
	}
	for _, bad := range []string{"task", "task:", ":9f2a", "pod:x", "unknown:y"} {
		if _, err := ParseTarget(bad); err == nil {
			t.Fatalf("bad target %q accepted", bad)
		}
	}
}

// TestEnvelopeConstructors covers Task/Nudge/Cancel and WriteEnvelope framing,
// round-tripping through ParseEnvelopes.
func TestEnvelopeConstructors(t *testing.T) {
	if e := Task("read_file", []byte(`{"p":1}`)); e.Type != SteerTask || e.Tool != "read_file" || string(e.Args) != `{"p":1}` {
		t.Fatalf("Task: %+v", e)
	}
	if e := Nudge("focus"); e.Type != SteerNudge || e.Text != "focus" {
		t.Fatalf("Nudge: %+v", e)
	}
	if e := Cancel(); e.Type != SteerCancel {
		t.Fatalf("Cancel: %+v", e)
	}
	var buf bytes.Buffer
	if err := WriteEnvelope(&buf, Task("t", nil)); err != nil {
		t.Fatal(err)
	}
	if buf.Len() == 0 || buf.Bytes()[buf.Len()-1] != '\n' {
		t.Fatalf("WriteEnvelope must end with a newline: %q", buf.String())
	}
	var got []SteerEnvelope
	if err := ParseEnvelopes(&buf, func(e SteerEnvelope) { got = append(got, e) }); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Tool != "t" {
		t.Fatalf("round-trip: %+v", got)
	}
}
