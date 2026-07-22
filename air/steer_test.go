package air

import (
	"strings"
	"testing"
)

// TestSteerEnvelopeValidate covers the centralized steer validation: task needs
// a tool, nudge/cancel are fine, and an unknown type is rejected.
func TestSteerEnvelopeValidate(t *testing.T) {
	ok := []SteerEnvelope{
		{Type: SteerTask, Tool: "read_file"},
		{Type: SteerNudge, Text: "focus"},
		{Type: SteerCancel},
	}
	for _, e := range ok {
		if err := e.Validate(); err != nil {
			t.Fatalf("valid envelope rejected: %+v: %v", e, err)
		}
	}
	bad := []SteerEnvelope{
		{Type: SteerTask}, // task without a tool
		{Type: "pause"},   // unknown type
		{Type: ""},        // empty type
	}
	for _, e := range bad {
		if err := e.Validate(); err == nil {
			t.Fatalf("invalid envelope accepted: %+v", e)
		}
	}
}

// TestParseEnvelopes covers newline-delimited parsing: valid lines are
// delivered, blanks skipped, and a malformed line ends the stream with an error.
func TestParseEnvelopes(t *testing.T) {
	in := strings.NewReader(`{"type":"task","tool":"read_file","args":{"path":"x"}}` + "\n" +
		"\n" + // blank skipped
		`{"type":"nudge","text":"focus","target":"task:9f2a","id":"corr-7"}` + "\n" +
		`{"type":"cancel"}` + "\n")
	var got []SteerEnvelope
	if err := ParseEnvelopes(in, func(e SteerEnvelope) { got = append(got, e) }); err != nil {
		t.Fatalf("ParseEnvelopes: %v", err)
	}
	if len(got) != 3 || got[0].Type != SteerTask || got[0].Tool != "read_file" || got[2].Type != SteerCancel {
		t.Fatalf("unexpected envelopes: %+v", got)
	}
	if got[1].Target != "task:9f2a" || got[1].ID != "corr-7" {
		t.Fatalf("target/id not parsed: %+v", got[1])
	}
	if err := ParseEnvelopes(strings.NewReader("not json\n"), func(SteerEnvelope) {}); err == nil {
		t.Fatal("expected error on malformed envelope")
	}
}

// TestCatalogFilters covers the Steerable/Resumable discovery helpers.
func TestCatalogFilters(t *testing.T) {
	c := Catalog{Endpoints: []CatalogEntry{
		{Name: "fs", Steerable: true, Resumable: true},
		{Name: "web", Steerable: false, Resumable: false},
		{Name: "vault", Steerable: false, Resumable: true},
	}}
	if s := c.Steerable(); len(s) != 1 || s[0].Name != "fs" {
		t.Fatalf("Steerable() = %+v", s)
	}
	if r := c.Resumable(); len(r) != 2 {
		t.Fatalf("Resumable() = %+v", r)
	}
}

// TestSteerConveniences covers TaskArgs and String.
func TestSteerConveniences(t *testing.T) {
	e := TaskArgs("read_customer", map[string]any{"id": 42})
	if e.Type != SteerTask || e.Tool != "read_customer" || len(e.Args) == 0 {
		t.Fatalf("TaskArgs: %+v", e)
	}
	if got := TaskArgs("t", nil); len(got.Args) != 0 {
		t.Fatalf("nil args should marshal to nothing: %+v", got)
	}
	cases := map[string]SteerEnvelope{
		"task read_file":             {Type: SteerTask, Tool: "read_file"},
		`nudge "focus"`:              {Type: SteerNudge, Text: "focus"},
		"cancel → task:9f2a":         {Type: SteerCancel, Target: "task:9f2a"},
		"task charge → session:1a2b": {Type: SteerTask, Tool: "charge", Target: "session:1a2b"},
	}
	for want, env := range cases {
		if got := env.String(); got != want {
			t.Errorf("String() = %q, want %q", got, want)
		}
	}
}
