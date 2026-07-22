package air

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSummarizeCounts(t *testing.T) {
	h := Home{
		Generated: "2026-07-22T12:00:00Z",
		Peers: []PeerRow{
			{Status: "connected"}, {Status: "connected"}, {Status: "idle"},
		},
		Sessions:  make([]Session, 2),
		Reachable: make([]CatalogEntry, 7),
		Pending:   1,
		Activity: []Receipt{
			{Decision: "deny", Time: "2026-07-22T11:30:00Z"},  // within 1h
			{Decision: "deny", Time: "2026-07-22T10:00:00Z"},  // older than 1h
			{Decision: "allow", Time: "2026-07-22T11:59:00Z"}, // not a deny
		},
	}
	s := Summarize(h)
	if s.PeersOnline != 2 || s.PeersTotal != 3 {
		t.Errorf("peers online/total = %d/%d, want 2/3", s.PeersOnline, s.PeersTotal)
	}
	if s.Sessions != 2 || s.Reachable != 7 {
		t.Errorf("sessions/reachable = %d/%d, want 2/7", s.Sessions, s.Reachable)
	}
	if s.Pending != 1 {
		t.Errorf("pending = %d, want 1", s.Pending)
	}
	if s.Denies1h != 1 {
		t.Errorf("denies_1h = %d, want 1 (only the deny inside the window)", s.Denies1h)
	}
}

func TestSummarizePendingUnknown(t *testing.T) {
	s := Summarize(Home{Generated: "2026-07-22T12:00:00Z", Pending: -1})
	if s.Pending != -1 {
		t.Fatalf("unknown pending must stay -1, got %d", s.Pending)
	}
}

// sampleHome builds a fully-populated Home at a given assembly instant, so tests
// can vary just the instant (or one section) and observe the signature.
func sampleHome(generated string) Home {
	return Home{
		Generated: generated,
		You:       PeerRow{Status: "connected", IP: "100.64.0.1", FQDN: "me.mesh", PubKey: "K0"},
		Peers:     []PeerRow{{Status: "connected", IP: "100.64.0.2", FQDN: "a.mesh", PubKey: "K1"}},
		Sessions:  []Session{{Backend: "fs", ID: "9f2a", Peer: "a.mesh", AgeSec: 4}},
		Reachable: []CatalogEntry{{Name: "fs", Address: "100.64.0.2:9101", Transport: "stdio"}},
		Activity:  []Receipt{{Decision: "allow", Time: "2026-07-22T11:59:00Z", Peer: "a.mesh", Method: "tools/call"}},
		Showing:   &Media{Name: "slide.png", ModUnix: 1700000000},
		Landed:    3,
		Pending:   1,
	}
}

func TestSignatureStableAcrossReassembly(t *testing.T) {
	a := sampleHome("2026-07-22T12:00:00Z")
	b := sampleHome("2026-07-22T12:00:05Z") // different instant, same state
	// A ticking session age is not a state change: it must not flip the hash.
	b.Sessions[0].AgeSec = 9
	if a.Signature() != b.Signature() {
		t.Fatalf("signature changed on re-assembly of identical state:\n a=%s\n b=%s", a.Signature(), b.Signature())
	}
}

func TestSignatureChangesOnDelta(t *testing.T) {
	base := sampleHome("2026-07-22T12:00:00Z")
	sig := base.Signature()

	cases := map[string]func(Home) Home{
		"new peer": func(h Home) Home {
			h.Peers = append(append([]PeerRow(nil), h.Peers...), PeerRow{Status: "connected", FQDN: "b.mesh", PubKey: "K9"})
			return h
		},
		"new session": func(h Home) Home {
			h.Sessions = append(append([]Session(nil), h.Sessions...), Session{Backend: "sql", ID: "abcd", Peer: "b.mesh"})
			return h
		},
		"new receipt": func(h Home) Home {
			h.Activity = append([]Receipt{{Decision: "deny", Time: "2026-07-22T12:00:01Z", Peer: "x"}}, h.Activity...)
			return h
		},
		"cast swap": func(h Home) Home {
			h.Showing = &Media{Name: "next.png", ModUnix: 1700000999}
			return h
		},
	}
	for name, mutate := range cases {
		if got := mutate(sampleHome("2026-07-22T12:00:00Z")).Signature(); got == sig {
			t.Errorf("%s: signature did not change (still %s)", name, got)
		}
	}
}

func TestParseReceipt(t *testing.T) {
	if r, ok := ParseReceipt([]byte(`{"time":"t","peer":"a","decision":"allow","method":"m"}`)); !ok || r.Decision != "allow" || r.Peer != "a" {
		t.Errorf("valid line rejected or mis-decoded: %+v ok=%v", r, ok)
	}
	if _, ok := ParseReceipt([]byte(`{"peer":"a","method":"m"}`)); ok {
		t.Error("a record with no decision must be rejected")
	}
	if _, ok := ParseReceipt([]byte(`not json`)); ok {
		t.Error("malformed JSON must be rejected")
	}
	if _, ok := ParseReceipt([]byte("   ")); ok {
		t.Error("blank line must be rejected")
	}
}

func TestHomeDegradesSectionBySection(t *testing.T) {
	var h Home // every section nil
	b, err := json.Marshal(h)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, want := range []string{`"peers":[]`, `"sessions":[]`, `"reachable":[]`, `"activity":[]`} {
		if !strings.Contains(s, want) {
			t.Errorf("nil section did not marshal to an empty array (%s missing): %s", want, s)
		}
	}
	if strings.Contains(s, "null") {
		t.Errorf("home marshalled a null section: %s", s)
	}
}
