package air

// The aggregated live state of a mesh as one caller sees it — the composition
// the `air home` terminal board and the served /api/home render. It invents no
// data source: every field reuses an existing Air type, and nil/zero means
// "that surface is not wired on this node", so the view degrades section by
// section. Pure data + pure logic (Summarize, Signature, ParseReceipt), so it
// is unit-testable without a mesh, mirroring air/change.go and air/catalog.go.

import (
	"bytes"
	"encoding/json"
	"hash/fnv"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Receipt is the subset of a policy.AuditRecord the home and stream views show.
// It is promoted here (out of airstream) so the terminal ledger tail (air
// stream) and the aggregated home tail decode governed activity through one
// shared parser, ParseReceipt.
type Receipt struct {
	Time     string `json:"time"`
	Backend  string `json:"backend"`
	Peer     string `json:"peer"`
	Method   string `json:"method"`
	Tool     string `json:"tool"`
	Decision string `json:"decision"`
	Reason   string `json:"reason"`
}

// ParseReceipt decodes one audit JSONL line into the subset home and stream
// render, reporting false if the line is not a renderable audit record (bad
// JSON, or no decision — the field that marks a policy record).
func ParseReceipt(line []byte) (Receipt, bool) {
	line = bytes.TrimSpace(line)
	if len(line) == 0 {
		return Receipt{}, false
	}
	var r Receipt
	if json.Unmarshal(line, &r) != nil || r.Decision == "" {
		return Receipt{}, false
	}
	return r, true
}

// Media is the newest image in a cast slot — the Now-Showing card.
type Media struct {
	Name    string `json:"name"`
	ModUnix int64  `json:"mod"`
}

// HomeSummary is the one-line hero: the numbers that answer "what is my mesh
// doing right now?". Pending is -1 when unknown (not surfaced to this caller).
type HomeSummary struct {
	PeersOnline int `json:"peers_online"`
	PeersTotal  int `json:"peers_total"`
	Sessions    int `json:"sessions"`
	Reachable   int `json:"reachable"`
	Pending     int `json:"pending"`
	Denies1h    int `json:"denies_1h"`
}

// Home is the aggregated live state of a mesh as one caller sees it.
type Home struct {
	Generated string         `json:"generated"` // RFC3339, when assembled
	You       PeerRow        `json:"you"`       // this node's own identity
	Peers     []PeerRow      `json:"peers"`     // reachable identities — Find My
	Sessions  []Session      `json:"sessions"`  // live resumable sessions
	Reachable []CatalogEntry `json:"reachable"` // backends I may reach (ARD catalog)
	Activity  []Receipt      `json:"activity"`  // newest-first ledger tail
	Showing   *Media         `json:"showing,omitempty"`
	Landed    int            `json:"landed"`  // images in the vision inbox
	Pending   int            `json:"pending"` // held approvals (-1 = unknown)
	Summary   HomeSummary    `json:"summary"` // the hero counts
}

// MarshalJSON emits the section slices as empty arrays rather than null when a
// surface is not wired, so a consumer (the page, a script) can iterate every
// section unconditionally — the home degrades section by section, never to a
// null that breaks a `.map`.
func (h Home) MarshalJSON() ([]byte, error) {
	type alias Home
	a := alias(h)
	if a.Peers == nil {
		a.Peers = []PeerRow{}
	}
	if a.Sessions == nil {
		a.Sessions = []Session{}
	}
	if a.Reachable == nil {
		a.Reachable = []CatalogEntry{}
	}
	if a.Activity == nil {
		a.Activity = []Receipt{}
	}
	return json.Marshal(a)
}

// denyWindow is the trailing span "denies in the last hour" counts over.
const denyWindow = time.Hour

// Summarize computes the hero counts from the assembled sections. Pure: the
// deny window is measured against Generated (the assembly instant), so the same
// Home always summarizes identically regardless of the wall clock.
func Summarize(h Home) HomeSummary {
	online := 0
	for _, p := range h.Peers {
		if p.Status == "connected" {
			online++
		}
	}
	return HomeSummary{
		PeersOnline: online,
		PeersTotal:  len(h.Peers),
		Sessions:    len(h.Sessions),
		Reachable:   len(h.Reachable),
		Pending:     h.Pending,
		Denies1h:    recentDenies(h),
	}
}

// recentDenies counts deny receipts within denyWindow of Generated. If Generated
// is unparseable, every deny in the tail is counted (a safe over-report).
func recentDenies(h Home) int {
	ref, err := time.Parse(time.RFC3339, h.Generated)
	haveRef := err == nil
	cutoff := ref.Add(-denyWindow)
	n := 0
	for _, r := range h.Activity {
		if r.Decision != "deny" {
			continue
		}
		if !haveRef {
			n++
			continue
		}
		t, err := time.Parse(time.RFC3339, r.Time)
		if err != nil {
			continue
		}
		if !t.Before(cutoff) {
			n++
		}
	}
	return n
}

// unit separates fields inside a signature line so two adjacent values can never
// collide into a third (e.g. "a"+"bc" vs "ab"+"c").
const unit = "\x1f"

// Signature is a cheap, stable fingerprint of the render-visible state, used by
// the terminal --watch loop to skip redraws when nothing changed — the server
// analog of the page's changed(el, sig). It excludes Generated (so a re-poll of
// identical state hashes identically) and a session's ticking age (age is
// derived from time, not a state change), and it sorts each section so source
// ordering never flips the hash.
func (h Home) Signature() string {
	var b strings.Builder
	line := func(parts ...string) {
		for _, p := range parts {
			b.WriteString(p)
			b.WriteString(unit)
		}
		b.WriteByte('\n')
	}

	line("you", h.You.Status, h.You.IP, h.You.FQDN, h.You.PubKey)

	peers := append([]PeerRow(nil), h.Peers...)
	sort.Slice(peers, func(i, j int) bool {
		if peers[i].PubKey != peers[j].PubKey {
			return peers[i].PubKey < peers[j].PubKey
		}
		return peers[i].FQDN < peers[j].FQDN
	})
	for _, p := range peers {
		line("peer", p.Status, p.IP, p.FQDN, p.PubKey)
	}

	sess := append([]Session(nil), h.Sessions...)
	sort.Slice(sess, func(i, j int) bool {
		if sess[i].Backend != sess[j].Backend {
			return sess[i].Backend < sess[j].Backend
		}
		return sess[i].ID < sess[j].ID
	})
	for _, s := range sess {
		line("session", s.Backend, s.ID, s.Peer)
	}

	reach := append([]CatalogEntry(nil), h.Reachable...)
	sort.Slice(reach, func(i, j int) bool {
		if reach[i].Name != reach[j].Name {
			return reach[i].Name < reach[j].Name
		}
		return reach[i].Address < reach[j].Address
	})
	for _, e := range reach {
		line("reach", e.Name, e.Address, e.Transport,
			strconv.FormatBool(e.Resumable), strconv.FormatBool(e.Steerable))
	}

	for _, r := range h.Activity {
		line("act", r.Time, r.Peer, r.Backend, r.Method, r.Tool, r.Decision)
	}

	if h.Showing != nil {
		line("show", h.Showing.Name, strconv.FormatInt(h.Showing.ModUnix, 10))
	}
	line("n", strconv.Itoa(h.Landed), strconv.Itoa(h.Pending))

	sum := fnv.New64a()
	sum.Write([]byte(b.String()))
	return strconv.FormatUint(sum.Sum64(), 16)
}
