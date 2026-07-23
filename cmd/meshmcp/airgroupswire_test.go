package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/xrey167/meshmcp/air"
)

// announceMember stamps one present card into the fake controller's registry —
// through the same Upsert the live gateway uses, so tests exercise real
// identity-stamped cards, not hand-built ones.
func announceMember(t *testing.T, c *fakeAirControl, key, fqdn, name string, services ...air.Service) {
	t.Helper()
	if _, _, err := c.announce(key, fqdn, "100.64.0.8", air.Announcement{
		Name: name, Kind: air.NodeAgent, TTLSeconds: 90, Services: services,
	}, time.Now()); err != nil {
		t.Fatalf("announce %s: %v", name, err)
	}
}

// TestAirGroupsWire covers GET /v1/groups end to end through the real handler:
// the gate is exactly /v1/sessions' (default-deny on an empty allow, explicit
// allow required), the reply embeds full member cards plus unmatched patterns
// from one snapshot, unknown names 404 with the F17 wording, and every request
// — allowed or denied — appends exactly one air/groups audit record.
func TestAirGroupsWire(t *testing.T) {
	newFake := func() *fakeAirControl {
		c := &fakeAirControl{groupPatterns: map[string][]string{
			"oncall": {"pubkey:KEY-A", "pubkey:KEY-GONE"},
			"quiet":  {},
		}}
		announceMember(t, c, "KEY-A", "analyst.mesh", "Analyst", air.Service{Kind: air.ServiceRing, Port: 9120})
		return c
	}

	t.Run("empty control allow fails closed and is audited as deny", func(t *testing.T) {
		c := newFake()
		var recs []airSteerAudit
		h := airControlHandler(c,
			func(*http.Request) (string, string) { return "key1", "caller.mesh" },
			newACL(nil), newACL(nil),
			func(r airSteerAudit) { recs = append(recs, r) })
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/groups?name=oncall", nil))
		if rr.Code != http.StatusForbidden {
			t.Fatalf("empty allow = %d, want 403", rr.Code)
		}
		if len(recs) != 1 || recs[0].Method != "air/groups" || recs[0].OK || recs[0].Session != "oncall" {
			t.Fatalf("deny not audited: %+v", recs)
		}
	})

	t.Run("caller off the allow list is refused", func(t *testing.T) {
		rr := httptest.NewRecorder()
		newTestHandler(newFake(), false).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/groups", nil))
		if rr.Code != http.StatusForbidden {
			t.Fatalf("disallowed caller = %d, want 403", rr.Code)
		}
	})

	t.Run("GET only", func(t *testing.T) {
		rr := httptest.NewRecorder()
		newTestHandler(newFake(), true).ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/v1/groups", strings.NewReader("{}")))
		if rr.Code != http.StatusMethodNotAllowed {
			t.Fatalf("POST /v1/groups = %d, want 405", rr.Code)
		}
	})

	t.Run("unknown group is 404 with the groups-map wording", func(t *testing.T) {
		c := newFake()
		var recs []airSteerAudit
		h := handlerWithIdentity(c, "opkey", "operator.mesh", func(r airSteerAudit) { recs = append(recs, r) })
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/groups?name=ghost", nil))
		if rr.Code != http.StatusNotFound {
			t.Fatalf("unknown group = %d, want 404: %s", rr.Code, rr.Body)
		}
		if got := strings.TrimSpace(rr.Body.String()); got != `group "ghost" is not defined in the gateway groups map` {
			t.Fatalf("wording = %q", got)
		}
		if len(recs) != 1 || recs[0].Method != "air/groups" || recs[0].OK {
			t.Fatalf("failed resolution not audited: %+v", recs)
		}
	})

	t.Run("resolved roster embeds member cards and unmatched patterns", func(t *testing.T) {
		c := newFake()
		var recs []airSteerAudit
		h := handlerWithIdentity(c, "opkey", "operator.mesh", func(r airSteerAudit) { recs = append(recs, r) })
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/groups?name=oncall", nil))
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d: %s", rr.Code, rr.Body)
		}
		var out airGroupsReply
		if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
			t.Fatalf("bad json: %v", err)
		}
		if out.Schema != airGroupsSchemaV1 || out.You != "operator.mesh" || len(out.Groups) != 1 {
			t.Fatalf("envelope = %+v", out)
		}
		g := out.Groups[0]
		if g.Name != "oncall" || len(g.Members) != 1 {
			t.Fatalf("group = %+v", g)
		}
		// The embedded card is the full identity-stamped Presence: the key for
		// steer binding and the advertised service address for ring, from ONE
		// atomic snapshot.
		m := g.Members[0]
		if m.PublicKey != "KEY-A" || m.FQDN != "analyst.mesh" || len(m.Services) != 1 || m.Services[0].Address != "100.64.0.8:9120" {
			t.Fatalf("member card = %+v", m)
		}
		if len(g.UnmatchedPatterns) != 1 || g.UnmatchedPatterns[0] != "pubkey:KEY-GONE" {
			t.Fatalf("unmatched = %v", g.UnmatchedPatterns)
		}
		if len(recs) != 1 || recs[0].Method != "air/groups" || !recs[0].OK || recs[0].Session != "oncall" {
			t.Fatalf("resolution not audited exactly once: %+v", recs)
		}
	})

	t.Run("defined-but-empty group resolves to zero members, not an error", func(t *testing.T) {
		// The WIRE returns the honest empty roster; refusing to deliver into it
		// is the CLIENT's loud no-op (emptyGroupError), tested with the fan-out.
		rr := httptest.NewRecorder()
		newTestHandler(newFake(), true).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/groups?name=quiet", nil))
		if rr.Code != http.StatusOK {
			t.Fatalf("empty group = %d: %s", rr.Code, rr.Body)
		}
		var out airGroupsReply
		if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil || len(out.Groups) != 1 {
			t.Fatalf("reply = %+v, %v", out, err)
		}
		if len(out.Groups[0].Members) != 0 || len(out.Groups[0].UnmatchedPatterns) != 0 {
			t.Fatalf("quiet group = %+v", out.Groups[0])
		}
	})

	t.Run("oversize resolution is 422, never a truncated roster", func(t *testing.T) {
		c := &fakeAirControl{
			presence:      air.NewRegistry(2 * maxGroupMembers),
			groupPatterns: map[string][]string{"wide": {"*"}},
		}
		for i := 0; i < maxGroupMembers+1; i++ {
			announceMember(t, c, keyN(i), fqdnN(i), nameN(i))
		}
		rr := httptest.NewRecorder()
		newTestHandler(c, true).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/groups?name=wide", nil))
		if rr.Code != http.StatusUnprocessableEntity {
			t.Fatalf("oversize = %d, want 422: %s", rr.Code, rr.Body)
		}
		if !strings.Contains(rr.Body.String(), "resolves to 65 members (max 64)") {
			t.Fatalf("oversize wording = %q", rr.Body.String())
		}
	})

	t.Run("unfiltered listing reports an over-wide group as its own error entry", func(t *testing.T) {
		// One wide group must not abort every OTHER group's truth in the
		// list-all form: the wide group becomes a loud zero-member error entry
		// (never a truncated subset) while the rest of the listing survives.
		// The named form above keeps its whole-request 422.
		c := &fakeAirControl{
			presence: air.NewRegistry(2 * maxGroupMembers),
			groupPatterns: map[string][]string{
				"wide":   {"*"},
				"oncall": {"pubkey:" + keyN(0)},
			},
		}
		for i := 0; i < maxGroupMembers+1; i++ {
			announceMember(t, c, keyN(i), fqdnN(i), nameN(i))
		}
		rr := httptest.NewRecorder()
		newTestHandler(c, true).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/groups", nil))
		if rr.Code != http.StatusOK {
			t.Fatalf("list-all with a wide group = %d, want 200: %s", rr.Code, rr.Body)
		}
		var out airGroupsReply
		if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil || len(out.Groups) != 2 {
			t.Fatalf("reply = %+v, %v", out, err)
		}
		oncall, wide := out.Groups[0], out.Groups[1] // sorted by name
		if oncall.Name != "oncall" || oncall.Error != "" || len(oncall.Members) != 1 {
			t.Fatalf("healthy group harmed by its wide neighbour: %+v", oncall)
		}
		if wide.Name != "wide" || len(wide.Members) != 0 ||
			!strings.Contains(wide.Error, "resolves to 65 members (max 64)") {
			t.Fatalf("wide group entry = %+v", wide)
		}
	})
}

func keyN(i int) string  { return "KEY-" + string(rune('A'+i/26)) + string(rune('A'+i%26)) }
func fqdnN(i int) string { return "node-" + keyN(i) + ".mesh" }
func nameN(i int) string { return "Node " + keyN(i) }
