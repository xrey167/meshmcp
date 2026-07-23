package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xrey167/meshmcp/air"
	"github.com/xrey167/meshmcp/session"
)

// controlClientFor serves h from a local httptest server and returns an
// http.Client shaped exactly like airControlHTTP's: the request URL's host is
// ignored and every dial lands on the served control endpoint.
func controlClientFor(t *testing.T, h http.Handler) *http.Client {
	t.Helper()
	ts := httptest.NewServer(h)
	t.Cleanup(ts.Close)
	u, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "tcp", u.Host)
			},
		},
	}
}

// TestAirSteerGroupFanoutSkipsAndDelivers proves the per-member binding rule is
// the single-target rule applied per member: a member with no identity-bound
// session and a member with several are skipped with exact reasons, the bound
// member is delivered, and exactly one steer reaches the endpoint.
func TestAirSteerGroupFanoutSkipsAndDelivers(t *testing.T) {
	c := &fakeAirControl{
		list: []AirSession{
			{Backend: "fs", ID: "b1", Peer: "builder.mesh", PeerKey: "KEY-B"},
			{Backend: "kg", ID: "b2", Peer: "builder.mesh", PeerKey: "KEY-B"},
			{Backend: "fs", ID: "c1", Peer: "curator.mesh", PeerKey: "KEY-C"},
		},
		groupPatterns: map[string][]string{
			"oncall": {"pubkey:KEY-A", "pubkey:KEY-B", "pubkey:KEY-C", "pubkey:KEY-GONE"},
		},
	}
	announceMember(t, c, "KEY-A", "analyst.mesh", "Analyst")
	announceMember(t, c, "KEY-B", "builder.mesh", "Builder")
	announceMember(t, c, "KEY-C", "curator.mesh", "Curator")
	hc := controlClientFor(t, newTestHandler(c, true))

	res, err := airSteerGroupFanout(context.Background(), hc, "oncall", "notifications/air/steer", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.UnmatchedPatterns) != 1 || res.UnmatchedPatterns[0] != "pubkey:KEY-GONE" {
		t.Fatalf("unmatched = %v", res.UnmatchedPatterns)
	}
	if res.Group != "oncall" || res.Action != air.FanoutActionSteer || len(res.Members) != 3 {
		t.Fatalf("result = %+v", res)
	}
	if m := res.Members[0]; m.Recipient.PublicKey != "KEY-A" || m.Status != air.FanoutSkipped || m.Reason != "no identity-bound live session" {
		t.Fatalf("member A = %+v", m)
	}
	if m := res.Members[1]; m.Recipient.PublicKey != "KEY-B" || m.Status != air.FanoutSkipped || m.Reason != "ambiguous (2 sessions)" {
		t.Fatalf("member B = %+v", m)
	}
	m := res.Members[2]
	if m.Recipient.PublicKey != "KEY-C" || m.Status != air.FanoutDelivered || m.Steer == nil {
		t.Fatalf("member C = %+v", m)
	}
	if m.Steer.Backend != "fs" || m.Steer.Session != "c1" || m.Steer.By != "caller.mesh" {
		t.Fatalf("member C steer detail = %+v", m.Steer)
	}
	if len(c.steers) != 1 || c.steers[0] != "fs/c1/notifications/air/steer" {
		t.Fatalf("exactly one steer must reach the endpoint: %v", c.steers)
	}
}

// TestAirSteerGroupFanoutUnknownGroup proves an undefined group is a hard error
// carrying the endpoint's wording, before any delivery.
func TestAirSteerGroupFanoutUnknownGroup(t *testing.T) {
	c := &fakeAirControl{groupPatterns: map[string][]string{"oncall": {"*"}}}
	hc := controlClientFor(t, newTestHandler(c, true))

	_, err := airSteerGroupFanout(context.Background(), hc, "ghost", "notifications/air/steer", nil)
	if err == nil || !strings.Contains(err.Error(), `group "ghost" is not defined in the gateway groups map`) {
		t.Fatalf("unknown group = %v", err)
	}
	if len(c.steers) != 0 {
		t.Fatalf("unknown group must deliver nothing: %v", c.steers)
	}
}

// TestAirSteerGroupFanoutEmptyGroupIsLoud proves a defined group with zero
// present members is a loud pre-delivery error — a no-op broadcast never
// pretends to have happened — echoing the patterns that matched nothing.
func TestAirSteerGroupFanoutEmptyGroupIsLoud(t *testing.T) {
	c := &fakeAirControl{groupPatterns: map[string][]string{
		"quiet":  {},
		"absent": {"pubkey:KEY-GONE"},
	}}
	hc := controlClientFor(t, newTestHandler(c, true))

	_, err := airSteerGroupFanout(context.Background(), hc, "quiet", "notifications/air/steer", nil)
	if err == nil || !strings.Contains(err.Error(), `group "quiet" has no members present`) {
		t.Fatalf("empty group = %v", err)
	}
	_, err = airSteerGroupFanout(context.Background(), hc, "absent", "notifications/air/steer", nil)
	if err == nil || !strings.Contains(err.Error(), `group "absent" has no members present`) || !strings.Contains(err.Error(), "pubkey:KEY-GONE") {
		t.Fatalf("all-unmatched group = %v", err)
	}
	if len(c.steers) != 0 {
		t.Fatalf("empty groups must deliver nothing: %v", c.steers)
	}
}

// TestAirSteerGroupFanoutAllDenied proves an endpoint 403 for every member
// still yields the full per-member list — each entry `denied` with the
// endpoint's own reason — and the exit-code contract reports zero delivered.
func TestAirSteerGroupFanoutAllDenied(t *testing.T) {
	c := &fakeAirControl{
		list: []AirSession{
			{Backend: "fs", ID: "a1", PeerKey: "KEY-A"},
			{Backend: "fs", ID: "b1", PeerKey: "KEY-B"},
		},
		err:           errBackendForbidden,
		groupPatterns: map[string][]string{"oncall": {"pubkey:KEY-A", "pubkey:KEY-B"}},
	}
	announceMember(t, c, "KEY-A", "analyst.mesh", "Analyst")
	announceMember(t, c, "KEY-B", "builder.mesh", "Builder")
	hc := controlClientFor(t, newTestHandler(c, true))

	res, err := airSteerGroupFanout(context.Background(), hc, "oncall", "notifications/air/steer", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Members) != 2 {
		t.Fatalf("full list required even when all denied: %+v", res.Members)
	}
	for i, m := range res.Members {
		if m.Status != air.FanoutDenied || !strings.Contains(m.Reason, "not permitted for this backend") {
			t.Fatalf("member %d = %+v", i, m)
		}
	}
	captureStdout(t, func() {
		var fe *fanoutExitError
		if rerr := reportFanout(res, false); !errors.As(rerr, &fe) || fe.code != 3 {
			t.Fatalf("all-denied exit = %v, want fanout exit 3", rerr)
		}
	})
}

// --- SACRED proof: per-member authority over real gateway machinery ---

// idleBackend keeps a live session's backend open without producing output.
type idleBackend struct {
	done chan struct{}
	once sync.Once
}

func (b *idleBackend) Read(p []byte) (int, error)  { <-b.done; return 0, context.Canceled }
func (b *idleBackend) Write(p []byte) (int, error) { return len(p), nil }
func (b *idleBackend) Close() error                { b.once.Do(func() { close(b.done) }); return nil }

// idleStream keeps the client half attached until the test cancels.
type idleStream struct{ ctx context.Context }

func (s idleStream) Read(p []byte) (int, error)  { <-s.ctx.Done(); return 0, context.Canceled }
func (s idleStream) Write(p []byte) (int, error) { return len(p), nil }
func (idleStream) Close() error                  { return nil }

// attachLiveSession attaches one real, resumable session to srv with the given
// transport identity and returns once it is visible in srv.Sessions().
func attachLiveSession(t *testing.T, ctx context.Context, srv *session.Server, fqdn, key string) {
	t.Helper()
	dial := func(context.Context) (net.Conn, error) {
		cc, sc := net.Pipe()
		go srv.Handle(sc, session.Meta{PeerFQDN: fqdn, PeerKey: key, PeerAddr: "100.64.0.9:1"})
		return cc, nil
	}
	go func() { _ = session.NewClient(dial, nil).Run(ctx, idleStream{ctx: ctx}) }()
	deadline := time.Now().Add(5 * time.Second)
	for srv.Count() == 0 {
		if time.Now().After(deadline) {
			t.Fatalf("session for %s never attached", fqdn)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestAirSteerGroupFanoutPerMemberAuthority is the SACRED proof over the real
// stack — airControlHandler + gatewayAirControl + air.Registry + live
// session.Servers: a group is name resolution only, so each fanned-out steer
// independently enters the target backend's OWN ACL. Backend beta's ACL is
// swapped to deny between the binding snapshot and delivery (the reload window
// the hot-swappable acl exists for); the fan-out then reports member A
// delivered and member B denied via the endpoint's errBackendForbidden — the
// loop continues past the denial — and the ledger holds one allow AND one deny
// steer record plus the air/groups resolution record. Per-member truth; no
// all-or-nothing.
func TestAirSteerGroupFanoutPerMemberAuthority(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	factory := func(session.Meta) (session.Backend, error) {
		return &idleBackend{done: make(chan struct{})}, nil
	}
	srvAlpha := session.NewServer(factory, time.Minute, nil)
	srvBeta := session.NewServer(factory, time.Minute, nil)
	attachLiveSession(t, ctx, srvAlpha, "member-a.mesh", "KEY-A")
	attachLiveSession(t, ctx, srvBeta, "member-b.mesh", "KEY-B")

	registry := air.NewRegistry(8)
	now := time.Now()
	for _, m := range []struct{ key, fqdn, name string }{
		{"KEY-A", "member-a.mesh", "Alpha Agent"},
		{"KEY-B", "member-b.mesh", "Beta Agent"},
	} {
		if _, _, err := registry.Upsert(air.VerifiedIdentity{PublicKey: m.key, FQDN: m.fqdn}, "100.64.0.8",
			air.Announcement{Name: m.name, Kind: air.NodeAgent, TTLSeconds: 90}, now); err != nil {
			t.Fatal(err)
		}
	}

	// The operator may reach the control endpoint and BOTH backends at
	// snapshot time; beta's ACL is swapped to deny before delivery.
	betaACL := newACL([]string{"pubkey:OPKEY"})
	gw := &gatewayAirControl{
		servers:       map[string]*session.Server{"alpha": srvAlpha, "beta": srvBeta},
		acls:          map[string]acl{"alpha": newACL([]string{"pubkey:OPKEY"}), "beta": betaACL},
		mu:            &sync.Mutex{},
		gateway:       "gw.mesh",
		presence:      registry,
		groupPatterns: map[string][]string{"oncall": {"pubkey:KEY-A", "pubkey:KEY-B"}},
	}

	var mu sync.Mutex
	var recs []airSteerAudit
	handler := airControlHandler(gw,
		func(*http.Request) (string, string) { return "OPKEY", "operator.mesh" },
		newACL([]string{"pubkey:OPKEY"}), newACL(nil),
		func(r airSteerAudit) { mu.Lock(); recs = append(recs, r); mu.Unlock() })
	hc := controlClientFor(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler.ServeHTTP(w, r)
		if r.URL.Path == "/v1/sessions" {
			// The binding snapshot has been served; now the operator loses
			// backend beta. Each subsequent steer must re-enter beta's own ACL
			// and be denied there — resolution never carried authority.
			betaACL.swap([]string{"pubkey:someone-else"})
		}
	}))

	res, err := airSteerGroupFanout(context.Background(), hc, "oncall", "notifications/air/steer", map[string]any{"text": "focus"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.UnmatchedPatterns) != 0 || len(res.Members) != 2 {
		t.Fatalf("result = %+v", res)
	}

	a, b := res.Members[0], res.Members[1] // registry order: Alpha Agent, Beta Agent
	if a.Recipient.PublicKey != "KEY-A" || a.Status != air.FanoutDelivered || a.Steer == nil || a.Steer.Backend != "alpha" || a.Steer.By != "operator.mesh" {
		t.Fatalf("member A = %+v (steer %+v)", a, a.Steer)
	}
	if got := srvAlpha.Sessions(); len(got) != 1 || a.Steer.Session != got[0].ID {
		t.Fatalf("member A steer must name the live session: %+v vs %+v", a.Steer, got)
	}
	if b.Recipient.PublicKey != "KEY-B" || b.Status != air.FanoutDenied || b.Reason != "not permitted for this backend" {
		t.Fatalf("member B = %+v", b)
	}

	// The ledger tells the same per-member truth: one air/groups resolution
	// record, one allow steer on alpha, one deny steer on beta.
	mu.Lock()
	defer mu.Unlock()
	var groupsRecs, allowSteers, denySteers []airSteerAudit
	for _, r := range recs {
		switch {
		case r.Method == "air/groups":
			groupsRecs = append(groupsRecs, r)
		case r.Method == "notifications/air/steer" && r.OK:
			allowSteers = append(allowSteers, r)
		case r.Method == "notifications/air/steer" && !r.OK:
			denySteers = append(denySteers, r)
		}
	}
	if len(groupsRecs) != 1 || !groupsRecs[0].OK || groupsRecs[0].Session != "oncall" {
		t.Fatalf("air/groups resolution audit = %+v", groupsRecs)
	}
	if len(allowSteers) != 1 || allowSteers[0].Backend != "alpha" {
		t.Fatalf("allow steer audit = %+v", allowSteers)
	}
	if len(denySteers) != 1 || denySteers[0].Backend != "beta" {
		t.Fatalf("deny steer audit = %+v", denySteers)
	}

	// Receipt truthfulness: the partial fan-out reports exit 2 and the
	// envelope itself carries no aggregate verdict a UI could misread.
	captureStdout(t, func() {
		var fe *fanoutExitError
		if rerr := reportFanout(res, false); !errors.As(rerr, &fe) || fe.code != 2 {
			t.Fatalf("partial fan-out exit = %v, want fanout exit 2", rerr)
		}
	})
	if err := res.Validate(); err != nil {
		t.Fatalf("fanout envelope invalid: %v", err)
	}
}

// --- trust boundary: tampered control replies never reach the delivery loop ---

// TestAirSteerGroupFanoutRefusesOversizeRosterBeforeDelivery proves the
// envelope bound is a PRE-delivery gate on the client too: a tampered or buggy
// control endpoint returning a roster wider than air.MaxFanoutMembers (a
// compliant gateway 422s instead) is refused loudly at the trust boundary and
// NOT ONE /v1/steer POST is sent — the amplification and the report collapse
// the finding described can no longer happen.
func TestAirSteerGroupFanoutRefusesOversizeRosterBeforeDelivery(t *testing.T) {
	wide := airGroupMembers{Name: "wide", Members: []air.Presence{}, UnmatchedPatterns: []string{}}
	for i := 0; i < maxGroupMembers+1; i++ {
		wide.Members = append(wide.Members, air.Presence{Name: nameN(i), FQDN: fqdnN(i), PublicKey: keyN(i)})
	}
	var steers atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/groups", func(w http.ResponseWriter, r *http.Request) {
		writeJSONResp(w, http.StatusOK, airGroupsReply{Schema: airGroupsSchemaV1, Groups: []airGroupMembers{wide}, You: "caller.mesh"})
	})
	mux.HandleFunc("/v1/sessions", func(w http.ResponseWriter, r *http.Request) {
		writeJSONResp(w, http.StatusOK, map[string]any{"sessions": []AirSession{}})
	})
	mux.HandleFunc("/v1/steer", func(w http.ResponseWriter, r *http.Request) {
		steers.Add(1)
		writeJSONResp(w, http.StatusOK, map[string]any{"status": "steered"})
	})
	hc := controlClientFor(t, mux)

	_, err := airSteerGroupFanout(context.Background(), hc, "wide", "notifications/air/steer", nil)
	if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("resolves to %d members (max %d)", maxGroupMembers+1, maxGroupMembers)) {
		t.Fatalf("oversize roster = %v, want loud pre-delivery refusal", err)
	}
	if n := steers.Load(); n != 0 {
		t.Fatalf("an oversize roster must deliver NOTHING, yet %d steer POST(s) were sent", n)
	}
}

// TestFetchAirGroupTrustBoundary proves a tampered 200 reply is refused when
// it is parsed: a member card the result envelope could not carry, an
// envelope-unsafe unmatched-pattern echo, or a smuggled per-group error entry
// all fail the fetch — before any fan-out loop can start from bad data.
func TestFetchAirGroupTrustBoundary(t *testing.T) {
	serve := func(g airGroupMembers) *http.Client {
		mux := http.NewServeMux()
		mux.HandleFunc("/v1/groups", func(w http.ResponseWriter, r *http.Request) {
			writeJSONResp(w, http.StatusOK, airGroupsReply{Schema: airGroupsSchemaV1, Groups: []airGroupMembers{g}})
		})
		return controlClientFor(t, mux)
	}
	card := func(key string) air.Presence { return air.Presence{Name: "N", FQDN: key + ".mesh", PublicKey: key} }

	tests := []struct {
		name string
		g    airGroupMembers
		want string
	}{
		{"member card without a public key",
			airGroupMembers{Name: "g", Members: []air.Presence{card("KEY-A"), {Name: "ghost"}}},
			"member card #2"},
		{"member card with a control-character name",
			airGroupMembers{Name: "g", Members: []air.Presence{{Name: "bad\x1bname", PublicKey: "KEY-A"}}},
			"control character"},
		{"envelope-unsafe unmatched pattern",
			airGroupMembers{Name: "g", Members: []air.Presence{card("KEY-A")}, UnmatchedPatterns: []string{"gh\x1bost.*"}},
			"unmatched pattern #1"},
		{"smuggled per-group error entry",
			airGroupMembers{Name: "g", Members: []air.Presence{card("KEY-A")}, Error: "upstream says no"},
			"upstream says no"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := fetchAirGroup(context.Background(), serve(tc.g), "g")
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("tampered roster = %v, want error containing %q", err, tc.want)
			}
		})
	}
}

// TestSteerGroupMemberBindingAndConfirmationTruth pins two per-member truths
// against untrusted server data: a 200 confirmation missing its session id
// (or carrying envelope-unsafe text) falls back to the identity-bound pair
// that was ACTUALLY posted — still delivered, reported with our truth — and a
// binding-snapshot row the envelope could not carry is skipped BEFORE any
// POST is sent.
func TestSteerGroupMemberBindingAndConfirmationTruth(t *testing.T) {
	card := air.Presence{Name: "Analyst", FQDN: "analyst.mesh", PublicKey: "KEY-A"}
	sessions := []AirSession{{Backend: "fs", ID: "9f2a", Peer: "analyst.mesh", PeerKey: "KEY-A"}}
	serve := func(body string) (*http.Client, *atomic.Int32) {
		posts := new(atomic.Int32)
		mux := http.NewServeMux()
		mux.HandleFunc("/v1/steer", func(w http.ResponseWriter, r *http.Request) {
			posts.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(body))
		})
		return controlClientFor(t, mux), posts
	}

	t.Run("200 with backend but no id falls back to the bound pair", func(t *testing.T) {
		hc, posts := serve(`{"status":"steered","backend":"fs"}`)
		m := steerGroupMember(context.Background(), hc, card, sessions, "notifications/air/steer", nil)
		if m.Status != air.FanoutDelivered || m.Steer == nil ||
			m.Steer.Backend != "fs" || m.Steer.Session != "9f2a" || m.Steer.By != "" {
			t.Fatalf("member = %+v (steer %+v)", m, m.Steer)
		}
		if n := posts.Load(); n != 1 {
			t.Fatalf("posts = %d, want exactly 1", n)
		}
	})

	t.Run("200 with envelope-unsafe confirmation falls back to the bound pair", func(t *testing.T) {
		hc, _ := serve("{\"status\":\"steered\",\"backend\":\"f\\u0001s\",\"id\":\"x\",\"by\":\"evil\"}")
		m := steerGroupMember(context.Background(), hc, card, sessions, "notifications/air/steer", nil)
		if m.Status != air.FanoutDelivered || m.Steer == nil ||
			m.Steer.Backend != "fs" || m.Steer.Session != "9f2a" || m.Steer.By != "" {
			t.Fatalf("member = %+v (steer %+v)", m, m.Steer)
		}
	})

	t.Run("unusable binding row is skipped before any POST", func(t *testing.T) {
		hc, posts := serve(`{"status":"steered"}`)
		bad := []AirSession{{Backend: "fs", ID: "bad\x01id", Peer: "analyst.mesh", PeerKey: "KEY-A"}}
		m := steerGroupMember(context.Background(), hc, card, bad, "notifications/air/steer", nil)
		if m.Status != air.FanoutSkipped || !strings.Contains(m.Reason, "unusable session binding") {
			t.Fatalf("member = %+v", m)
		}
		if n := posts.Load(); n != 0 {
			t.Fatalf("an unusable binding must never be POSTed, got %d", n)
		}
	})
}
