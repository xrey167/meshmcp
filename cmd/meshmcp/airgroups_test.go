package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/xrey167/meshmcp/air"
)

func ringCard(name, fqdn, key, address string) air.Presence {
	return air.Presence{
		Name: name, FQDN: fqdn, PublicKey: key,
		Services: []air.Service{{Kind: air.ServiceRing, Port: 9120, Address: address}},
	}
}

// TestResolveGroupMembers proves the server-side join uses the acl pattern
// language (pubkey exact, FQDN glob, "*"), dedupes by key, keeps the snapshot's
// deterministic order, and echoes patterns that matched no present card.
func TestResolveGroupMembers(t *testing.T) {
	cards := []air.Presence{
		{Name: "Analyst", FQDN: "analyst.mesh", PublicKey: "KEY-A"},
		{Name: "Builder", FQDN: "builder.mesh", PublicKey: "KEY-B"},
		{Name: "Curator", FQDN: "curator.lab.mesh", PublicKey: "KEY-C"},
	}

	t.Run("pubkey exact and fqdn glob", func(t *testing.T) {
		out, err := resolveGroupMembers("oncall", []string{"pubkey:KEY-A", "builder.*"}, cards)
		if err != nil {
			t.Fatal(err)
		}
		if len(out.Members) != 2 || out.Members[0].PublicKey != "KEY-A" || out.Members[1].PublicKey != "KEY-B" {
			t.Fatalf("unexpected members: %+v", out.Members)
		}
		if len(out.UnmatchedPatterns) != 0 {
			t.Fatalf("unexpected unmatched: %v", out.UnmatchedPatterns)
		}
	})

	t.Run("star matches every present card", func(t *testing.T) {
		out, err := resolveGroupMembers("all", []string{"*"}, cards)
		if err != nil || len(out.Members) != 3 {
			t.Fatalf("star match = %+v, %v", out.Members, err)
		}
	})

	t.Run("suffix glob selects like acl.allows", func(t *testing.T) {
		// Same path.Match semantics as the acl language: "*.lab.mesh" selects
		// curator.lab.mesh and neither of the plain .mesh nodes.
		out, err := resolveGroupMembers("lab", []string{"*.lab.mesh"}, cards)
		if err != nil || len(out.Members) != 1 || out.Members[0].PublicKey != "KEY-C" {
			t.Fatalf("glob = %+v, %v", out.Members, err)
		}
	})

	t.Run("dedupe by key when two patterns match one card", func(t *testing.T) {
		out, err := resolveGroupMembers("dup", []string{"pubkey:KEY-A", "analyst.mesh"}, cards)
		if err != nil || len(out.Members) != 1 || out.Members[0].PublicKey != "KEY-A" {
			t.Fatalf("dedupe failed: %+v, %v", out.Members, err)
		}
	})

	t.Run("unmatched patterns echoed, never silent", func(t *testing.T) {
		out, err := resolveGroupMembers("g", []string{"pubkey:KEY-A", "pubkey:KEY-GONE", "ghost.*"}, cards)
		if err != nil {
			t.Fatal(err)
		}
		if len(out.Members) != 1 {
			t.Fatalf("members: %+v", out.Members)
		}
		if len(out.UnmatchedPatterns) != 2 || out.UnmatchedPatterns[0] != "pubkey:KEY-GONE" || out.UnmatchedPatterns[1] != "ghost.*" {
			t.Fatalf("unmatched: %v", out.UnmatchedPatterns)
		}
	})

	t.Run("empty pubkey pattern never matches an empty key", func(t *testing.T) {
		out, err := resolveGroupMembers("g", []string{"pubkey:"}, []air.Presence{{Name: "X", PublicKey: ""}})
		if err != nil || len(out.Members) != 0 || len(out.UnmatchedPatterns) != 1 {
			t.Fatalf("pubkey: with empty key must not match: %+v, %v", out, err)
		}
	})

	t.Run("oversize resolution refused loudly, never truncated", func(t *testing.T) {
		var wide []air.Presence
		for i := 0; i < maxGroupMembers+1; i++ {
			wide = append(wide, air.Presence{Name: fmt.Sprintf("n%03d", i), PublicKey: fmt.Sprintf("K%03d", i)})
		}
		_, err := resolveGroupMembers("wide", []string{"*"}, wide)
		var oversize *oversizeGroupError
		if !errors.As(err, &oversize) {
			t.Fatalf("oversize group = %v, want oversizeGroupError", err)
		}
		want := fmt.Sprintf("group %q resolves to %d members (max %d)", "wide", maxGroupMembers+1, maxGroupMembers)
		if err.Error() != want {
			t.Fatalf("error = %q, want %q", err, want)
		}
	})
}

func TestResolveGroupsReply(t *testing.T) {
	groups := map[string][]string{
		"oncall": {"pubkey:KEY-A"},
		"lab":    {"*.lab.mesh"},
	}
	cards := []air.Presence{{Name: "Analyst", FQDN: "analyst.mesh", PublicKey: "KEY-A"}}

	t.Run("unknown group is a typed 404 with the F17 wording", func(t *testing.T) {
		_, err := resolveGroupsReply(groups, cards, "ghost")
		var unknown *unknownGroupError
		if !errors.As(err, &unknown) {
			t.Fatalf("unknown group = %v, want unknownGroupError", err)
		}
		if err.Error() != `group "ghost" is not defined in the gateway groups map` {
			t.Fatalf("wording = %q", err)
		}
	})

	t.Run("one group by name", func(t *testing.T) {
		reply, err := resolveGroupsReply(groups, cards, "oncall")
		if err != nil || reply.Schema != airGroupsSchemaV1 || len(reply.Groups) != 1 || reply.Groups[0].Name != "oncall" {
			t.Fatalf("reply = %+v, %v", reply, err)
		}
	})

	t.Run("all groups sorted by name", func(t *testing.T) {
		reply, err := resolveGroupsReply(groups, cards, "")
		if err != nil || len(reply.Groups) != 2 || reply.Groups[0].Name != "lab" || reply.Groups[1].Name != "oncall" {
			t.Fatalf("reply = %+v, %v", reply, err)
		}
	})
}

func TestParseGroupSelector(t *testing.T) {
	for _, s := range []string{"analyst", "analyst.mesh", "pubkey:KEY-A", "100.64.0.8:9120", ""} {
		if name, ok, err := parseGroupSelector(s); ok || err != nil || name != "" {
			t.Fatalf("parseGroupSelector(%q) = %q, %v, %v; want non-group passthrough", s, name, ok, err)
		}
	}
	if name, ok, err := parseGroupSelector("group:oncall"); !ok || err != nil || name != "oncall" {
		t.Fatalf("group:oncall = %q, %v, %v", name, ok, err)
	}
	if name, ok, err := parseGroupSelector("  group:oncall  "); !ok || err != nil || name != "oncall" {
		t.Fatalf("padded group selector = %q, %v, %v", name, ok, err)
	}
	for _, bad := range []string{
		"group:",
		"group: oncall",
		"group:on:call",
		"group:on\x1bcall",
		"group:" + strings.Repeat("g", air.MaxGroupNameBytes+1),
	} {
		if _, ok, err := parseGroupSelector(bad); !ok || err == nil {
			t.Fatalf("parseGroupSelector(%q) = %v, %v; want group syntax with an error", bad, ok, err)
		}
	}
}

func TestResolveAirGroupMembersHardErrorsAndSkips(t *testing.T) {
	ctx := context.Background()
	roster := func(members []air.Presence, unmatched ...string) airGroupSource {
		return func(context.Context, string) (airGroupMembers, error) {
			return airGroupMembers{Name: "oncall", Members: members, UnmatchedPatterns: unmatched}, nil
		}
	}

	if _, _, err := resolveAirGroupMembers(ctx, "oncall", "", air.ServiceRing, roster(nil)); err == nil || !strings.Contains(err.Error(), "requires --control") {
		t.Fatalf("missing control = %v", err)
	}
	if _, _, err := resolveAirGroupMembers(ctx, "oncall", "not-an-addr", air.ServiceRing, roster(nil)); err == nil || !strings.Contains(err.Error(), "not a valid host:port") {
		t.Fatalf("bad control = %v", err)
	}
	if _, _, err := resolveAirGroupMembers(ctx, "oncall", "100.64.0.1:9120", air.ServiceRing, nil); err == nil || !strings.Contains(err.Error(), "resolver is unavailable") {
		t.Fatalf("nil source = %v", err)
	}
	failing := func(context.Context, string) (airGroupMembers, error) {
		return airGroupMembers{}, errors.New("boom")
	}
	if _, _, err := resolveAirGroupMembers(ctx, "oncall", "100.64.0.1:9120", air.ServiceRing, failing); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("source error = %v", err)
	}

	// Empty resolution is a loud pre-delivery error, echoing what matched nothing.
	_, _, err := resolveAirGroupMembers(ctx, "oncall", "100.64.0.1:9120", air.ServiceRing, roster(nil, "pubkey:KEY-GONE"))
	if err == nil || !strings.Contains(err.Error(), `group "oncall" has no members present`) || !strings.Contains(err.Error(), "pubkey:KEY-GONE") {
		t.Fatalf("empty group = %v", err)
	}

	// Per-member skips: missing service and invalid advertised address never
	// abort the others.
	members, unmatched, err := resolveAirGroupMembers(ctx, "oncall", "100.64.0.1:9120", air.ServiceRing, roster([]air.Presence{
		ringCard("Analyst", "analyst.mesh", "KEY-A", "100.64.0.8:9120"),
		{Name: "Builder", FQDN: "builder.mesh", PublicKey: "KEY-B"},
		ringCard("Curator", "curator.mesh", "KEY-C", "not-an-addr"),
	}, "ghost.*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(unmatched) != 1 || unmatched[0] != "ghost.*" {
		t.Fatalf("unmatched = %v", unmatched)
	}
	if len(members) != 3 {
		t.Fatalf("members = %+v", members)
	}
	if members[0].SkipReason != "" || members[0].Address != "100.64.0.8:9120" {
		t.Fatalf("valid member mis-resolved: %+v", members[0])
	}
	if members[1].SkipReason != `no "ring" service advertised` {
		t.Fatalf("missing-service skip = %q", members[1].SkipReason)
	}
	if members[2].SkipReason != "invalid advertised address" || members[2].Address != "" {
		t.Fatalf("invalid-address skip = %+v", members[2])
	}

	// An over-wide roster is refused BEFORE any delivery, whatever the source
	// injected it — the envelope bound is a pre-delivery gate, never a
	// post-delivery surprise.
	var wide []air.Presence
	for i := 0; i < maxGroupMembers+1; i++ {
		wide = append(wide, air.Presence{Name: nameN(i), FQDN: fqdnN(i), PublicKey: keyN(i)})
	}
	_, _, err = resolveAirGroupMembers(ctx, "oncall", "100.64.0.1:9120", air.ServiceRing, roster(wide))
	var oversize *oversizeGroupError
	if !errors.As(err, &oversize) || !strings.Contains(err.Error(), fmt.Sprintf("resolves to %d members (max %d)", maxGroupMembers+1, maxGroupMembers)) {
		t.Fatalf("oversize roster = %v, want loud oversizeGroupError", err)
	}

	// A member card whose identity the result envelope cannot carry is a hard
	// pre-delivery error: every entry (even a skip) embeds that identity.
	_, _, err = resolveAirGroupMembers(ctx, "oncall", "100.64.0.1:9120", air.ServiceRing, roster([]air.Presence{{Name: "ghost"}}))
	if err == nil || !strings.Contains(err.Error(), "bad member card") {
		t.Fatalf("keyless card = %v", err)
	}

	// An address that parses as host:port but could not ride in the envelope
	// (control character in the host) is that member's own skip — decided
	// before dialing, so it can never invalidate the finished envelope.
	members, _, err = resolveAirGroupMembers(ctx, "oncall", "100.64.0.1:9120", air.ServiceRing, roster([]air.Presence{
		ringCard("Analyst", "analyst.mesh", "KEY-A", "bad\x01host:9120"),
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(members) != 1 || members[0].SkipReason != "invalid advertised address" || members[0].Address != "" {
		t.Fatalf("ctrl-char address = %+v", members[0])
	}
}

// TestRingGroupFanout proves a delivery failure becomes that member's own
// `failed` entry with a bounded reason while the other members still deliver,
// and a skipped member is never dialed at all.
func TestRingGroupFanout(t *testing.T) {
	members := []groupMember{
		{Presence: ringCard("Analyst", "analyst.mesh", "KEY-A", "100.64.0.8:9120"), Address: "100.64.0.8:9120"},
		{Presence: air.Presence{Name: "Builder", FQDN: "builder.mesh", PublicKey: "KEY-B"}, SkipReason: `no "ring" service advertised`},
		{Presence: ringCard("Curator", "curator.mesh", "KEY-C", "100.64.0.9:9120"), Address: "100.64.0.9:9120"},
	}
	var dialed []string
	deliver := func(_ context.Context, addr string) error {
		dialed = append(dialed, addr)
		if addr == "100.64.0.9:9120" {
			return errors.New("dial tcp: connection refused\nafter 2 attempts")
		}
		return nil
	}
	res, err := ringGroupFanout(context.Background(), "oncall", members, []string{"ghost.*"}, deliver)
	if err != nil {
		t.Fatal(err)
	}
	if len(dialed) != 2 || dialed[0] != "100.64.0.8:9120" || dialed[1] != "100.64.0.9:9120" {
		t.Fatalf("skipped member must not be dialed: %v", dialed)
	}
	if res.Action != air.FanoutActionRing || len(res.Members) != 3 {
		t.Fatalf("result = %+v", res)
	}
	if len(res.UnmatchedPatterns) != 1 || res.UnmatchedPatterns[0] != "ghost.*" {
		t.Fatalf("unmatched echo lost from the envelope: %v", res.UnmatchedPatterns)
	}
	if res.Members[0].Status != air.FanoutDelivered || res.Members[0].Recipient.Address != "100.64.0.8:9120" {
		t.Fatalf("member 0 = %+v", res.Members[0])
	}
	if res.Members[1].Status != air.FanoutSkipped || res.Members[1].Reason != `no "ring" service advertised` {
		t.Fatalf("member 1 = %+v", res.Members[1])
	}
	if res.Members[2].Status != air.FanoutFailed || res.Members[2].Reason != "dial tcp: connection refused after 2 attempts" {
		t.Fatalf("member 2 = %+v", res.Members[2])
	}
}

func TestSingleLineReason(t *testing.T) {
	if got := singleLineReason("line one\r\nline\ttwo"); got != "line one line two" {
		t.Fatalf("newline fold = %q", got)
	}
	if got := singleLineReason("\x1b[31mred\x1b[0m"); strings.ContainsAny(got, "\x1b\n\r") {
		t.Fatalf("escape not neutralized: %q", got)
	}
	if got := singleLineReason("   "); got != "unknown error" {
		t.Fatalf("blank reason = %q", got)
	}
	long := strings.Repeat("é", air.MaxFanoutReasonBytes) // 2 bytes per rune
	got := singleLineReason(long)
	if len(got) > air.MaxFanoutReasonBytes {
		t.Fatalf("reason not bounded: %d bytes", len(got))
	}
	if !strings.HasSuffix(got, "é") {
		t.Fatalf("trim split a rune: %q...", got[len(got)-8:])
	}
}

// TestReportFanoutExitCodes pins the CLI contract: nil only when every resolved
// member delivered, exit 2 for a partial fan-out, exit 3 when nothing was
// delivered — and the full member list is emitted in every case.
func TestReportFanoutExitCodes(t *testing.T) {
	member := func(key string, status air.FanoutStatus, reason string) air.FanoutMember {
		m := air.FanoutMember{Recipient: air.FanoutRecipient{FQDN: key + ".mesh", PublicKey: key}, Status: status, Reason: reason}
		if status == air.FanoutDelivered {
			m.Steer = &air.FanoutSteer{Backend: "fs", Session: "9f2a"}
		}
		return m
	}
	mustResult := func(unmatched []string, members ...air.FanoutMember) air.FanoutResult {
		res, err := air.NewFanoutResult("oncall", air.FanoutActionSteer, members, unmatched)
		if err != nil {
			t.Fatal(err)
		}
		return res
	}

	t.Run("all delivered is the only nil", func(t *testing.T) {
		out := captureStdout(t, func() {
			if err := reportFanout(mustResult(nil, member("KEY-A", air.FanoutDelivered, "")), false); err != nil {
				t.Fatalf("all-delivered = %v", err)
			}
		})
		if !strings.Contains(out, "steered fs/9f2a") {
			t.Fatalf("member line missing: %q", out)
		}
	})

	t.Run("partial is exit 2 with the full list", func(t *testing.T) {
		out := captureStdout(t, func() {
			err := reportFanout(mustResult(nil,
				member("KEY-A", air.FanoutDelivered, ""),
				member("KEY-B", air.FanoutDenied, "not permitted for this backend"),
			), false)
			var fe *fanoutExitError
			if !errors.As(err, &fe) || fe.code != 2 || !strings.Contains(err.Error(), "partial delivery (1 of 2 members)") {
				t.Fatalf("partial = %v", err)
			}
		})
		if !strings.Contains(out, "denied KEY-B.mesh: not permitted for this backend") {
			t.Fatalf("denied member line missing: %q", out)
		}
	})

	t.Run("zero delivered is exit 3", func(t *testing.T) {
		captureStdout(t, func() {
			err := reportFanout(mustResult(nil,
				member("KEY-A", air.FanoutSkipped, "no identity-bound live session"),
				member("KEY-B", air.FanoutFailed, "connection refused"),
			), false)
			var fe *fanoutExitError
			if !errors.As(err, &fe) || fe.code != 3 {
				t.Fatalf("zero-delivered = %v", err)
			}
		})
	})

	t.Run("json emits the envelope verbatim and keeps the exit contract", func(t *testing.T) {
		res := mustResult([]string{"ghost.*"},
			member("KEY-A", air.FanoutDelivered, ""),
			member("KEY-B", air.FanoutDenied, "not permitted for this backend"),
		)
		var fe *fanoutExitError
		out := captureStdout(t, func() {
			err := reportFanout(res, true)
			if !errors.As(err, &fe) || fe.code != 2 {
				t.Fatalf("json partial = %v", err)
			}
		})
		var back air.FanoutResult
		if err := json.Unmarshal([]byte(out), &back); err != nil {
			t.Fatalf("json output does not parse: %v\n%s", err, out)
		}
		if err := back.Validate(); err != nil {
			t.Fatalf("emitted envelope invalid: %v", err)
		}
		if len(back.Members) != 2 || back.Members[0].Status != air.FanoutDelivered || back.Members[1].Status != air.FanoutDenied {
			t.Fatalf("envelope lost member truth: %+v", back.Members)
		}
		// A JSON consumer sees the quiet part of the roster too: the
		// configured pattern that matched nothing is IN the envelope, not
		// only in the human stderr summary.
		if len(back.UnmatchedPatterns) != 1 || back.UnmatchedPatterns[0] != "ghost.*" {
			t.Fatalf("unmatched patterns missing from the JSON envelope: %v", back.UnmatchedPatterns)
		}
	})
}

func TestEmptyGroupErrorWording(t *testing.T) {
	if got := emptyGroupError("quiet", nil).Error(); got != `group "quiet" has no members present` {
		t.Fatalf("wording = %q", got)
	}
	got := emptyGroupError("quiet", []string{"a.*", "pubkey:K"}).Error()
	if !strings.Contains(got, "unmatched patterns: a.*, pubkey:K") {
		t.Fatalf("unmatched echo missing: %q", got)
	}
}
