package main

// Air · Groups — the resolution layer behind `group:<name>` fan-out (Spaces
// v1). A group is an operator-owned NAME-RESOLUTION convenience, never an
// authorization: this file only turns the config `groups:` map into present
// member cards (server side) and renders per-member outcomes (client side).
// Every fanned-out action re-enters its destination's own ACL/policy through
// the EXISTING single-target path, one audited decision per member; the result
// envelope (air.FanoutResult) has no aggregate verdict that could lie about a
// partially denied fan-out.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/xrey167/meshmcp/air"
)

// airGroupsSchemaV1 versions the GET /v1/groups reply.
const airGroupsSchemaV1 = "air.groups/v1"

// airGroupMembers is one resolved group: the operator-configured name, the
// present member cards (full air.Presence from ONE atomic snapshot — steer
// binds to the transport-stamped key, ring reads the advertised service
// address), and the configured patterns that matched no present card, echoed
// so a quiet roster is visible rather than silent. Error is set ONLY in the
// unfiltered listing (GET /v1/groups with no name) for a group that could not
// be resolved — an over-wide group is reported as its own loud entry with
// zero members (never a truncated subset) instead of aborting every other
// group's truth; the named form still refuses the whole request (422).
type airGroupMembers struct {
	Name              string         `json:"name"`
	Members           []air.Presence `json:"members"`
	UnmatchedPatterns []string       `json:"unmatched_patterns"`
	Error             string         `json:"error,omitempty"`
}

// airGroupsReply is the GET /v1/groups response envelope.
type airGroupsReply struct {
	Schema string            `json:"schema"`
	Groups []airGroupMembers `json:"groups"`
	You    string            `json:"you"`
}

// unknownGroupError maps to 404: the group is not defined at all. The wording
// mirrors the F17 load-time error so config and wire speak one language.
type unknownGroupError struct{ name string }

func (e *unknownGroupError) Error() string {
	return fmt.Sprintf("group %q is not defined in the gateway groups map", e.name)
}

// oversizeGroupError maps to 422: the group resolves to more present members
// than one fan-out may address. Refused loudly, never truncated to a subset.
type oversizeGroupError struct {
	name string
	n    int
}

func (e *oversizeGroupError) Error() string {
	return fmt.Sprintf("group %q resolves to %d members (max %d)", e.name, e.n, maxGroupMembers)
}

// resolveGroupsReply joins a groups map against one presence snapshot —
// server-side, so every client shares ONE pattern semantics and never
// re-implements glob matching. Shared by the live gateway controller and the
// handler-test fake.
func resolveGroupsReply(groups map[string][]string, cards []air.Presence, name string) (airGroupsReply, error) {
	reply := airGroupsReply{Schema: airGroupsSchemaV1, Groups: []airGroupMembers{}}
	var names []string
	if name != "" {
		if _, ok := groups[name]; !ok {
			return airGroupsReply{}, &unknownGroupError{name: name}
		}
		names = []string{name}
	} else {
		for n := range groups {
			names = append(names, n)
		}
		sort.Strings(names)
	}
	for _, n := range names {
		resolved, err := resolveGroupMembers(n, groups[n], cards)
		if err != nil {
			// In the unfiltered listing one over-wide group must not silence
			// every other group: it becomes its own loud error entry (name +
			// refusal, zero members — never a truncated subset). The named
			// form keeps refusing the whole request so fan-out stays a hard
			// pre-delivery error (422).
			var oversize *oversizeGroupError
			if name == "" && errors.As(err, &oversize) {
				reply.Groups = append(reply.Groups, airGroupMembers{
					Name: n, Members: []air.Presence{}, UnmatchedPatterns: []string{}, Error: err.Error(),
				})
				continue
			}
			return airGroupsReply{}, err
		}
		reply.Groups = append(reply.Groups, resolved)
	}
	return reply, nil
}

// resolveGroupMembers joins one group's patterns against the presence snapshot
// with the SAME semantics as acl.allows / policy.StaticGroups: "pubkey:<key>"
// matches exactly against the transport-stamped key; anything else is an FQDN
// glob ("*" included). Members keep the snapshot's deterministic order and are
// deduped by public key; patterns matching nothing are echoed back.
func resolveGroupMembers(name string, patterns []string, cards []air.Presence) (airGroupMembers, error) {
	out := airGroupMembers{Name: name, Members: []air.Presence{}, UnmatchedPatterns: []string{}}
	matched := map[string]bool{} // by transport-stamped public key
	for _, pat := range patterns {
		hit := false
		for _, card := range cards {
			if groupPatternMatches(pat, card) {
				hit = true
				matched[card.PublicKey] = true
			}
		}
		if !hit {
			out.UnmatchedPatterns = append(out.UnmatchedPatterns, pat)
		}
	}
	added := map[string]bool{}
	for _, card := range cards { // snapshot order = deterministic member order
		if matched[card.PublicKey] && !added[card.PublicKey] {
			added[card.PublicKey] = true
			out.Members = append(out.Members, card)
		}
	}
	if len(out.Members) > maxGroupMembers {
		return airGroupMembers{}, &oversizeGroupError{name: name, n: len(out.Members)}
	}
	return out, nil
}

// groupPatternMatches applies the acl pattern language to one present card.
func groupPatternMatches(pat string, card air.Presence) bool {
	if key, ok := strings.CutPrefix(pat, "pubkey:"); ok {
		return key != "" && key == card.PublicKey
	}
	if pat == "*" || pat == card.FQDN {
		return true
	}
	ok, _ := path.Match(pat, card.FQDN)
	return ok
}

// groups implements the airController roster surface for the live gateway from
// the startup groups map and the TTL-pruned presence registry. The caller
// identity parameters are part of the controller seam (every surface receives
// them); the roster itself is one disclosure tier — control-allowed callers
// only, gated by the handler exactly like /v1/sessions.
func (g *gatewayAirControl) groups(pubKey, fqdn, name string, now time.Time) (airGroupsReply, error) {
	_, _ = pubKey, fqdn
	return resolveGroupsReply(g.groupPatterns, g.nearby(now), name)
}

// emptyGroupError is the loud no-op: a defined group with zero present members
// fails BEFORE any delivery, echoing the patterns that matched nothing.
func emptyGroupError(group string, unmatched []string) error {
	if len(unmatched) == 0 {
		return fmt.Errorf("group %q has no members present", group)
	}
	return fmt.Errorf("group %q has no members present (unmatched patterns: %s)", group, strings.Join(unmatched, ", "))
}

// fetchAirGroup resolves one group server-side via GET /v1/groups?name=…,
// surfacing the endpoint's exact wording on error (unknown group 404,
// oversize 422, permission 403). The reply is a TRUST BOUNDARY: a compliant
// gateway can never send an over-wide roster (it 422s), a member card without
// a clean transport-stamped identity, or an envelope-unsafe pattern echo — so
// any of those is refused HERE, before a single delivery, rather than
// discovered by envelope validation after the whole fan-out already ran.
func fetchAirGroup(ctx context.Context, hc *http.Client, group string) (airGroupMembers, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://air-control/v1/groups?name="+url.QueryEscape(group), nil)
	if err != nil {
		return airGroupMembers{}, err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return airGroupMembers{}, fmt.Errorf("groups: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return airGroupMembers{}, fmt.Errorf("groups: %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	var out airGroupsReply
	if err := json.Unmarshal(body, &out); err != nil {
		return airGroupMembers{}, fmt.Errorf("groups: bad response: %w", err)
	}
	if len(out.Groups) != 1 || out.Groups[0].Name != group {
		return airGroupMembers{}, fmt.Errorf("groups: bad response: expected exactly group %q", group)
	}
	g := out.Groups[0]
	if g.Error != "" {
		return airGroupMembers{}, fmt.Errorf("groups: %s", singleLineReason(g.Error))
	}
	if len(g.Members) > maxGroupMembers {
		return airGroupMembers{}, fmt.Errorf("groups: bad response: %w", &oversizeGroupError{name: group, n: len(g.Members)})
	}
	for i, card := range g.Members {
		if err := (air.FanoutRecipient{Name: card.Name, FQDN: card.FQDN, PublicKey: card.PublicKey}).Validate(); err != nil {
			return airGroupMembers{}, fmt.Errorf("groups: bad response: member card #%d: %w", i+1, err)
		}
	}
	for i, p := range g.UnmatchedPatterns {
		if err := air.ValidateGroupPattern(p); err != nil {
			return airGroupMembers{}, fmt.Errorf("groups: bad response: unmatched pattern #%d: %w", i+1, err)
		}
	}
	return g, nil
}

// singleLineReason folds an untrusted error or response body into the bounded,
// single-line reason a FanoutMember may carry: control characters (terminal
// escapes included) become spaces and the result is trimmed to the envelope
// bound at a rune boundary.
func singleLineReason(s string) string {
	mapped := strings.Map(func(r rune) rune {
		if r < 0x20 || (r >= 0x7f && r <= 0x9f) {
			return ' '
		}
		return r
	}, s)
	mapped = strings.Join(strings.Fields(mapped), " ")
	if mapped == "" {
		mapped = "unknown error"
	}
	for len(mapped) > air.MaxFanoutReasonBytes {
		_, size := utf8.DecodeLastRuneInString(mapped)
		mapped = mapped[:len(mapped)-size]
	}
	return mapped
}

// fanoutExitError carries a fan-out's designed exit code (2 = partial,
// 3 = zero delivered) through main's error presenter, so deferred cleanups
// still run (a direct os.Exit would skip stopMesh) while the process reports
// the honest per-member outcome. Hard errors before any delivery stay plain
// errors (exit 1).
type fanoutExitError struct {
	code int
	msg  string
}

func (e *fanoutExitError) Error() string { return e.msg }

// reportFanout renders one fan-out result — one line per member in server
// resolution order plus a summary — or, with --json, the air.fanout-result/v1
// envelope verbatim (which carries the unmatched-pattern echo itself, so a
// JSON consumer sees a quiet part of the roster too). It returns nil only when
// EVERY resolved member was delivered; otherwise a fanoutExitError carries the
// honest exit code (2 partial, 3 none delivered). The full member list is
// emitted in every case.
func reportFanout(res air.FanoutResult, asJSON bool) error {
	delivered := 0
	counts := map[air.FanoutStatus]int{}
	for _, m := range res.Members {
		counts[m.Status]++
	}
	delivered = counts[air.FanoutDelivered]

	if asJSON {
		encoded, err := json.MarshalIndent(res, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(encoded))
	} else {
		for _, m := range res.Members {
			fmt.Println(fanoutMemberLine(res.Action, m))
		}
		fmt.Fprintln(os.Stderr, dim(fanoutSummary(res, counts)))
	}

	switch {
	case delivered == len(res.Members):
		return nil
	case delivered == 0:
		return &fanoutExitError{code: 3, msg: fmt.Sprintf("group %s: no member was delivered (%d skipped/denied/failed)", res.Group, len(res.Members))}
	default:
		return &fanoutExitError{code: 2, msg: fmt.Sprintf("group %s: partial delivery (%d of %d members)", res.Group, delivered, len(res.Members))}
	}
}

// fanoutMemberLine is one member's human line, colour-coded like the page's
// decisions: ✓ delivered · ✗ denied/failed · dimmed skip.
func fanoutMemberLine(action air.FanoutAction, m air.FanoutMember) string {
	node := m.Recipient.FQDN
	if node == "" {
		node = m.Recipient.Name
	}
	if node == "" {
		node = m.Recipient.PublicKey
	}
	switch m.Status {
	case air.FanoutDelivered:
		if action == air.FanoutActionSteer && m.Steer != nil {
			line := okLine("steered %s/%s", m.Steer.Backend, m.Steer.Session) + dim(" ("+node+")")
			if m.Steer.By != "" {
				line += dim(" by " + m.Steer.By)
			}
			return line
		}
		return okLine("%s → %s", action, m.Recipient.Address) + dim(" ("+node+")")
	case air.FanoutSkipped:
		return dim("- skipped " + node + ": " + m.Reason)
	case air.FanoutDenied:
		return red("✗") + " denied " + node + ": " + m.Reason
	default:
		return amber("✗") + " failed " + node + ": " + m.Reason
	}
}

func fanoutSummary(res air.FanoutResult, counts map[air.FanoutStatus]int) string {
	s := fmt.Sprintf("group %s: delivered %d · denied %d · skipped %d · failed %d",
		res.Group, counts[air.FanoutDelivered], counts[air.FanoutDenied], counts[air.FanoutSkipped], counts[air.FanoutFailed])
	if len(res.UnmatchedPatterns) > 0 {
		s += fmt.Sprintf(" (%d pattern(s) unmatched: %s)", len(res.UnmatchedPatterns), strings.Join(res.UnmatchedPatterns, ", "))
	}
	return s
}
