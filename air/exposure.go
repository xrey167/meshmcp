package air

import (
	"path"
	"sort"
	"strings"
)

// Air · Osint — defensive self-recon of your OWN mesh's attack surface.
//
// The per-caller verbs (whoami, map, catalog, change) each answer from ONE
// identity's seat: the gateway filters the catalog for the calling peer. That is
// a security feature for peers, but it blinds the operator to their aggregate
// exposure. `air osint` inverts the view: it reads the trusted gateway config
// the operator alone holds and computes, across ALL configured identities, a
// reachability matrix plus a risk audit — "turn on the light in your own house".
//
// This file is the pure, dependency-free analyzer (std only, no config/policy/
// secrets imports), so it is fully unit-testable without a mesh — the same
// carve-out discipline as catalog.go and change.go. The thin CLI in the main
// package projects the trusted Config into these flat types and renders the
// report.
//
// Honest ACL model (important): backend reachability here mirrors the gateway's
// backend ACL (acl.allows) EXACTLY — "pubkey:" exact match and FQDN path.Match
// globs, with the fail-closed empty-identity rule. That layer performs NO
// group: expansion, so this analyzer performs none either: the reach matrix is
// ACL-only and never claims a parity it does not have. A group: token appearing
// in a backend allow list is therefore inert at the ACL layer and is flagged as
// a likely misconfiguration rather than silently expanded.

// Severity orders findings for the report and the fail-on gate.
type Severity string

const (
	SevCritical Severity = "critical"
	SevHigh     Severity = "high"
	SevMedium   Severity = "medium"
	SevLow      Severity = "low"
)

// severityRank orders severities most-severe first for a stable sort.
func severityRank(s Severity) int {
	switch s {
	case SevCritical:
		return 0
	case SevHigh:
		return 1
	case SevMedium:
		return 2
	case SevLow:
		return 3
	default:
		return 4
	}
}

// SecretGrantExposure is one secrets grant projected into a shape the analyzer
// can reason about without importing the secrets package. Cosigned is
// pre-computed by the projector in main by correlating the grant's tools to the
// policy rule that authorizes them (a fact only the policy layer can decide);
// the analyzer never fabricates it.
type SecretGrantExposure struct {
	Secrets  []string `json:"secrets"`         // secret-name globs this grant injects
	Peers    []string `json:"peers"`           // grant peer patterns (pubkey:/FQDN glob) — the ACTUAL binding
	Tools    []string `json:"tools,omitempty"` // tool-name globs the grant is bound to
	Cosigned bool     `json:"cosigned"`        // the rule authorizing these tools requires co-sign
}

// BackendExposure is one backend projected into a flat, analyzable shape.
// Booleans are pre-computed by the projector in main from the trusted config.
type BackendExposure struct {
	Name           string                `json:"name"`
	Transport      string                `json:"transport"` // stdio | http | remote
	Allow          []string              `json:"allow"`     // FQDN globs / pubkey: (empty = any mesh peer)
	Audited        bool                  `json:"audited"`   // backend audit_log OR gateway-wide audit_log set
	PolicyGated    bool                  `json:"policy_gated"`
	DefaultAllow   bool                  `json:"default_allow"` // policy default is allow, or no policy at all
	SecretGrants   []SecretGrantExposure `json:"secret_grants,omitempty"`
	RemoteEndpoint string                `json:"remote_endpoint,omitempty"` // outbound egress target
}

// ControlExposure is the Air control endpoint's own gate.
type ControlExposure struct {
	Enabled       bool     `json:"enabled"`
	Allow         []string `json:"allow"`
	OnBehalfAllow []string `json:"on_behalf_allow,omitempty"`
}

// MeshExposure is the whole projected attack surface.
type MeshExposure struct {
	Gateway  string            `json:"gateway"`
	Control  ControlExposure   `json:"control"`
	Backends []BackendExposure `json:"backends"`
}

// Finding is one flagged risk in the surface.
type Finding struct {
	Rule     string   `json:"rule"` // stable id, e.g. "secrets-no-cosign"
	Severity Severity `json:"severity"`
	Backend  string   `json:"backend,omitempty"`
	Title    string   `json:"title"`
	Detail   string   `json:"detail"`
	Evidence []string `json:"evidence,omitempty"`
}

// Reach is what one identity can touch — the answer to "what can identity X
// actually reach?" under real ACL semantics.
type Reach struct {
	Identity     string   `json:"identity"`
	Backends     []string `json:"backends"`
	Secrets      []string `json:"secrets,omitempty"`       // secrets it can command (keyed off grant peers)
	RemoteEgress []string `json:"remote_egress,omitempty"` // third-party endpoints it can drive
	ViaWildcard  []string `json:"via_wildcard,omitempty"`  // backends reached only via a wildcard/empty allow
}

// ExposureScore is the one-glance headline: counts by severity and a grade.
type ExposureScore struct {
	Critical int    `json:"critical"`
	High     int    `json:"high"`
	Medium   int    `json:"medium"`
	Low      int    `json:"low"`
	Grade    string `json:"grade"` // A (clean) … F (criticals present)
}

// ExposureReport is the diffable, renderable artifact of one recon run.
type ExposureReport struct {
	Kind      string        `json:"kind"`      // "meshmcp/air/exposure"
	Version   int           `json:"version"`   // 1
	Generated string        `json:"generated"` // RFC3339, injectable clock
	Gateway   string        `json:"gateway"`
	Mesh      MeshExposure  `json:"mesh"`
	Reach     []Reach       `json:"reach"`
	Findings  []Finding     `json:"findings"`
	Score     ExposureScore `json:"score"`
}

// ExposureKind is the report's schema tag.
const ExposureKind = "meshmcp/air/exposure"

// ExposureVersion is the current report schema version.
const ExposureVersion = 1

// isWildcard reports whether an allow pattern admits any mesh peer.
func isWildcard(p string) bool { return p == "*" || p == "**" }

// isGroupToken reports whether a pattern is a group: reference. The backend ACL
// layer does not expand these, so one appearing in a backend/control allow list
// is inert (never matches a real caller) and is flagged as a misconfiguration.
func isGroupToken(p string) bool { return strings.HasPrefix(p, "group:") }

// splitSubject maps an identity subject to the (pubkey, fqdn) pair the ACL
// matcher consumes: a "pubkey:" subject binds the key, anything else is an FQDN.
func splitSubject(id string) (pubkey, fqdn string) {
	if k, ok := strings.CutPrefix(id, "pubkey:"); ok {
		return k, ""
	}
	return "", id
}

// identityMatches reports whether one allow pattern admits the caller. It mirrors
// acl.allows' per-pattern rule exactly: a "pubkey:" pattern is an exact key
// match; every other pattern is an FQDN path.Match glob. No group expansion —
// the backend ACL layer has none.
func identityMatches(pattern, pubkey, fqdn string) bool {
	if key, ok := strings.CutPrefix(pattern, "pubkey:"); ok {
		return key == pubkey
	}
	ok, _ := path.Match(pattern, fqdn)
	return ok
}

// reaches mirrors acl.allows for a full allow list: an unattributable caller
// (no key and no FQDN) is denied (fail closed); an empty list admits any
// identified mesh peer (the mesh is the outer boundary); otherwise any matching
// pattern admits.
func reaches(patterns []string, pubkey, fqdn string) bool {
	if pubkey == "" && fqdn == "" {
		return false
	}
	if len(patterns) == 0 {
		return true
	}
	for _, p := range patterns {
		if identityMatches(p, pubkey, fqdn) {
			return true
		}
	}
	return false
}

// reachedViaWildcard reports whether the caller reaches an allow list ONLY
// because of an empty or wildcard entry — i.e. no specific pattern matched. Used
// to separate "scoped" reach from "reached because the door was left open".
func reachedViaWildcard(patterns []string, pubkey, fqdn string) bool {
	if len(patterns) == 0 {
		return true // empty allow = any mesh peer
	}
	var specific []string
	for _, p := range patterns {
		if !isWildcard(p) {
			specific = append(specific, p)
		}
	}
	if len(specific) == 0 {
		return true // only wildcards present
	}
	return !reaches(specific, pubkey, fqdn)
}

// ReachabilityFor computes what a single identity subject can actually reach.
// Secret exposure is keyed off each grant's OWN peer list (the real binding),
// not the backend allow list: a caller may reach a backend yet still be unable
// to command its secrets if the grant scopes them to a narrower peer set.
func ReachabilityFor(m MeshExposure, id string) Reach {
	pubkey, fqdn := splitSubject(id)
	r := Reach{Identity: id}
	secretsSet := map[string]bool{}
	egressSet := map[string]bool{}
	for _, b := range m.Backends {
		if !reaches(b.Allow, pubkey, fqdn) {
			continue
		}
		r.Backends = append(r.Backends, b.Name)
		if reachedViaWildcard(b.Allow, pubkey, fqdn) {
			r.ViaWildcard = append(r.ViaWildcard, b.Name)
		}
		for _, g := range b.SecretGrants {
			if !reaches(g.Peers, pubkey, fqdn) {
				continue
			}
			for _, s := range g.Secrets {
				secretsSet[s] = true
			}
		}
		if b.RemoteEndpoint != "" {
			egressSet[b.RemoteEndpoint] = true
		}
	}
	sort.Strings(r.Backends)
	sort.Strings(r.ViaWildcard)
	r.Secrets = sortedKeys(secretsSet)
	r.RemoteEgress = sortedKeys(egressSet)
	return r
}

// AllReach computes the reachability of every distinct allow-subject named in
// the surface (backend allows, the control allow, and secret-grant peers).
// Bare wildcards and group: tokens are omitted as subjects: a wildcard is not an
// identity, and a group token is inert at the ACL layer.
func AllReach(m MeshExposure) []Reach {
	subjectSet := map[string]bool{}
	add := func(patterns []string) {
		for _, p := range patterns {
			if p == "" || isWildcard(p) || isGroupToken(p) {
				continue
			}
			subjectSet[p] = true
		}
	}
	add(m.Control.Allow)
	for _, b := range m.Backends {
		add(b.Allow)
		for _, g := range b.SecretGrants {
			add(g.Peers)
		}
	}
	subjects := sortedKeys(subjectSet)
	out := make([]Reach, 0, len(subjects))
	for _, s := range subjects {
		out = append(out, ReachabilityFor(m, s))
	}
	return out
}

// Analyze runs every risk rule over the surface and returns the findings sorted
// most-severe first, then by rule id, then by backend — a stable, reproducible
// order for rendering and diffing.
func Analyze(m MeshExposure) []Finding {
	var f []Finding

	if m.Control.Enabled {
		if wild := wildcardEntries(m.Control.Allow); len(wild) > 0 {
			f = append(f, Finding{
				Rule: "control-wildcard", Severity: SevCritical,
				Title:  "control endpoint open to any mesh peer",
				Detail: "the Air control endpoint (list/steer live sessions) admits any peer via a wildcard allow",
				Evidence: wild,
			})
		}
		if g := groupEntries(m.Control.Allow); len(g) > 0 {
			f = append(f, Finding{
				Rule: "group-in-acl", Severity: SevMedium,
				Title:  "control allow uses a group: token the ACL layer ignores",
				Detail: "the control endpoint ACL matches only pubkey:/FQDN; a group: entry never matches a caller and grants nothing",
				Evidence: g,
			})
		}
	}

	for _, b := range m.Backends {
		injectsSecrets := len(b.SecretGrants) > 0
		openAllow := len(b.Allow) == 0 || len(wildcardEntries(b.Allow)) > 0

		if (injectsSecrets || b.Transport == "remote") && openAllow {
			f = append(f, Finding{
				Rule: "open-secrets-backend", Severity: SevCritical, Backend: b.Name,
				Title:  "sensitive backend reachable by any mesh peer",
				Detail: "a secret-injecting or remote-egress backend has an empty/wildcard allow — any identified mesh peer can drive it",
				Evidence: allowEvidence(b.Allow),
			})
		}
		if injectsSecrets && !allGrantsCosigned(b.SecretGrants) {
			f = append(f, Finding{
				Rule: "secrets-no-cosign", Severity: SevCritical, Backend: b.Name,
				Title:  "secrets injected without co-sign",
				Detail: "no policy rule authorizing the secret-injecting tool requires co-sign — an allowed identity pulls credentials unattended",
				Evidence: uncosignedSecrets(b.SecretGrants),
			})
		}
		if broad := broadGrants(b.SecretGrants); len(broad) > 0 {
			f = append(f, Finding{
				Rule: "secrets-broad-grant", Severity: SevHigh, Backend: b.Name,
				Title:  "secret granted to any mesh peer",
				Detail: "a secret grant lists a wildcard peer — the credential is exposed to every mesh peer, not a scoped identity",
				Evidence: broad,
			})
		}
		if !b.Audited {
			f = append(f, Finding{
				Rule: "unaudited-backend", Severity: SevHigh, Backend: b.Name,
				Title:  "backend has no audit ledger",
				Detail: "no backend audit_log and no gateway-wide audit_log — governed calls leave no tamper-evident record",
			})
		}
		if b.DefaultAllow {
			f = append(f, Finding{
				Rule: "default-allow", Severity: SevHigh, Backend: b.Name,
				Title:  "deny-by-default not enforced",
				Detail: "the backend has no policy or a default-allow policy — tool calls that match no rule are permitted",
			})
		}
		if wild := wildcardEntries(b.Allow); len(wild) > 0 || len(b.Allow) == 0 {
			f = append(f, Finding{
				Rule: "wildcard-allow", Severity: SevHigh, Backend: b.Name,
				Title:  "backend allows any mesh peer",
				Detail: "an empty or wildcard allow list admits every identified mesh peer",
				Evidence: allowEvidence(b.Allow),
			})
		}
		if g := groupEntries(b.Allow); len(g) > 0 {
			f = append(f, Finding{
				Rule: "group-in-acl", Severity: SevMedium, Backend: b.Name,
				Title:  "allow uses a group: token the ACL layer ignores",
				Detail: "backend ACL matches only pubkey:/FQDN; a group: entry never matches a caller (likely a silent misconfiguration)",
				Evidence: g,
			})
		}
		if b.Transport == "remote" && b.RemoteEndpoint != "" {
			f = append(f, Finding{
				Rule: "remote-egress", Severity: SevMedium, Backend: b.Name,
				Title:  "data leaves the mesh to a third party",
				Detail: "a remote backend forwards calls out to an external endpoint",
				Evidence: []string{b.RemoteEndpoint},
			})
		}
	}

	sort.SliceStable(f, func(i, j int) bool {
		if ri, rj := severityRank(f[i].Severity), severityRank(f[j].Severity); ri != rj {
			return ri < rj
		}
		if f[i].Rule != f[j].Rule {
			return f[i].Rule < f[j].Rule
		}
		return f[i].Backend < f[j].Backend
	})
	return f
}

// ScoreFindings tallies findings by severity and assigns a headline grade from
// the most severe present: F on any critical, then D/C/B for high/medium/low,
// A for a clean surface.
func ScoreFindings(f []Finding) ExposureScore {
	var s ExposureScore
	for _, x := range f {
		switch x.Severity {
		case SevCritical:
			s.Critical++
		case SevHigh:
			s.High++
		case SevMedium:
			s.Medium++
		case SevLow:
			s.Low++
		}
	}
	switch {
	case s.Critical > 0:
		s.Grade = "F"
	case s.High > 0:
		s.Grade = "D"
	case s.Medium > 0:
		s.Grade = "C"
	case s.Low > 0:
		s.Grade = "B"
	default:
		s.Grade = "A"
	}
	return s
}

// BuildReport assembles the full report from a projected surface, stamping the
// generation time from the injected clock so a run is deterministic under test.
func BuildReport(m MeshExposure, now func() string) ExposureReport {
	if now == nil {
		now = func() string { return "" }
	}
	findings := Analyze(m)
	return ExposureReport{
		Kind:      ExposureKind,
		Version:   ExposureVersion,
		Generated: now(),
		Gateway:   m.Gateway,
		Mesh:      m,
		Reach:     AllReach(m),
		Findings:  findings,
		Score:     ScoreFindings(findings),
	}
}

// --- rule helpers ---

func wildcardEntries(patterns []string) []string {
	var out []string
	for _, p := range patterns {
		if isWildcard(p) {
			out = append(out, p)
		}
	}
	return out
}

func groupEntries(patterns []string) []string {
	var out []string
	for _, p := range patterns {
		if isGroupToken(p) {
			out = append(out, p)
		}
	}
	return out
}

// allowEvidence renders an allow list as finding evidence, naming the empty case
// explicitly so the report shows why the door is open.
func allowEvidence(patterns []string) []string {
	if len(patterns) == 0 {
		return []string{"(empty — any mesh peer)"}
	}
	return append([]string(nil), patterns...)
}

func allGrantsCosigned(grants []SecretGrantExposure) bool {
	for _, g := range grants {
		if len(g.Secrets) > 0 && !g.Cosigned {
			return false
		}
	}
	return true
}

func uncosignedSecrets(grants []SecretGrantExposure) []string {
	set := map[string]bool{}
	for _, g := range grants {
		if g.Cosigned {
			continue
		}
		for _, s := range g.Secrets {
			set[s] = true
		}
	}
	return sortedKeys(set)
}

func broadGrants(grants []SecretGrantExposure) []string {
	set := map[string]bool{}
	for _, g := range grants {
		if len(wildcardEntries(g.Peers)) == 0 {
			continue
		}
		for _, s := range g.Secrets {
			set[s] = true
		}
	}
	return sortedKeys(set)
}

func sortedKeys(m map[string]bool) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
