// Package federation bridges named tools between two independent meshes/orgs
// through a boundary. The boundary is the whole trust story of cross-org
// agent-to-agent traffic: it maps a remote identity to a known org, admits only
// the tools that org is granted, stamps every crossing with its origin, and
// audits it — so neither side exposes a public endpoint and every inter-org
// call is identity-attributed and recorded. This is the network-effects layer:
// each org you connect raises the switching cost for all the others.
package federation

import (
	"path"
	"strings"

	"github.com/xrey167/meshmcp/policy"
)

// Grant lists what a remote org may reach across the boundary: tool-name globs
// and, for cross-org knowledge exchange (F12), the corpora / KG subgraphs it
// may query. Corpora are enforced with CheckCorpus in addition to the tool
// grant, so an org can be given a vetted slice of knowledge and nothing else.
type Grant struct {
	Org     string   `yaml:"org"`
	Tools   []string `yaml:"tools"`
	Corpora []string `yaml:"corpora"`
}

// Mapping maps a remote mesh identity to an org id. Match is by "pubkey:<key>"
// (exact WireGuard key) or an FQDN glob.
type Mapping struct {
	Match string `yaml:"match"` // "pubkey:<key>" or fqdn glob
	Org   string `yaml:"org"`
	// Principal is the local identity a crossing from this org is stamped as,
	// so local policy/audit see a stable principal rather than a raw remote key.
	Principal string `yaml:"principal"`
	// TrustDomain is this org's SPIFFE trust domain. When set (and the org is
	// matched by a stable pubkey), every crossing this org makes is additively
	// labeled spiffe://<TrustDomain>/peer/<key> on its audit record. It is a
	// label only — enforcement still keys solely on the WireGuard key. Empty
	// means no label is emitted for the org (Feature A, OAUTH-STANDARDS.md).
	TrustDomain string `yaml:"trust_domain"`
}

// Boundary authorizes and audits cross-org tool calls.
type Boundary struct {
	grants      map[string][]string // org -> tool globs
	corpora     map[string][]string // org -> corpus/subgraph globs
	mappings    []Mapping
	principal   map[string]string // org -> local principal
	trustDomain map[string]string // org -> SPIFFE trust domain (Feature A)
	pubkey      map[string]string // org -> stable WireGuard key, if pubkey-mapped
	collisions  []string          // trust domains claimed by more than one org
	audit       *policy.AuditLog
}

// NewBoundary builds a boundary from grants and identity mappings. audit may be
// nil (crossings are then not recorded — not recommended). Trust-domain
// collisions (the same non-empty domain claimed by two different orgs) are
// detected here and surfaced via TrustDomainCollisions so the caller can warn
// or reject rather than silently attribute two orgs to one SPIFFE identity.
func NewBoundary(grants []Grant, mappings []Mapping, audit *policy.AuditLog) *Boundary {
	b := &Boundary{
		grants:      map[string][]string{},
		corpora:     map[string][]string{},
		mappings:    mappings,
		principal:   map[string]string{},
		trustDomain: map[string]string{},
		pubkey:      map[string]string{},
		audit:       audit,
	}
	for _, g := range grants {
		b.grants[g.Org] = append(b.grants[g.Org], g.Tools...)
		b.corpora[g.Org] = append(b.corpora[g.Org], g.Corpora...)
	}
	domainOwner := map[string]string{} // trust domain -> first org that claimed it
	seenCollision := map[string]bool{}
	for _, m := range mappings {
		if m.Principal != "" {
			b.principal[m.Org] = m.Principal
		}
		if k, ok := strings.CutPrefix(m.Match, "pubkey:"); ok && k != "" {
			b.pubkey[m.Org] = k
		}
		if m.TrustDomain == "" {
			continue
		}
		b.trustDomain[m.Org] = m.TrustDomain
		if owner, ok := domainOwner[m.TrustDomain]; ok && owner != m.Org {
			if !seenCollision[m.TrustDomain] {
				b.collisions = append(b.collisions, m.TrustDomain)
				seenCollision[m.TrustDomain] = true
			}
		} else {
			domainOwner[m.TrustDomain] = m.Org
		}
	}
	return b
}

// TrustDomainCollisions returns the trust domains that more than one org
// claims. A non-empty result means the config maps distinct orgs to the same
// SPIFFE identity namespace — the caller should warn or reject at startup
// rather than let crossings from two orgs be labeled indistinguishably.
func (b *Boundary) TrustDomainCollisions() []string { return b.collisions }

// SpiffeID derives the additive spiffe://<trust-domain>/peer/<key> label for a
// crossing attributed to org, using peerKey as the stable identity. Returns ""
// when the org has no configured trust domain or peerKey is empty (e.g. an
// FQDN-glob-mapped org with no individual key) — never a malformed URI, never
// a panic. This is a label only; enforcement keys on peerKey, never on this.
func (b *Boundary) SpiffeID(org, peerKey string) policy.SpiffeLabel {
	td := b.trustDomain[org]
	if td == "" || peerKey == "" {
		return ""
	}
	return policy.SpiffeID(td, peerKey)
}

// spiffeForOrg derives the SPIFFE label to stamp on an org's crossing from what
// the boundary already knows: the org's configured trust domain and, if the org
// is matched by a stable pubkey, that key. FQDN-glob-mapped orgs have no stable
// key, so they yield "" (no label) rather than a synthetic one.
func (b *Boundary) spiffeForOrg(org string) policy.SpiffeLabel {
	return b.SpiffeID(org, b.pubkey[org])
}

// OrgFor resolves a remote peer identity to an org id. Returns "" if the peer
// maps to no known org (an unrecognized org is denied everything).
func (b *Boundary) OrgFor(peerFQDN, peerKey string) string {
	for _, m := range b.mappings {
		if k, ok := strings.CutPrefix(m.Match, "pubkey:"); ok {
			if k == peerKey && peerKey != "" {
				return m.Org
			}
			continue
		}
		if m.Match == "*" || m.Match == peerFQDN {
			return m.Org
		}
		if ok, _ := path.Match(m.Match, peerFQDN); ok {
			return m.Org
		}
	}
	return ""
}

// tokenIssuerPrefix marks a Mapping.Match value as a token-exchange issuer
// match (Feature C2, RFC 8693 exchange — see federation/exchange.go):
// "issuer:<iss>". Resolved only by OrgForIssuer, never by OrgFor.
const tokenIssuerPrefix = "issuer:"

// OrgForIssuer resolves a federation org from a subject token's VALIDATED
// issuer (never from the subject claim — the exchange path in
// federation/exchange.go looks this up only after signature/audience/time
// validation passes). This is deliberately a separate method from OrgFor,
// not a case folded into it: an "issuer:<iss>" Mapping is an exact string
// match only, with no glob and no "*" wildcard fallback, so an issuer this
// config does not explicitly name resolves to no org, full stop — it never
// falls through to a wildcard-mapped org the way OrgFor's FQDN matching
// does. Closes the issuer-collision attack described in
// docs/spec/OAUTH-STANDARDS.md Feature C2.
func (b *Boundary) OrgForIssuer(issuer string) string {
	if issuer == "" {
		return ""
	}
	for _, m := range b.mappings {
		if iss, ok := strings.CutPrefix(m.Match, tokenIssuerPrefix); ok && iss == issuer {
			return m.Org
		}
	}
	return ""
}

// Principal returns the local principal to stamp for an org (falls back to the
// org id).
func (b *Boundary) Principal(org string) string {
	if p, ok := b.principal[org]; ok {
		return p
	}
	return org
}

// Check authorizes a tool crossing for a resolved org and records it in the
// audit trail. tool is the requested tool name (already namespace-stripped if
// the boundary namespaces upstreams).
func (b *Boundary) Check(org, tool string) (allow bool, reason string) {
	if org == "" {
		reason = "unrecognized org (no identity mapping)"
		b.record("", tool, false, reason)
		return false, reason
	}
	globs, known := b.grants[org]
	if !known {
		reason = "org has no federation grant"
		b.record(org, tool, false, reason)
		return false, reason
	}
	for _, g := range globs {
		if g == "*" || g == tool {
			b.record(org, tool, true, "")
			return true, ""
		}
		if ok, _ := path.Match(g, tool); ok {
			b.record(org, tool, true, "")
			return true, ""
		}
	}
	reason = "tool not granted to org"
	b.record(org, tool, false, reason)
	return false, reason
}

// Allowed is Check without auditing — for deciding which tools to advertise to
// an org at list time (the audited decision happens at call time via Check).
func (b *Boundary) Allowed(org, tool string) bool {
	globs, known := b.grants[org]
	if org == "" || !known {
		return false
	}
	for _, g := range globs {
		if g == "*" || g == tool {
			return true
		}
		if ok, _ := path.Match(g, tool); ok {
			return true
		}
	}
	return false
}

// CheckCorpus authorizes an org querying a named corpus / KG subgraph across
// the boundary and records the crossing. Empty grant means no corpus is shared
// (deny), so knowledge is opt-in per org. This composes with Check (the org
// must be granted both the tool, e.g. "search", and the corpus).
func (b *Boundary) CheckCorpus(org, corpus string) (allow bool, reason string) {
	if org == "" {
		reason = "unrecognized org (no identity mapping)"
		b.recordCorpus("", corpus, false, reason)
		return false, reason
	}
	globs := b.corpora[org]
	for _, g := range globs {
		if g == "*" || g == corpus {
			b.recordCorpus(org, corpus, true, "")
			return true, ""
		}
		if ok, _ := path.Match(g, corpus); ok {
			b.recordCorpus(org, corpus, true, "")
			return true, ""
		}
	}
	reason = "corpus not granted to org"
	b.recordCorpus(org, corpus, false, reason)
	return false, reason
}

func (b *Boundary) recordCorpus(org, corpus string, allow bool, reason string) {
	if b.audit == nil {
		return
	}
	decision := "deny"
	if allow {
		decision = "allow"
	}
	b.audit.Append(policy.AuditRecord{
		Backend:      "federation-boundary",
		Peer:         org,
		PeerSpiffeID: b.spiffeForOrg(org),
		Method:       "federation/corpus/query",
		Tool:         corpus,
		Decision:     decision,
		Reason:       reason,
	})
}

func (b *Boundary) record(org, tool string, allow bool, reason string) {
	if b.audit == nil {
		return
	}
	decision := "deny"
	if allow {
		decision = "allow"
	}
	b.audit.Append(policy.AuditRecord{
		Backend:      "federation-boundary",
		Peer:         org,
		PeerSpiffeID: b.spiffeForOrg(org),
		Method:       "federation/tools/call",
		Tool:         tool,
		Decision:     decision,
		Reason:       reason,
	})
}
