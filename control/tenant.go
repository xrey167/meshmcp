package control

import (
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// A tenant is a partition of the control plane's OWN storage (policy, registry,
// enrollment, and audit) keyed on the enrolling/authenticated WireGuard
// identity — never on anything a request can name. It is the opposite direction
// from federation's org concept, which classifies *remote* peers for inbound
// boundary crossings: a tenant partitions *local* control state. The pattern is
// mirrored (pubkey -> id map, deny on no-match), the federation type is not
// reused.
//
// Cross-tenant access is absent BY CONSTRUCTION, not blocked by a check: a
// handler receives only the tenantID that authorize derived from the transport
// key, and every store is addressed through it. A key that resolves to no tenant
// is denied by default (no resolvable tenant -> refuse), matching the
// unattributable-caller path.

// TenantResolver maps a transport-proven WireGuard key to a tenant and answers
// role questions WITHIN that tenant. Both operations are pure functions of the
// key; neither ever consults request-supplied data.
type TenantResolver interface {
	// TenantFor maps a transport-proven key to its tenant id. ok=false means the
	// key belongs to no tenant, which the control plane refuses (deny-by-default).
	TenantFor(pubKey string) (tenantID string, ok bool)
	// Authorized reports whether pubKey holds role WITHIN tenantID. RoleAdmin
	// implies every role inside its OWN tenant only — there is no cross-tenant
	// super-role. A key absent from tenantID's grants holds nothing there.
	Authorized(tenantID, pubKey string, role Role) bool
}

// TenantSet is the concrete resolver, built from the operator ACL. It holds one
// StaticAuthorizer per tenant plus a reverse index (pubkey -> tenantID) and the
// per-tenant enrollment groups — ALL produced by a single parse, so a key's
// tenant and its roles can never drift apart the way two separate config files
// could. StaticAuthorizer itself is untouched: isolation is structural (a
// tenant's authorizer literally does not contain another tenant's keys).
type TenantSet struct {
	authz  map[string]*StaticAuthorizer // tenantID -> its own authorizer
	byKey  map[string]string            // pubkey -> tenantID (reverse index)
	groups map[string][]string          // tenantID -> enroll_groups (optional)
}

// TenantFor resolves a transport-proven key to its tenant. Default-deny: an
// empty or unmapped key belongs to no tenant.
func (t *TenantSet) TenantFor(pubKey string) (string, bool) {
	if t == nil || pubKey == "" {
		return "", false
	}
	tid, ok := t.byKey[pubKey]
	return tid, ok
}

// Authorized delegates to the resolved tenant's OWN authorizer. Because that
// authorizer's role map has no entry for a key granted in a different tenant,
// admin-of-A holds nothing in B — the datum for KA-in-B does not exist, so this
// is not a "caller tenant == target tenant" comparison a logic slip could
// bypass.
func (t *TenantSet) Authorized(tenantID, pubKey string, role Role) bool {
	if t == nil {
		return false
	}
	a, ok := t.authz[tenantID]
	if !ok {
		return false
	}
	return a.HasRole(pubKey, role)
}

// TenantIDs returns the configured tenant ids, sorted — for deterministic
// startup wiring and logs.
func (t *TenantSet) TenantIDs() []string {
	out := make([]string, 0, len(t.authz))
	for id := range t.authz {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// EnrollGroups returns the NetBird auto_groups configured for a tenant (nil when
// none), so an enrolled node lands in its own tenant's groups.
func (t *TenantSet) EnrollGroups(tenantID string) []string {
	return t.groups[tenantID]
}

// ACL is a parsed operator control ACL. Exactly one of Flat (single-tenant) or
// Tenants (multi-tenant) is non-nil.
type ACL struct {
	// Flat is the single-tenant authorizer (top-level grants:). Nil in the
	// multi-tenant form.
	Flat *StaticAuthorizer
	// Tenants is the multi-tenant resolver (tenants:). Nil in the flat form.
	Tenants *TenantSet
}

// LoadControlACL parses an operator ACL, auto-detecting the flat (grants:) form
// from the tenant-structured (tenants:) form. The two are mutually exclusive; an
// ACL with both, or with neither, is a startup error (a default-deny control
// plane with an empty ACL admits no one). Strict decoding rejects unknown fields
// so a typo fails startup instead of silently mis-granting.
func LoadControlACL(raw []byte) (*ACL, error) {
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	var f aclFile
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("control ACL: %w", err)
	}
	hasFlat := len(f.Grants) > 0
	hasTenants := len(f.Tenants) > 0
	switch {
	case hasFlat && hasTenants:
		return nil, fmt.Errorf("control ACL: use either top-level grants: (single-tenant) or tenants: (multi-tenant), not both")
	case hasTenants:
		ts, err := newTenantSet(f)
		if err != nil {
			return nil, err
		}
		return &ACL{Tenants: ts}, nil
	case hasFlat:
		a, err := NewStaticAuthorizer(f.Grants)
		if err != nil {
			return nil, err
		}
		return &ACL{Flat: a}, nil
	default:
		return nil, fmt.Errorf("control ACL: no grants or tenants defined (a default-deny control plane with an empty ACL admits no one)")
	}
}

// LoadTenantACL parses a tenant-structured operator ACL into a TenantSet. It is
// the multi-tenant sibling of LoadAuthorizer; LoadControlACL auto-detects and
// calls the right one.
func LoadTenantACL(raw []byte) (*TenantSet, error) {
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	var f aclFile
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("control ACL: %w", err)
	}
	return newTenantSet(f)
}

// newTenantSet builds a TenantSet from a decoded ACL, enforcing — at load
// (operator input, NEVER the request path) — the invariants that make a tenant
// an isolated partition:
//   - each tenant id is path-safe (validTenantID: it becomes a directory
//     segment under every store root);
//   - a key is granted under EXACTLY ONE tenant (a key in two tenants would make
//     its tenant ambiguous — a config error, not a silent last-writer-wins);
//   - no tenant has empty grants (a tenant admitting no key is a config error,
//     matching the flat empty-grants guard);
//   - every role name is known (via NewStaticAuthorizer).
func newTenantSet(f aclFile) (*TenantSet, error) {
	if len(f.Tenants) == 0 {
		return nil, fmt.Errorf("control ACL: no tenants defined")
	}
	ts := &TenantSet{
		authz:  map[string]*StaticAuthorizer{},
		byKey:  map[string]string{},
		groups: map[string][]string{},
	}
	foldSeen := map[string]string{} // fs-fold(id) -> id: rejects storage-colliding ids
	for id, tacl := range f.Tenants {
		if err := validTenantID(id); err != nil {
			return nil, fmt.Errorf("control ACL: tenant %q: %w", id, err)
		}
		// Reject two ids that collapse to the same on-disk path on a case-
		// insensitive / trailing-dot-stripping filesystem (Windows, default macOS):
		// they would address ONE storage partition, silently merging two tenants'
		// policy, registry, and audit — a cross-tenant read/write the per-tenant
		// authorizers (keyed on the exact-case id) never see. This is the cross-id
		// complement to validTenantID's per-id rules: a collision is a property of
		// the PAIR, so it cannot live in validTenantID.
		fold := fsFoldTenantID(id)
		if other, dup := foldSeen[fold]; dup {
			return nil, fmt.Errorf("control ACL: tenant ids %q and %q collide to the same storage on a case-insensitive filesystem (Windows/macOS); tenant ids must remain distinct after case-folding and trailing-dot stripping", other, id)
		}
		foldSeen[fold] = id
		if len(tacl.Grants) == 0 {
			return nil, fmt.Errorf("control ACL: tenant %q has no grants (a tenant with no admitted keys admits no one)", id)
		}
		a, err := NewStaticAuthorizer(tacl.Grants)
		if err != nil {
			return nil, fmt.Errorf("control ACL: tenant %q: %w", id, err)
		}
		ts.authz[id] = a
		if len(tacl.EnrollGroups) > 0 {
			ts.groups[id] = append([]string(nil), tacl.EnrollGroups...)
		}
		// Reverse index, enforcing one-tenant-per-key. Keys are trimmed the same
		// way NewStaticAuthorizer stores them, so the index and the authorizers
		// agree on the lookup key.
		for key := range tacl.Grants {
			k := strings.TrimSpace(key)
			if other, dup := ts.byKey[k]; dup {
				return nil, fmt.Errorf("control ACL: key %s is granted under two tenants (%q and %q); a key belongs to exactly one tenant", short(k), other, id)
			}
			ts.byKey[k] = id
		}
	}
	return ts, nil
}

// fsFoldTenantID collapses a tenant id the way the deployment filesystems
// (Windows and default macOS) resolve a filename: case-insensitively and with
// trailing dots/spaces stripped. Two distinct ids with the same fold would
// address the SAME directory and audit file, so newTenantSet rejects such a pair
// — keeping "distinct tenants ⇒ distinct storage" true by construction on the
// case-insensitive filesystems this ships on, not only on case-sensitive Linux.
func fsFoldTenantID(id string) string {
	return strings.ToLower(strings.TrimRight(id, ". "))
}

// validTenantID applies validPolicyName's path-safety rules plus one MORE,
// because a tenant id is not merely a directory segment but a security-partition
// boundary: an id that collapses to another id's path on a case-insensitive,
// trailing-dot-stripping filesystem (Windows / default macOS, the deployment
// targets) would silently SHARE one tenant's policy/registry/audit storage with
// another. So a trailing dot is rejected here (Windows strips it), and
// newTenantSet additionally rejects two ids that case-fold to the same storage
// key. Validated at LOAD (operator input), never in the request path — a request
// never names a tenant. Rules: non-empty, <=128, not
// "."/".."/leading-dot/trailing-dot, no separators/NUL, and only [A-Za-z0-9._-].
func validTenantID(id string) error {
	if id == "" {
		return fmt.Errorf("tenant id required")
	}
	if len(id) > 128 {
		return fmt.Errorf("tenant id too long")
	}
	if id == "." || id == ".." || strings.HasPrefix(id, ".") || strings.HasSuffix(id, ".") {
		return fmt.Errorf("invalid tenant id")
	}
	if strings.ContainsAny(id, "/\\\x00") || strings.Contains(id, "..") {
		return fmt.Errorf("invalid tenant id")
	}
	for _, c := range id {
		if !(c == '-' || c == '_' || c == '.' ||
			(c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
			return fmt.Errorf("invalid tenant id: only [A-Za-z0-9._-] are allowed")
		}
	}
	return nil
}
