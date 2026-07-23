package control

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Role is a control-plane privilege. The control plane is default-deny: a caller
// holds a role only if an operator ACL grants it to the caller's WireGuard
// public key. Reaching the mesh port grants nothing.
type Role string

const (
	// RoleAdmin implies every other role.
	RoleAdmin           Role = "control.admin"
	RoleEnrollmentIssue Role = "enrollment.issue"
	RoleRegistryRead    Role = "registry.read"
	RoleRegistryWrite   Role = "registry.write"
	RolePolicyRead      Role = "policy.read"
	RolePolicyWrite     Role = "policy.write"
	// RoleAnchorSubmit permits POSTing audit checkpoints to the anchor witness.
	RoleAnchorSubmit Role = "anchor.submit"
)

// allRoles is the set a RoleAdmin key implicitly holds.
var allRoles = []Role{RoleAdmin, RoleEnrollmentIssue, RoleRegistryRead, RoleRegistryWrite, RolePolicyRead, RolePolicyWrite, RoleAnchorSubmit}

func validRole(r Role) bool {
	for _, x := range allRoles {
		if x == r {
			return true
		}
	}
	return false
}

// Identity is a transport-proven caller identity. PubKey (the WireGuard public
// key) is the durable identity RBAC matches on; FQDN is display-only and MUST
// NOT be the sole basis for a privilege decision because it is mutable.
type Identity struct {
	PubKey string
	FQDN   string
}

// IdentityResolver derives the caller identity from the authenticated transport
// (the mesh source address), never from headers or the request body. It returns
// ok=false when the remote address cannot be attributed to a mesh peer.
type IdentityResolver func(remoteAddr string) (Identity, bool)

// Authorizer answers whether a WireGuard public key holds a role. It must be
// default-deny: an unknown key holds nothing.
type Authorizer interface {
	HasRole(pubKey string, role Role) bool
}

// StaticAuthorizer maps WireGuard public keys to roles. A key granted RoleAdmin
// holds every role. It is safe for concurrent reads after construction.
type StaticAuthorizer struct {
	roles map[string]map[Role]bool
}

// NewStaticAuthorizer builds an authorizer from key->roles. Empty keys and
// unknown role names are rejected so a typo fails startup rather than silently
// granting or dropping a privilege.
func NewStaticAuthorizer(grants map[string][]Role) (*StaticAuthorizer, error) {
	a := &StaticAuthorizer{roles: map[string]map[Role]bool{}}
	for key, roles := range grants {
		k := strings.TrimSpace(key)
		if k == "" {
			return nil, fmt.Errorf("control ACL: empty public key in grants")
		}
		set := map[Role]bool{}
		for _, r := range roles {
			if !validRole(r) {
				return nil, fmt.Errorf("control ACL: key %s has unknown role %q", short(k), r)
			}
			set[r] = true
		}
		a.roles[k] = set
	}
	return a, nil
}

// HasRole reports whether key holds role (RoleAdmin implies all). Default-deny:
// an empty key or an unknown key holds nothing.
func (a *StaticAuthorizer) HasRole(pubKey string, role Role) bool {
	if pubKey == "" || a == nil {
		return false
	}
	set, ok := a.roles[pubKey]
	if !ok {
		return false
	}
	return set[RoleAdmin] || set[role]
}

// aclFile is the on-disk ACL. In the single-tenant (flat) form it carries a
// top-level Grants map (WireGuard public key -> roles). In the multi-tenant form
// it carries Tenants instead — a named group of grants per tenant. The two are
// mutually exclusive; LoadControlACL auto-detects which is present. Both fields
// are declared here so strict decoding (KnownFields) accepts either shape while
// still rejecting an unknown top-level key.
type aclFile struct {
	Grants  map[string][]Role    `yaml:"grants"`
	Tenants map[string]tenantACL `yaml:"tenants"`
}

// tenantACL is one tenant's block in a multi-tenant ACL: the grants that DEFINE
// the tenant (which keys hold which roles — a tenant is defined ONLY by the keys
// it lists, never by a field a request can reach) plus optional per-tenant
// NetBird auto_groups used at enrollment.
type tenantACL struct {
	Grants       map[string][]Role `yaml:"grants"`
	EnrollGroups []string          `yaml:"enroll_groups"`
}

// LoadAuthorizer parses an operator ACL (strict YAML) into a StaticAuthorizer.
// Unknown fields, empty keys, and unknown roles are errors so a misconfigured
// ACL fails startup instead of silently denying or granting.
func LoadAuthorizer(raw []byte) (*StaticAuthorizer, error) {
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	var f aclFile
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("control ACL: %w", err)
	}
	if len(f.Grants) == 0 {
		return nil, fmt.Errorf("control ACL: no grants defined (a default-deny control plane with an empty ACL admits no one)")
	}
	return NewStaticAuthorizer(f.Grants)
}

// KeysWithRole lists the keys holding a role, sorted — for diagnostics/startup logs.
func (a *StaticAuthorizer) KeysWithRole(role Role) []string {
	var out []string
	for k, set := range a.roles {
		if set[RoleAdmin] || set[role] {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// short abbreviates a key/hash for human-facing messages and audit records.
func short(s string) string {
	if len(s) <= 12 {
		return s
	}
	return s[:6] + "…" + s[len(s)-6:]
}

// newCorrelationID returns a random request-correlation id for audit records.
func newCorrelationID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "corr-unknown"
	}
	return hex.EncodeToString(b[:])
}
